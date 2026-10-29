import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { createApp } from "../src/app.js";
import { deriveHeaderFindings } from "../src/assessment.js";
import { createDatabase } from "../src/db.js";
import { parseDomain, resolvePublicAddresses } from "../src/security.js";

process.env.JWT_SECRET = "test-only-signing-secret-that-is-long-enough";
process.env.ADMIN_EMAIL = "admin@example.com";
const temporaryDirectory = mkdtempSync(join(tmpdir(), "webguard-test-"));
const db = createDatabase(join(temporaryDirectory, "test.db"));
const runnerCalls: string[] = [];
const app = createApp({
  db,
  assessmentRunner: async (database, assessmentId) => {
    runnerCalls.push(assessmentId);
    database.prepare(`
      UPDATE assessments SET status = 'completed', stage = 'Findings saved', progress = 100,
        completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?
    `).run(assessmentId);
  },
});
let server: ReturnType<typeof app.listen>;
let baseUrl = "";
let userToken = "";
let adminToken = "";
let userId = "";
let adminId = "";
let reportFixtureAssessmentId = "";

before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  rmSync(temporaryDirectory, { recursive: true, force: true });
});

async function request(path: string, init: RequestInit = {}, token?: string) {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(`${baseUrl}/api${path}`, { ...init, headers });
}

async function register(email: string, password = "safe-example-password-2026") {
  const response = await request("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  return { response, body: await response.json() as { token: string; user: { id: string; role: string } } };
}

test("health endpoint and migration are available", async () => {
  const response = await request("/health");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok" });
  assert.equal((db.prepare("SELECT version FROM schema_migrations").get() as { version: number }).version, 1);
});

test("registration validates passwords, hashes credentials, and applies configured admin role", async () => {
  const weak = await register("weak@example.com", "short");
  assert.equal(weak.response.status, 400);

  const regular = await register("person@example.com");
  assert.equal(regular.response.status, 201);
  assert.equal(regular.body.user.role, "user");
  userToken = regular.body.token;
  userId = regular.body.user.id;

  const admin = await register("admin@example.com");
  assert.equal(admin.response.status, 201);
  assert.equal(admin.body.user.role, "admin");
  adminToken = admin.body.token;
  adminId = admin.body.user.id;

  const storedPassword = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(userId) as { password_hash: string };
  assert.notEqual(storedPassword.password_hash, "safe-example-password-2026");
});

test("login errors are generic and role-protected admin route denies regular users", async () => {
  const invalid = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: "person@example.com", password: "wrong-password" }),
  });
  assert.equal(invalid.status, 401);
  assert.deepEqual(await invalid.json(), { error: "Email or password is incorrect." });

  const denied = await request("/admin/users", {}, userToken);
  assert.equal(denied.status, 403);
  const allowed = await request("/admin/users", {}, adminToken);
  assert.equal(allowed.status, 200);
  const body = await allowed.json() as { users: Array<{ id: string }> };
  assert.equal(body.users.length, 2);
});

test("target registration accepts domains only and prevents assessments until verified", async () => {
  const invalid = await request("/targets", {
    method: "POST",
    body: JSON.stringify({ domain: "https://example.com/path" }),
  }, userToken);
  assert.equal(invalid.status, 400);

  const created = await request("/targets", {
    method: "POST",
    body: JSON.stringify({ domain: "Example.COM" }),
  }, userToken);
  assert.equal(created.status, 201);
  const body = await created.json() as { target: { id: string; domain: string }; verification: { hostname: string; value: string } };
  assert.equal(body.target.domain, "example.com");
  assert.equal(body.verification.hostname, "_webguard.example.com");
  assert.match(body.verification.value, /^webguard-verify=/);

  const unverified = await request(`/targets/${body.target.id}/assessments`, { method: "POST", body: "{}" }, userToken);
  assert.equal(unverified.status, 409);

  const otherAccount = await register("other-person@example.com");
  assert.equal(otherAccount.response.status, 201);
  const notOwner = await request(`/targets/${body.target.id}/verify`, { method: "POST", body: "{}" }, otherAccount.body.token);
  assert.equal(notOwner.status, 404);

  db.prepare("UPDATE targets SET verified_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
    .run(body.target.id);
  const queued = await request(`/targets/${body.target.id}/assessments`, {
    method: "POST",
    body: "{}",
  }, userToken);
  assert.equal(queued.status, 202);
  const queuedBody = await queued.json() as { assessment: { id: string; status: string } };
  assert.equal(queuedBody.assessment.status, "queued");

  for (let attempt = 0; attempt < 20 && !runnerCalls.includes(queuedBody.assessment.id); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.ok(runnerCalls.includes(queuedBody.assessment.id));
  const completed = await request(`/assessments/${queuedBody.assessment.id}`, {}, userToken);
  const completedBody = await completed.json() as { assessment: { status: string; progress: number } };
  assert.equal(completedBody.assessment.status, "completed");
  assert.equal(completedBody.assessment.progress, 100);
});

test("resource ownership hides another user's findings and targets", async () => {
  const targetId = randomUUID();
  const assessmentId = randomUUID();
  const findingId = randomUUID();
  db.prepare("INSERT INTO targets (id, user_id, domain, verification_token) VALUES (?, ?, ?, ?)")
    .run(targetId, adminId, "owned.example.com", "webguard-verify=fixture");
  db.prepare("INSERT INTO assessments (id, target_id, user_id, status) VALUES (?, ?, ?, 'completed')")
    .run(assessmentId, targetId, adminId);
  reportFixtureAssessmentId = assessmentId;
  db.prepare(`
    INSERT INTO findings (id, assessment_id, target_id, user_id, title, severity, description, remediation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(findingId, assessmentId, targetId, adminId, "Fixture finding", "low", "Description", "Recommendation");

  const deniedFinding = await request(`/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ status: "resolved" }),
  }, userToken);
  assert.equal(deniedFinding.status, 404);
  const remediation = await request(`/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ status: "resolved", note: "Header policy updated." }),
  }, adminToken);
  assert.equal(remediation.status, 200);
  const remediationBody = await remediation.json() as { finding: { status: string; remediation_note: string } };
  assert.equal(remediationBody.finding.status, "resolved");
  assert.equal(remediationBody.finding.remediation_note, "Header policy updated.");
  const userTargets = await request("/targets", {}, userToken);
  const result = await userTargets.json() as { targets: Array<{ id: string }> };
  assert.ok(result.targets.every((target) => target.id !== targetId));
});

test("reports are scoped and can be exported as JSON, escaped HTML, or PDF", async () => {
  const assessment = { id: reportFixtureAssessmentId };

  const denied = await request(`/assessments/${assessment.id}/report?format=json`, {}, userToken);
  assert.equal(denied.status, 404);

  const jsonResponse = await request(`/assessments/${assessment.id}/report?format=json`, {}, adminToken);
  assert.equal(jsonResponse.status, 200);
  assert.match(jsonResponse.headers.get("content-disposition") ?? "", /attachment/);
  const report = await jsonResponse.json() as { findings: Array<{ title: string }> };
  assert.equal(report.findings[0]?.title, "Fixture finding");

  const htmlResponse = await request(`/assessments/${assessment.id}/report?format=html`, {}, adminToken);
  assert.match(await htmlResponse.text(), /Fixture finding/);

  const pdfResponse = await request(`/assessments/${assessment.id}/report?format=pdf`, {}, adminToken);
  assert.equal(pdfResponse.headers.get("content-type"), "application/pdf");
  const pdf = new Uint8Array(await pdfResponse.arrayBuffer());
  assert.equal(new TextDecoder().decode(pdf.slice(0, 5)), "%PDF-");
});

test("domain validation rejects local targets and resolution blocks loopback/private IPs", async () => {
  assert.throws(() => parseDomain("localhost"));
  assert.throws(() => parseDomain("192.168.1.1"));
  await assert.rejects(resolvePublicAddresses("localhost"), /private or reserved/);
});

test("clickjacking observation requires an actual frame-ancestors directive or X-Frame-Options", () => {
  const cspWithoutFrameAncestors = deriveHeaderFindings({ "content-security-policy": "default-src 'self'" });
  assert.ok(cspWithoutFrameAncestors.some((finding) => finding.title === "Clickjacking protection is not apparent"));

  const cspWithFrameAncestors = deriveHeaderFindings({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  });
  assert.ok(!cspWithFrameAncestors.some((finding) => finding.title === "Clickjacking protection is not apparent"));

  const withLegacyProtection = deriveHeaderFindings({ "x-frame-options": "DENY" });
  assert.ok(!withLegacyProtection.some((finding) => finding.title === "Clickjacking protection is not apparent"));
});

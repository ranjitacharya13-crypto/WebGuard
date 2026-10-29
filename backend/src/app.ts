import "dotenv/config";
import { randomBytes, randomUUID } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import bcrypt from "bcryptjs";
import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import PDFDocument from "pdfkit";
import { z } from "zod";
import type { AppDatabase } from "./db.js";
import { runPassiveAssessment } from "./assessment.js";
import { parseDomain, safeDomainError } from "./security.js";
import type { UserIdentity } from "./types.js";

const signupSchema = z.object({
  email: z.string().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(12).max(128),
});
const remediationSchema = z.object({
  status: z.enum(["open", "in_progress", "resolved"]),
  note: z.string().trim().max(1000).optional(),
});

type AppOptions = {
  db: AppDatabase;
  assessmentRunner?: (db: AppDatabase, assessmentId: string) => Promise<void>;
};

function asyncRoute(handler: (request: Request, response: Response, next: NextFunction) => Promise<void>) {
  return (request: Request, response: Response, next: NextFunction) => {
    void handler(request, response, next).catch(next);
  };
}

function authMiddleware(db: AppDatabase) {
  return (request: Request, response: Response, next: NextFunction) => {
    const header = request.header("authorization");
    const token = header?.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) {
      response.status(401).json({ error: "Authentication required." });
      return;
    }
    const jwtSecret = process.env.JWT_SECRET ?? "";
    if (jwtSecret.length < 32) {
      response.status(503).json({ error: "Authentication is not configured. Set a JWT_SECRET of at least 32 characters." });
      return;
    }

    try {
      const payload = jwt.verify(token, jwtSecret);
      if (typeof payload === "string" || typeof payload.sub !== "string") {
        response.status(401).json({ error: "Invalid authentication token." });
        return;
      }
      const user = db.prepare("SELECT id, email, role FROM users WHERE id = ?").get(payload.sub) as UserIdentity | undefined;
      if (!user) {
        response.status(401).json({ error: "Account not found." });
        return;
      }
      request.user = user;
      next();
    } catch {
      response.status(401).json({ error: "Invalid or expired authentication token." });
    }
  };
}

function issueToken(user: UserIdentity): string {
  const jwtSecret = process.env.JWT_SECRET ?? "";
  if (jwtSecret.length < 32) throw new Error("Authentication is not configured. Set a JWT_SECRET of at least 32 characters.");
  return jwt.sign({ role: user.role }, jwtSecret, { subject: user.id, expiresIn: "8h" });
}

function ownsResource(db: AppDatabase, request: Request, table: "targets" | "assessments" | "findings", id: string): boolean {
  const ownerColumn = "user_id";
  const row = db.prepare(`SELECT ${ownerColumn} FROM ${table} WHERE id = ?`).get(id) as { user_id: string } | undefined;
  return Boolean(row && request.user && (request.user.role === "admin" || row.user_id === request.user.id));
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character] ?? character);
}

export function createApp({ db, assessmentRunner = runPassiveAssessment }: AppOptions) {
  const app = express();
  const assessmentQueue: string[] = [];
  let runningJobs = 0;
  const maxConcurrentJobs = 2;

  db.prepare(`
    UPDATE assessments
    SET status = 'failed', stage = 'Assessment interrupted', error = 'The server restarted while this assessment was running.',
        completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE status = 'running'
  `).run();

  const dispatchQueuedAssessments = () => {
    while (runningJobs < maxConcurrentJobs && assessmentQueue.length > 0) {
      const id = assessmentQueue.shift();
      if (!id) continue;
      runningJobs += 1;
      void assessmentRunner(db, id).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : "The passive check failed.";
        db.prepare(`
          UPDATE assessments SET status = 'failed', stage = 'Assessment failed', error = ?,
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?
        `).run(message.slice(0, 500), id);
      }).finally(() => {
        runningJobs -= 1;
        dispatchQueuedAssessments();
      });
    }
  };
  const pending = db.prepare("SELECT id FROM assessments WHERE status = 'queued' ORDER BY created_at")
    .all() as Array<{ id: string }>;
  assessmentQueue.push(...pending.map(({ id }) => id));
  if (assessmentQueue.length > 0) setImmediate(dispatchQueuedAssessments);

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(cors({
    origin: process.env.FRONTEND_ORIGIN ?? "http://127.0.0.1:5173",
    credentials: false,
  }));
  app.use(express.json({ limit: "32kb" }));
  app.get("/api/health", (_request, response) => response.json({ status: "ok" }));

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many sign-in attempts. Try again later." },
  });
  const auth = authMiddleware(db);

  app.post("/api/auth/register", authLimiter, asyncRoute(async (request, response) => {
    const input = signupSchema.safeParse(request.body);
    if (!input.success) {
      response.status(400).json({ error: input.error.issues[0]?.message ?? "Invalid registration details." });
      return;
    }
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(input.data.email);
    if (existing) {
      response.status(409).json({ error: "An account with this email already exists." });
      return;
    }

    const id = randomUUID();
    const passwordHash = await bcrypt.hash(input.data.password, 12);
    const configuredAdmin = process.env.ADMIN_EMAIL?.trim().toLowerCase();
    const role = configuredAdmin && configuredAdmin === input.data.email ? "admin" : "user";
    db.prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
      .run(id, input.data.email, passwordHash, role);
    const user: UserIdentity = { id, email: input.data.email, role };
    response.status(201).json({ token: issueToken(user), user });
  }));

  app.post("/api/auth/login", authLimiter, asyncRoute(async (request, response) => {
    const input = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(128) }).safeParse(request.body);
    if (!input.success) {
      response.status(400).json({ error: "Enter a valid email and password." });
      return;
    }
    const row = db.prepare("SELECT id, email, password_hash, role FROM users WHERE email = ?")
      .get(input.data.email.toLowerCase()) as (UserIdentity & { password_hash: string }) | undefined;
    if (!row || !(await bcrypt.compare(input.data.password, row.password_hash))) {
      response.status(401).json({ error: "Email or password is incorrect." });
      return;
    }
    const user: UserIdentity = { id: row.id, email: row.email, role: row.role };
    response.json({ token: issueToken(user), user });
  }));

  app.get("/api/auth/me", auth, (request, response) => response.json({ user: request.user }));

  app.get("/api/admin/users", auth, (request, response) => {
    if (request.user?.role !== "admin") {
      response.status(403).json({ error: "Administrator access is required." });
      return;
    }
    response.json({ users: db.prepare("SELECT id, email, role, created_at FROM users ORDER BY created_at DESC").all() });
  });

  app.get("/api/targets", auth, (request, response) => {
    const targets = request.user?.role === "admin"
      ? db.prepare("SELECT * FROM targets ORDER BY created_at DESC").all()
      : db.prepare("SELECT * FROM targets WHERE user_id = ? ORDER BY created_at DESC").all(request.user!.id);
    response.json({ targets });
  });

  app.post("/api/targets", auth, (request, response) => {
    try {
      const domain = parseDomain(request.body?.domain);
      const id = randomUUID();
      const verificationToken = `webguard-verify=${randomBytes(24).toString("hex")}`;
      db.prepare(`
        INSERT INTO targets (id, user_id, domain, verification_token)
        VALUES (?, ?, ?, ?)
      `).run(id, request.user!.id, domain, verificationToken);
      response.status(201).json({
        target: db.prepare("SELECT * FROM targets WHERE id = ?").get(id),
        verification: { recordType: "TXT", hostname: `_webguard.${domain}`, value: verificationToken },
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        response.status(400).json({ error: safeDomainError(error) });
        return;
      }
      if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
        response.status(409).json({ error: "This domain is already registered to your account." });
        return;
      }
      throw error;
    }
  });

  app.post("/api/targets/:id/verify", auth, asyncRoute(async (request, response) => {
    if (!ownsResource(db, request, "targets", request.params.id)) {
      response.status(404).json({ error: "Target not found." });
      return;
    }
    const target = db.prepare("SELECT id, domain, verification_token FROM targets WHERE id = ?")
      .get(request.params.id) as { id: string; domain: string; verification_token: string };
    let records: string[][];
    try {
      records = await resolveTxt(`_webguard.${target.domain}`);
    } catch {
      response.status(422).json({ error: "Verification TXT record was not found. DNS changes may take time to propagate." });
      return;
    }
    if (!records.some((record) => record.join("") === target.verification_token)) {
      response.status(422).json({ error: "The DNS TXT value does not match the verification token." });
      return;
    }
    db.prepare("UPDATE targets SET verified_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
      .run(target.id);
    response.json({ target: db.prepare("SELECT * FROM targets WHERE id = ?").get(target.id) });
  }));

  app.delete("/api/targets/:id", auth, (request, response) => {
    if (!ownsResource(db, request, "targets", request.params.id)) {
      response.status(404).json({ error: "Target not found." });
      return;
    }
    db.prepare("DELETE FROM targets WHERE id = ?").run(request.params.id);
    response.status(204).end();
  });

  app.get("/api/assessments", auth, (request, response) => {
    const assessments = request.user?.role === "admin"
      ? db.prepare(`
          SELECT a.*, t.domain FROM assessments a JOIN targets t ON t.id = a.target_id
          ORDER BY a.created_at DESC LIMIT 100
        `).all()
      : db.prepare(`
          SELECT a.*, t.domain FROM assessments a JOIN targets t ON t.id = a.target_id
          WHERE a.user_id = ? ORDER BY a.created_at DESC LIMIT 100
        `).all(request.user!.id);
    response.json({ assessments });
  });

  app.post("/api/targets/:id/assessments", auth, (request, response) => {
    if (!ownsResource(db, request, "targets", request.params.id)) {
      response.status(404).json({ error: "Target not found." });
      return;
    }
    const target = db.prepare("SELECT id, verified_at FROM targets WHERE id = ?")
      .get(request.params.id) as { id: string; verified_at: string | null };
    if (!target.verified_at) {
      response.status(409).json({ error: "Verify control of this domain before starting an assessment." });
      return;
    }
    const activeCount = db.prepare(`
      SELECT COUNT(*) AS count FROM assessments
      WHERE user_id = ? AND status IN ('queued', 'running')
    `).get(request.user!.id) as { count: number };
    if (activeCount.count >= 3) {
      response.status(429).json({ error: "You already have three active assessment jobs. Wait for one to finish." });
      return;
    }
    const id = randomUUID();
    db.prepare("INSERT INTO assessments (id, target_id, user_id) VALUES (?, ?, ?)")
      .run(id, target.id, request.user!.id);
    response.status(202).json({ assessment: db.prepare("SELECT * FROM assessments WHERE id = ?").get(id) });
    assessmentQueue.push(id);
    setImmediate(dispatchQueuedAssessments);
  });

  app.get("/api/assessments/:id", auth, (request, response) => {
    if (!ownsResource(db, request, "assessments", request.params.id)) {
      response.status(404).json({ error: "Assessment not found." });
      return;
    }
    const assessment = db.prepare(`
      SELECT a.*, t.domain FROM assessments a JOIN targets t ON t.id = a.target_id WHERE a.id = ?
    `).get(request.params.id);
    response.json({ assessment });
  });

  app.get("/api/findings", auth, (request, response) => {
    const isAdmin = request.user?.role === "admin";
    const requestedStatus = typeof request.query.status === "string" ? request.query.status : undefined;
    const allowedStatus = ["open", "in_progress", "resolved"].includes(requestedStatus ?? "");
    const clauses = [isAdmin ? "1 = 1" : "f.user_id = ?"];
    const params: Array<string> = isAdmin ? [] : [request.user!.id];
    if (allowedStatus && requestedStatus) {
      clauses.push("f.status = ?");
      params.push(requestedStatus);
    }
    const findings = db.prepare(`
      SELECT f.*, t.domain, a.created_at AS assessment_date
      FROM findings f
      JOIN targets t ON t.id = f.target_id
      JOIN assessments a ON a.id = f.assessment_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY CASE f.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
               f.created_at DESC
      LIMIT 200
    `).all(...params);
    response.json({ findings });
  });

  app.patch("/api/findings/:id", auth, (request, response) => {
    if (!ownsResource(db, request, "findings", request.params.id)) {
      response.status(404).json({ error: "Finding not found." });
      return;
    }
    const input = remediationSchema.safeParse(request.body);
    if (!input.success) {
      response.status(400).json({ error: input.error.issues[0]?.message ?? "Invalid remediation update." });
      return;
    }
    db.prepare(`
      UPDATE findings SET status = ?, remediation_note = ?,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ?
    `).run(input.data.status, input.data.note ?? null, request.params.id);
    response.json({ finding: db.prepare("SELECT * FROM findings WHERE id = ?").get(request.params.id) });
  });

  app.get("/api/assessments/:id/report", auth, (request, response, next) => {
    if (!ownsResource(db, request, "assessments", request.params.id)) {
      response.status(404).json({ error: "Assessment not found." });
      return;
    }
    const assessment = db.prepare(`
      SELECT a.*, t.domain FROM assessments a JOIN targets t ON t.id = a.target_id WHERE a.id = ?
    `).get(request.params.id) as {
      id: string; domain: string; status: string; stage: string; progress: number;
      error: string | null; created_at: string; completed_at: string | null;
    };
    const findings = db.prepare("SELECT title, severity, description, remediation, status, remediation_note FROM findings WHERE assessment_id = ? ORDER BY severity, title")
      .all(request.params.id) as Array<{
        title: string; severity: string; description: string; remediation: string;
        status: string; remediation_note: string | null;
      }>;
    const report = { generatedAt: new Date().toISOString(), assessment, findings };
    const format = request.query.format === undefined ? "json" : request.query.format;
    if (format === "json") {
      response.setHeader("Content-Disposition", `attachment; filename="webguard-${assessment.id}.json"`);
      response.json(report);
      return;
    }
    if (format === "html") {
      response.type("html").send(`<!doctype html><html lang="en"><meta charset="utf-8"><title>WebGuard report</title>
        <style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 20px;color:#1c2540}article{border:1px solid #ddd;padding:16px;margin:12px 0;border-radius:8px}small{color:#697389}</style>
        <h1>WebGuard assessment report</h1><p><strong>Target:</strong> ${escapeHtml(assessment.domain)}</p>
        <p><strong>Status:</strong> ${escapeHtml(assessment.status)} · <strong>Created:</strong> ${escapeHtml(assessment.created_at)}</p>
        <h2>Findings (${findings.length})</h2>${findings.map((finding) => `<article><small>${escapeHtml(finding.severity.toUpperCase())} · ${escapeHtml(finding.status)}</small><h3>${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.description)}</p><p><strong>Recommendation:</strong> ${escapeHtml(finding.remediation)}</p>${finding.remediation_note ? `<p><strong>Remediation note:</strong> ${escapeHtml(finding.remediation_note)}</p>` : ""}</article>`).join("")}
        <p><small>Passive HTTPS response review only. Educational guidance; not a penetration test.</small></p></html>`);
      return;
    }
    if (format === "pdf") {
      response.type("application/pdf");
      response.setHeader("Content-Disposition", `attachment; filename="webguard-${assessment.id}.pdf"`);
      const document = new PDFDocument({ margin: 48, size: "A4" });
      document.on("error", next);
      document.pipe(response);
      document.fontSize(22).text("WebGuard assessment report");
      document.moveDown().fontSize(12).text(`Target: ${assessment.domain}`);
      document.text(`Status: ${assessment.status}`);
      document.text(`Created: ${assessment.created_at}`);
      document.moveDown().fontSize(16).text(`Findings (${findings.length})`);
      for (const finding of findings) {
        document.moveDown(0.6).fontSize(13).text(`${finding.severity.toUpperCase()} · ${finding.title}`);
        document.fontSize(10).text(finding.description);
        document.text(`Recommendation: ${finding.remediation}`);
        if (finding.remediation_note) document.text(`Remediation note: ${finding.remediation_note}`);
      }
      document.moveDown().fontSize(9).text("Passive HTTPS response review only. Educational guidance; not a penetration test.");
      document.end();
      return;
    }
    response.status(400).json({ error: "Format must be json, html, or pdf." });
  });

  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (response.headersSent) return;
    const message = error instanceof Error ? error.message : "An unexpected server error occurred.";
    console.error("Request failed:", message);
    response.status(500).json({ error: "An unexpected server error occurred." });
  });

  return app;
}

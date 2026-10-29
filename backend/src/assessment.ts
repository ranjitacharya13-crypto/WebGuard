import { request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";
import { TLSSocket } from "node:tls";
import { randomUUID } from "node:crypto";
import type { AppDatabase } from "./db.js";
import { resolvePublicAddresses } from "./security.js";

type AssessmentRow = {
  id: string;
  target_id: string;
  user_id: string;
  domain: string;
};

type HeaderFinding = {
  title: string;
  severity: "info" | "low" | "medium" | "high";
  description: string;
  remediation: string;
};

const stages = [
  "Confirming authorization",
  "Resolving the verified domain",
  "Checking HTTPS and certificate",
  "Reviewing response headers",
  "Saving findings and recommendations",
];

export const safeAssessmentStages = stages;

function updateProgress(db: AppDatabase, assessmentId: string, stage: string, progress: number) {
  db.prepare("UPDATE assessments SET stage = ?, progress = ? WHERE id = ?")
    .run(stage, progress, assessmentId);
}

function inspectHttps(domain: string, pinnedAddresses: string[]): Promise<{
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  certificateValidTo?: string;
}> {
  return new Promise((resolve, reject) => {
    let addressIndex = 0;
    const pinnedLookup: LookupFunction = (_hostname, options, callback) => {
      const selected = pinnedAddresses[addressIndex % pinnedAddresses.length];
      addressIndex += 1;
      if (typeof options === "object" && options !== null && options.all) {
        callback(null, [{ address: selected, family: selected.includes(":") ? 6 : 4 }]);
        return;
      }
      callback(null, selected, selected.includes(":") ? 6 : 4);
    };

    const request = httpsRequest({
      hostname: domain,
      servername: domain,
      path: "/",
      method: "HEAD",
      headers: { "User-Agent": "WebGuard-Passive-Assessment/1.0", "Accept": "*/*" },
      lookup: pinnedLookup,
      agent: false,
      timeout: 8000,
    }, (response) => {
      const certificate = (response.socket as TLSSocket).getPeerCertificate();
      response.resume();
      resolve({
        statusCode: response.statusCode ?? 0,
        headers: response.headers,
        certificateValidTo: certificate.valid_to,
      });
    });

    request.on("timeout", () => request.destroy(new Error("The HTTPS check timed out.")));
    request.on("error", reject);
    request.end();
  });
}

export function deriveHeaderFindings(headers: Record<string, string | string[] | undefined>): HeaderFinding[] {
  const findings: HeaderFinding[] = [];
  const has = (name: string) => Boolean(headers[name]);
  const csp = headers["content-security-policy"];
  const cspValue = Array.isArray(csp) ? csp.join("; ") : csp ?? "";
  const hasFrameAncestors = /(?:^|;)\s*frame-ancestors(?:\s|;|$)/i.test(cspValue);

  if (!has("strict-transport-security")) {
    findings.push({
      title: "HTTP Strict Transport Security is not set",
      severity: "medium",
      description: "The HTTPS response did not include a Strict-Transport-Security header.",
      remediation: "After confirming all subdomains support HTTPS, configure Strict-Transport-Security with an appropriate max-age.",
    });
  }
  if (!has("content-security-policy")) {
    findings.push({
      title: "Content Security Policy is not set",
      severity: "medium",
      description: "The response did not include a Content-Security-Policy header.",
      remediation: "Define a restrictive Content-Security-Policy for the site and test it in report-only mode before enforcement.",
    });
  }
  if (!has("x-content-type-options")) {
    findings.push({
      title: "MIME-sniffing protection is not set",
      severity: "low",
      description: "The response did not include X-Content-Type-Options.",
      remediation: "Set X-Content-Type-Options: nosniff on appropriate responses.",
    });
  }
  if (!has("referrer-policy")) {
    findings.push({
      title: "Referrer Policy is not set",
      severity: "low",
      description: "The response did not include a Referrer-Policy header.",
      remediation: "Set a policy such as strict-origin-when-cross-origin based on the site's requirements.",
    });
  }
  if (!has("permissions-policy")) {
    findings.push({
      title: "Permissions Policy is not set",
      severity: "info",
      description: "The response did not include a Permissions-Policy header.",
      remediation: "Consider disabling browser features the site does not use with a Permissions-Policy header.",
    });
  }
  if (!has("x-frame-options") && !hasFrameAncestors) {
    findings.push({
      title: "Clickjacking protection is not apparent",
      severity: "low",
      description: "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive was observed.",
      remediation: "Use Content-Security-Policy frame-ancestors; use X-Frame-Options as a compatibility fallback if needed.",
    });
  }

  return findings;
}

export async function runPassiveAssessment(db: AppDatabase, assessmentId: string): Promise<void> {
  const assessment = db.prepare(`
    SELECT a.id, a.target_id, a.user_id, t.domain
    FROM assessments a
    JOIN targets t ON t.id = a.target_id
    WHERE a.id = ? AND t.verified_at IS NOT NULL
  `).get(assessmentId) as AssessmentRow | undefined;

  if (!assessment) throw new Error("Assessment target is missing or not verified.");

  db.prepare(`
    UPDATE assessments
    SET status = 'running', started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = ?
  `).run(assessmentId);

  try {
    updateProgress(db, assessmentId, stages[0], 10);
    const addresses = await resolvePublicAddresses(assessment.domain);

    updateProgress(db, assessmentId, stages[1], 30);
    updateProgress(db, assessmentId, stages[2], 50);
    const response = await inspectHttps(assessment.domain, addresses);

    updateProgress(db, assessmentId, stages[3], 75);
    const findings = deriveHeaderFindings(response.headers);
    if (response.certificateValidTo) {
      const daysUntilExpiry = Math.floor((Date.parse(response.certificateValidTo) - Date.now()) / 86_400_000);
      if (daysUntilExpiry >= 0 && daysUntilExpiry <= 30) {
        findings.push({
          title: "TLS certificate expires soon",
          severity: "medium",
          description: `The presented certificate expires in approximately ${daysUntilExpiry} day(s).`,
          remediation: "Renew the TLS certificate before its expiry and confirm automated renewal is working.",
        });
      }
    }
    const insertFinding = db.prepare(`
      INSERT INTO findings (id, assessment_id, target_id, user_id, title, severity, description, remediation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const saveResults = db.transaction(() => {
      for (const finding of findings) {
        insertFinding.run(
          randomUUID(),
          assessment.id,
          assessment.target_id,
          assessment.user_id,
          finding.title,
          finding.severity,
          finding.description,
          finding.remediation,
        );
      }
      db.prepare(`
        UPDATE assessments
        SET status = 'completed', stage = ?, progress = 100,
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE id = ?
      `).run(stages[4], assessmentId);
    });
    updateProgress(db, assessmentId, stages[4], 90);
    saveResults();
  } catch (error) {
    const message = error instanceof Error ? error.message : "The passive check failed.";
    db.prepare(`
      UPDATE assessments
      SET status = 'failed', stage = 'Assessment failed', error = ?,
          completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ?
    `).run(message.slice(0, 500), assessmentId);
  }
}

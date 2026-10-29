export type User = { id: string; email: string; role: "user" | "admin" };
export type Target = {
  id: string; domain: string; verified_at: string | null; created_at: string;
};
export type Assessment = {
  id: string; target_id: string; domain: string; status: string; stage: string;
  progress: number; error: string | null; created_at: string; completed_at: string | null;
};
export type Finding = {
  id: string; assessment_id: string; target_id: string; domain: string; title: string;
  severity: "info" | "low" | "medium" | "high"; description: string; remediation: string;
  status: "open" | "in_progress" | "resolved"; remediation_note: string | null;
  created_at: string;
};
export type Verification = { recordType: "TXT"; hostname: string; value: string };

let token = sessionStorage.getItem("webguard-token");

export function setToken(value: string | null) {
  token = value;
  if (value) sessionStorage.setItem("webguard-token", value);
  else sessionStorage.removeItem("webguard-token");
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`/api${path}`, { ...init, headers });
  if (response.status === 204) return undefined as T;
  const payload = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(payload.error ?? `Request failed (${response.status}).`);
  return payload;
}

export async function downloadReport(id: string, format: "json" | "html" | "pdf") {
  const headers = new Headers({ Accept: format === "pdf" ? "application/pdf" : format === "html" ? "text/html" : "application/json" });
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`/api/assessments/${encodeURIComponent(id)}/report?format=${format}`, { headers });
  if (!response.ok) {
    const payload = await response.json() as { error?: string };
    throw new Error(payload.error ?? `Report download failed (${response.status}).`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `webguard-${id}.${format === "html" ? "html" : format}`;
  link.click();
  URL.revokeObjectURL(url);
}

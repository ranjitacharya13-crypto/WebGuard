import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  Activity, ArrowDownToLine, ArrowRight, BadgeCheck, Check, CheckCircle2,
  CircleHelp, ClipboardCheck, Clock3, Globe2, LayoutDashboard, LockKeyhole,
  LogOut, Plus, Radar, RefreshCw, Shield, ShieldAlert, ShieldCheck,
  ShieldEllipsis, Target as TargetIcon, Users, X,
} from "lucide-react";
import { api, downloadReport, setToken, type Assessment, type Finding, type Target, type User, type Verification } from "./api";

type Section = "overview" | "targets" | "assessments" | "findings";
type LoginResult = { token: string; user: User };

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : "Something went wrong. Please try again.";
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: string }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function AuthScreen({ onLogin }: { onLogin: (result: LoginResult) => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const result = await api<LoginResult>(`/auth/${mode === "login" ? "login" : "register"}`, {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      setToken(result.token);
      onLogin(result);
    } catch (requestError) {
      setError(messageOf(requestError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card">
        <a className="brand" href="#" aria-label="WebGuard home"><span className="brand-icon"><ShieldCheck size={23} /></span><span>webguard<span className="brand-dot">.</span></span></a>
        <p className="eyebrow">YOUR PRIVATE SECURITY WORKSPACE</p>
        <h1>{mode === "login" ? "Welcome back." : "Create your account."}</h1>
        <p className="muted">{mode === "login" ? "Sign in to manage authorized targets and assessments." : "Use an email you control. Passwords must be at least 12 characters."}</p>
        <form className="auth-form" onSubmit={submit}>
          <label>Email address<input required type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" /></label>
          <label>Password<input required type="password" minLength={mode === "register" ? 12 : 1} autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={mode === "register" ? "At least 12 characters" : "Your password"} /></label>
          {error && <div className="alert alert-error" role="alert">{error}</div>}
          <button className="button button-primary full-button" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"} <ArrowRight size={16} /></button>
        </form>
        <p className="auth-switch">{mode === "login" ? "New to WebGuard?" : "Already have an account?"} <button type="button" onClick={() => { setError(""); setMode(mode === "login" ? "register" : "login"); }}>{mode === "login" ? "Create an account" : "Sign in"}</button></p>
        <div className="privacy-callout"><LockKeyhole size={16} /><span>Assessments are passive and run only against domains you verify.</span></div>
      </section>
    </main>
  );
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(Boolean(sessionStorage.getItem("webguard-token")));
  const [section, setSection] = useState<Section>("overview");
  const [targets, setTargets] = useState<Target[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [targetDialog, setTargetDialog] = useState(false);
  const [pendingTarget, setPendingTarget] = useState<{ target: Target; verification: Verification } | null>(null);
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [reportBusy, setReportBusy] = useState("");

  const refresh = useCallback(async () => {
    const [targetResponse, assessmentResponse, findingResponse] = await Promise.all([
      api<{ targets: Target[] }>("/targets"),
      api<{ assessments: Assessment[] }>("/assessments"),
      api<{ findings: Finding[] }>("/findings"),
    ]);
    setTargets(targetResponse.targets);
    setAssessments(assessmentResponse.assessments);
    setFindings(findingResponse.findings);
  }, []);

  useEffect(() => {
    let active = true;
    if (!sessionStorage.getItem("webguard-token")) return;
    api<{ user: User }>("/auth/me")
      .then(({ user: currentUser }) => {
        if (!active) return;
        setUser(currentUser);
        return refresh();
      })
      .catch(() => {
        setToken(null);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [refresh]);

  useEffect(() => {
    if (!user || !assessments.some((assessment) => assessment.status === "queued" || assessment.status === "running")) return;
    const timer = window.setInterval(() => {
      void refresh().catch((refreshError) => setError(messageOf(refreshError)));
    }, 1800);
    return () => window.clearInterval(timer);
  }, [user, assessments, refresh]);

  const openFindings = useMemo(() => findings.filter((finding) => finding.status !== "resolved"), [findings]);

  async function loadWorkspace() {
    setError("");
    await refresh();
  }

  async function submitTarget(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api<{ target: Target; verification: Verification }>("/targets", {
        method: "POST",
        body: JSON.stringify({ domain }),
      });
      setPendingTarget(result);
      setDomain("");
      await refresh();
    } catch (requestError) {
      setError(messageOf(requestError));
    } finally {
      setBusy(false);
    }
  }

  async function verifyTarget(targetId: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/targets/${encodeURIComponent(targetId)}/verify`, { method: "POST", body: "{}" });
      setPendingTarget(null);
      setTargetDialog(false);
      setNotice("Domain ownership verified.");
      await refresh();
    } catch (requestError) {
      setError(messageOf(requestError));
    } finally {
      setBusy(false);
    }
  }

  async function startAssessment(targetId: string) {
    setError("");
    try {
      await api(`/targets/${encodeURIComponent(targetId)}/assessments`, { method: "POST", body: "{}" });
      setNotice("Passive assessment queued. Progress will update automatically.");
      setSection("assessments");
      await refresh();
    } catch (requestError) {
      setError(messageOf(requestError));
    }
  }

  async function updateFinding(finding: Finding, status: Finding["status"]) {
    setError("");
    try {
      await api(`/findings/${encodeURIComponent(finding.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ status, note: finding.remediation_note ?? "" }),
      });
      await refresh();
    } catch (requestError) {
      setError(messageOf(requestError));
    }
  }

  async function getReport(assessment: Assessment, format: "json" | "html" | "pdf") {
    setReportBusy(`${assessment.id}:${format}`);
    setError("");
    try {
      await downloadReport(assessment.id, format);
    } catch (requestError) {
      setError(messageOf(requestError));
    } finally {
      setReportBusy("");
    }
  }

  function signOut() {
    setToken(null);
    setUser(null);
    setTargets([]);
    setAssessments([]);
    setFindings([]);
  }

  if (loading) return <div className="boot-screen"><ShieldCheck size={30} /> Loading WebGuard…</div>;
  if (!user) return <AuthScreen onLogin={async ({ user: signedInUser }) => {
    setUser(signedInUser);
    try { await loadWorkspace(); } catch (loadError) { setError(messageOf(loadError)); }
  }} />;

  const navItems: { id: Section; label: string; icon: ReactNode; count?: number }[] = [
    { id: "overview", label: "Overview", icon: <LayoutDashboard size={18} /> },
    { id: "targets", label: "Authorized targets", icon: <TargetIcon size={18} />, count: targets.length },
    { id: "assessments", label: "Assessments", icon: <Activity size={18} />, count: assessments.length },
    { id: "findings", label: "Findings & fixes", icon: <ClipboardCheck size={18} />, count: openFindings.length },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" onClick={(event) => { event.preventDefault(); setSection("overview"); }}><span className="brand-icon"><ShieldCheck size={22} /></span><span>webguard<span className="brand-dot">.</span></span></a>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="navigation" aria-label="Main navigation">
          {navItems.map((item) => <button key={item.id} className={`nav-link ${section === item.id ? "active" : ""}`} onClick={() => setSection(item.id)}>{item.icon}<span>{item.label}</span>{item.count !== undefined && <span className="nav-count">{item.count}</span>}</button>)}
          {user.role === "admin" && <div className="admin-note"><Users size={15} /> Administrator account</div>}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-privacy"><span className="privacy-shield"><Shield size={16} /></span><strong>Privacy first</strong><p>Only verify domains you own or are explicitly authorized to assess.</p></div>
          <div className="sidebar-user"><span className="avatar">{user.email.slice(0, 1).toUpperCase()}</span><div className="user-copy"><strong>{user.email}</strong><span>{user.role}</span></div><button className="icon-button" title="Sign out" aria-label="Sign out" onClick={signOut}><LogOut size={16} /></button></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar"><div className="breadcrumb"><span>Workspace</span><span className="slash">/</span><strong>{navItems.find((item) => item.id === section)?.label}</strong></div><div className="topbar-right"><span className="local-indicator"><i /> Local checks only</span><button className="icon-button" onClick={() => void refresh().catch((refreshError) => setError(messageOf(refreshError)))} title="Refresh workspace" aria-label="Refresh workspace"><RefreshCw size={17} /></button><span className="avatar top-avatar">{user.email.slice(0, 1).toUpperCase()}</span></div></header>
        <div className="content-wrap">
          {error && <div className="alert alert-error" role="alert"><ShieldAlert size={17} /><span>{error}</span><button className="alert-close" onClick={() => setError("")} aria-label="Dismiss error"><X size={15} /></button></div>}
          {notice && <div className="alert alert-success" role="status"><CheckCircle2 size={17} /><span>{notice}</span><button className="alert-close" onClick={() => setNotice("")} aria-label="Dismiss notification"><X size={15} /></button></div>}

          {section === "overview" && <Overview
            user={user} targets={targets} assessments={assessments} findings={findings}
            onNavigate={setSection} onAddTarget={() => { setPendingTarget(null); setTargetDialog(true); }}
            onVerify={verifyTarget} onAssess={startAssessment} onReport={getReport} reportBusy={reportBusy}
          />}
          {section === "targets" && <TargetsView
            targets={targets} onAdd={() => { setPendingTarget(null); setTargetDialog(true); }}
            onVerify={verifyTarget} onAssess={startAssessment}
          />}
          {section === "assessments" && <AssessmentsView assessments={assessments} onReport={getReport} reportBusy={reportBusy} />}
          {section === "findings" && <FindingsView findings={findings} onUpdate={updateFinding} />}
          <footer className="page-footer"><span>WebGuard · Security through good habits</span><span>Passive checks only · Educational guidance, not a penetration test.</span></footer>
        </div>
      </main>

      {targetDialog && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) { setTargetDialog(false); setPendingTarget(null); setError(""); } }}>
        <section className="modal" role="dialog" aria-modal="true" aria-labelledby="target-dialog-title">
          <div className="modal-heading"><div><p className="eyebrow">AUTHORIZED SCOPE</p><h2 id="target-dialog-title">{pendingTarget ? "Verify your domain" : "Add a target"}</h2></div><button className="icon-button" onClick={() => { setTargetDialog(false); setPendingTarget(null); setError(""); }} aria-label="Close dialog"><X size={18} /></button></div>
          {pendingTarget ? <div className="verify-panel">
            <p>Publish this DNS TXT record to prove control of <strong>{pendingTarget.target.domain}</strong>. WebGuard does not scan unverified targets.</p>
            <div className="dns-record"><span>TYPE</span><strong>TXT</strong><span>HOST / NAME</span><code>{pendingTarget.verification.hostname}</code><span>VALUE</span><code>{pendingTarget.verification.value}</code></div>
            <button className="button button-primary full-button" disabled={busy} onClick={() => void verifyTarget(pendingTarget.target.id)}><BadgeCheck size={16} /> {busy ? "Checking DNS…" : "Verify DNS record"}</button>
          </div> : <form className="auth-form" onSubmit={submitTarget}>
            <p className="muted">Enter a public domain you own or have explicit permission to assess. Only the domain name is accepted.</p>
            <label>Domain name<input required value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.com" autoComplete="off" /></label>
            <div className="scope-warning"><CircleHelp size={16} /><span>Verification uses a DNS TXT record. Assessments make one HTTPS HEAD request to the domain root.</span></div>
            <button className="button button-primary full-button" disabled={busy}><Plus size={16} /> {busy ? "Adding…" : "Add domain"}</button>
          </form>}
        </section>
      </div>}
    </div>
  );
}

function Overview(props: {
  user: User; targets: Target[]; assessments: Assessment[]; findings: Finding[];
  onNavigate: (section: Section) => void; onAddTarget: () => void;
  onVerify: (id: string) => void; onAssess: (id: string) => void;
  onReport: (assessment: Assessment, format: "json" | "html" | "pdf") => void; reportBusy: string;
}) {
  const verified = props.targets.filter((target) => target.verified_at);
  const active = props.assessments.filter((assessment) => assessment.status === "queued" || assessment.status === "running");
  const open = props.findings.filter((finding) => finding.status !== "resolved");
  const completed = props.assessments.filter((assessment) => assessment.status === "completed").length;
  return <>
    <section className="welcome-section"><div><p className="eyebrow"><span className="eyebrow-line" /> YOUR PERSONAL SAFETY SPACE</p><h1>A safer web starts<br />with <span>small steps.</span></h1><p className="welcome-copy">Welcome back, {props.user.email}. Keep an eye on your authorized web properties.</p><button className="button button-primary welcome-button" onClick={props.onAddTarget}><Plus size={16} /> Register a domain</button></div><div className="welcome-art" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="hero-shield"><ShieldCheck size={58} /></div><span className="spark spark-a">✦</span><span className="spark spark-b">✧</span></div></section>
    <section className="metrics-grid">
      <Metric icon={<Globe2 size={19} />} label="Registered targets" value={String(props.targets.length)} note={`${verified.length} verified`} tone="lavender" />
      <Metric icon={<Activity size={19} />} label="Assessments" value={String(props.assessments.length)} note={`${completed} completed`} tone="blue" />
      <Metric icon={<ShieldAlert size={19} />} label="Open findings" value={String(open.length)} note="Across your workspace" tone="peach" />
      <Metric icon={<Radar size={19} />} label="Active jobs" value={String(active.length)} note={active.length ? "Progress updating live" : "No checks running"} tone="mint" />
    </section>
    <div className="dashboard-columns">
      <section className="panel"><div className="panel-heading"><div><p className="card-kicker">AUTHORIZED SCOPE</p><h2>Your targets</h2></div><button className="subtle-button" onClick={() => props.onNavigate("targets")}>View all <ArrowRight size={15} /></button></div>
        {props.targets.length === 0 ? <EmptyState icon={<TargetIcon size={23} />} title="No targets yet" description="Register a domain you own, then verify it with a DNS TXT record." action="Register domain" onClick={props.onAddTarget} /> : <div className="compact-list">{props.targets.slice(0, 4).map((target) => <TargetRow key={target.id} target={target} onVerify={props.onVerify} onAssess={props.onAssess} />)}</div>}
      </section>
      <section className="panel"><div className="panel-heading"><div><p className="card-kicker">ASSESSMENT ACTIVITY</p><h2>Recent checks</h2></div><button className="subtle-button" onClick={() => props.onNavigate("assessments")}>View all <ArrowRight size={15} /></button></div>
        {props.assessments.length === 0 ? <EmptyState icon={<Activity size={23} />} title="No assessments" description="Verify a domain to queue your first passive check." /> : <div className="compact-list">{props.assessments.slice(0, 4).map((assessment) => <AssessmentRow key={assessment.id} assessment={assessment} onReport={props.onReport} reportBusy={props.reportBusy} />)}</div>}
      </section>
    </div>
    <section className="scope-banner"><span className="scope-icon"><ShieldEllipsis size={20} /></span><div><strong>Designed to stay in scope</strong><p>WebGuard checks only verified domains and makes one passive HTTPS request. No crawling, port scans, or exploit attempts.</p></div><span className="scope-link"><LockKeyhole size={17} /></span></section>
  </>;
}

function Metric({ icon, label, value, note, tone }: { icon: ReactNode; label: string; value: string; note: string; tone: string }) {
  return <article className="metric-card"><span className={`metric-icon ${tone}`}>{icon}</span><div><span className="metric-label">{label}</span><div className="metric-value">{value}</div><span className="metric-note">{note}</span></div></article>;
}

function EmptyState({ icon, title, description, action, onClick }: { icon: ReactNode; title: string; description: string; action?: string; onClick?: () => void }) {
  return <div className="empty-state"><span className="empty-icon">{icon}</span><strong>{title}</strong><p>{description}</p>{action && onClick && <button className="text-button" onClick={onClick}>{action} <ArrowRight size={14} /></button>}</div>;
}

function TargetRow({ target, onVerify, onAssess }: { target: Target; onVerify: (id: string) => void; onAssess: (id: string) => void }) {
  return <div className="list-row"><span className="row-icon blue"><Globe2 size={17} /></span><div className="row-copy"><strong>{target.domain}</strong><span>Added {formatDate(target.created_at)}</span></div>{target.verified_at ? <><Badge tone="good"><Check size={12} /> Verified</Badge><button className="button button-small button-soft" onClick={() => onAssess(target.id)}>Assess</button></> : <><Badge tone="warning">Unverified</Badge><button className="button button-small button-soft" onClick={() => onVerify(target.id)}>Verify</button></>}</div>;
}

function AssessmentRow({ assessment, onReport, reportBusy }: { assessment: Assessment; onReport: (assessment: Assessment, format: "json" | "html" | "pdf") => void; reportBusy: string }) {
  const active = assessment.status === "queued" || assessment.status === "running";
  return <div className="list-row assessment-row"><span className={`row-icon ${active ? "lavender" : assessment.status === "failed" ? "peach" : "mint"}`}>{active ? <Activity size={17} /> : assessment.status === "failed" ? <ShieldAlert size={17} /> : <ShieldCheck size={17} />}</span><div className="row-copy"><strong>{assessment.domain}</strong><span>{active ? assessment.stage : formatDate(assessment.created_at)}</span>{active && <div className="mini-progress"><span style={{ width: `${assessment.progress}%` }} /></div>}</div><Badge tone={active ? "info" : assessment.status === "failed" ? "danger" : "good"}>{active ? `${assessment.progress}%` : assessment.status}</Badge>{assessment.status === "completed" && <ReportMenu assessment={assessment} onReport={onReport} reportBusy={reportBusy} />}</div>;
}

function ReportMenu({ assessment, onReport, reportBusy }: { assessment: Assessment; onReport: (assessment: Assessment, format: "json" | "html" | "pdf") => void; reportBusy: string }) {
  return <div className="report-actions">{(["pdf", "html", "json"] as const).map((format) => <button key={format} title={`Download ${format.toUpperCase()} report`} aria-label={`Download ${format.toUpperCase()} report`} disabled={reportBusy === `${assessment.id}:${format}`} onClick={() => onReport(assessment, format)}><ArrowDownToLine size={14} /><span>{format.toUpperCase()}</span></button>)}</div>;
}

function TargetsView({ targets, onAdd, onVerify, onAssess }: { targets: Target[]; onAdd: () => void; onVerify: (id: string) => void; onAssess: (id: string) => void }) {
  return <><PageHeading eyebrow="AUTHORIZED SCOPE" title="Your targets" description="Register a public domain and verify ownership before an assessment can run." action={<button className="button button-primary" onClick={onAdd}><Plus size={16} /> Add target</button>} />
    <div className="scope-banner scope-banner-large"><span className="scope-icon"><LockKeyhole size={19} /></span><div><strong>Prove domain control first</strong><p>WebGuard provides a unique DNS TXT challenge. Assessment stays disabled until that record is verified.</p></div></div>
    <section className="panel data-panel">    {targets.length ? <div className="table-wrap"><table><thead><tr><th>DOMAIN</th><th>STATUS</th><th>ADDED</th><th>ACTIONS</th></tr></thead><tbody>{targets.map((target) => <tr key={target.id}><td><span className="domain-cell"><Globe2 size={16} />{target.domain}</span></td><td>{target.verified_at ? <Badge tone="good"><Check size={12} /> Verified</Badge> : <Badge tone="warning">Verification needed</Badge>}</td><td>{formatDate(target.created_at)}</td><td><div className="table-actions">{target.verified_at ? <button className="button button-small button-soft" onClick={() => onAssess(target.id)}>Start assessment</button> : <button className="button button-small button-soft" onClick={() => onVerify(target.id)}>Check DNS</button>}</div></td></tr>)}</tbody></table></div> : <EmptyState icon={<TargetIcon size={24} />} title="No authorized targets" description="Add a domain that you own or have explicit authorization to assess." action="Register a domain" onClick={onAdd} />}</section>
  </>;
}

function AssessmentsView({ assessments, onReport, reportBusy }: { assessments: Assessment[]; onReport: (assessment: Assessment, format: "json" | "html" | "pdf") => void; reportBusy: string }) {
  return <><PageHeading eyebrow="PASSIVE SECURITY REVIEW" title="Assessment jobs" description="Each run makes one HTTPS HEAD request to the verified domain root." />
    {assessments.length ? <div className="assessment-grid">{assessments.map((assessment) => <article className="panel assessment-card" key={assessment.id}><div className="assessment-card-head"><span className={`row-icon ${assessment.status === "failed" ? "peach" : "lavender"}`}><Activity size={18} /></span><Badge tone={assessment.status === "completed" ? "good" : assessment.status === "failed" ? "danger" : assessment.status === "running" || assessment.status === "queued" ? "info" : "neutral"}>{assessment.status}</Badge></div><h3>{assessment.domain}</h3><p className="assessment-stage">{assessment.stage}</p><div className="progress-track"><span style={{ width: `${assessment.progress}%` }} /></div><div className="progress-caption"><span>{assessment.status === "failed" ? assessment.error : assessment.status === "completed" ? "Finished" : "Five-stage passive review"}</span><strong>{assessment.progress}%</strong></div><div className="assessment-card-footer"><span><Clock3 size={14} />{formatDate(assessment.created_at)}</span>{assessment.status === "completed" && <ReportMenu assessment={assessment} onReport={onReport} reportBusy={reportBusy} />}</div></article>)}</div> : <section className="panel"><EmptyState icon={<Activity size={24} />} title="Nothing here yet" description="Once you verify a domain and queue a check, its live job status will appear here." /></section>}
    {assessments.some((assessment) => assessment.status === "queued" || assessment.status === "running") && <p className="live-note"><span className="pulse-dot" /> Live progress refreshes automatically while a job is active.</p>}
  </>;
}

function FindingsView({ findings, onUpdate }: { findings: Finding[]; onUpdate: (finding: Finding, status: Finding["status"]) => void }) {
  const [filter, setFilter] = useState("all");
  const filtered = filter === "all" ? findings : findings.filter((finding) => finding.status === filter);
  return <><PageHeading eyebrow="REMEDIATION TRACKER" title="Findings & fixes" description="Review passive observations and keep remediation progress up to date." />
    <div className="filter-bar">{["all", "open", "in_progress", "resolved"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => setFilter(item)}>{item === "all" ? "All findings" : item.replace("_", " ")}</button>)}</div>
    {filtered.length ? <div className="findings-list">{filtered.map((finding) => <article className="panel finding-card" key={finding.id}><div className="finding-main"><span className={`severity-mark severity-${finding.severity}`}><ShieldAlert size={17} /></span><div className="finding-copy"><div className="finding-title"><h3>{finding.title}</h3><Badge tone={`severity-${finding.severity}`}>{finding.severity}</Badge></div><p>{finding.description}</p><div className="remediation-box"><strong>Suggested remediation</strong><span>{finding.remediation}</span></div>{finding.remediation_note && <p className="remediation-note">Note: {finding.remediation_note}</p>}<span className="finding-domain"><Globe2 size={13} />{finding.domain} · {formatDate(finding.created_at)}</span></div></div><label className="status-select-label">Status<select value={finding.status} onChange={(event) => void onUpdate(finding, event.target.value as Finding["status"])}><option value="open">Open</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option></select></label></article>)}</div> : <section className="panel"><EmptyState icon={<CheckCircle2 size={24} />} title={filter === "all" ? "No findings yet" : "No matching findings"} description="Complete an assessment to see passive security observations and suggested fixes." /></section>}
  </>;
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <section className="page-heading"><div><p className="eyebrow"><span className="eyebrow-line" />{eyebrow}</p><h1>{title}</h1><p className="welcome-copy">{description}</p></div>{action}</section>;
}

export default App;

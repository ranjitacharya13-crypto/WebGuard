# WebGuard

WebGuard is a local-first workspace for **authorized, passive web security reviews**. It combines a React, Vite, and TypeScript frontend with a Node.js/Express TypeScript API and a versioned SQLite schema.

> **Scope and safety:** WebGuard is not a penetration-testing tool. It does not crawl a site, enumerate ports, try credentials, submit forms, exploit vulnerabilities, or test arbitrary URLs. A user must prove control of a public domain with DNS before starting an assessment. Each assessment makes exactly one HTTPS `HEAD /` request and inspects the response status, TLS connection, and selected security headers. Checks are blocked for domains resolving to private or reserved addresses. Only assess systems you own or have explicit permission to assess.

## Requirements

- Node.js 22.13+ (Node 24 LTS recommended; uses the built-in `node:sqlite` module)
- npm 10+
- Git (for cloning)

## Run locally (Windows PowerShell)

From the folder where you cloned this repository:

```powershell
cd .\WebGuard
npm install
Copy-Item .\backend\.env.example .\backend\.env
```

Generate and set a private JWT signing secret in `backend\.env` (do not commit that file):

```powershell
$secret = node -p "require('node:crypto').randomBytes(32).toString('hex')"
notepad .\backend\.env
```

In Notepad, replace `JWT_SECRET=replace-with-at-least-32-random-characters` with `JWT_SECRET=` followed by the value printed by the first command, then save and close the file. Keep `.env` private.

Initialize the local database by starting the API once. The versioned migration runs automatically and creates `backend/data/webguard.db`:

```powershell
npm run dev
```

Open **http://127.0.0.1:5173**. The API listens on **http://127.0.0.1:4174**. Press `Ctrl+C` in the terminal to stop both services.

The database is local and is excluded from Git. The development server creates it at `backend/data/webguard.db` on first start.

## Environment configuration

Copy `backend/.env.example` to `backend/.env` and set:

| Variable | Description |
| --- | --- |
| `NODE_ENV` | `development` or `production`. |
| `PORT` | API port (default `4174`). |
| `JWT_SECRET` | Private signing secret, at least 32 characters. |
| `ADMIN_EMAIL` | Optional email that receives the admin role when its account is registered. Leave blank for regular accounts only. |
| `FRONTEND_ORIGIN` | Exact browser origin allowed by CORS (default `http://127.0.0.1:5173`). |
| `DATABASE_PATH` | SQLite file path; defaults to `backend/data/webguard.db` from the repository root. |

Never put a real secret or `.env` file in a commit. If the optional admin is enabled, register its configured email once; public registration otherwise only creates user accounts.

## Workflow

1. **Register / sign in:** create an account with a unique, 12-character-minimum password.
2. **Register target:** submit a public domain name (not a URL, IP, localhost, or private network).
3. **Verify authorization:** add the displayed TXT value at `_webguard.<domain>` in the domain's DNS. After it propagates, select **Verify DNS record**.
4. **Run an assessment:** queue a five-stage background job. The UI polls job progress while it runs.
5. **Review and remediate:** see observations about HTTPS and security headers, update each finding's status, and add remediation notes.
6. **Export:** download a completed assessment report as PDF, HTML, or JSON.

Users can access their own targets and assessment data. The optional administrator role can view all users and resources. Tokens are held in browser session storage and expire after eight hours. Passwords are hashed; assessment data stays in the local SQLite database.

## Assessment stages and limitations

The progress stages are: confirming target authorization, resolving its domain, checking HTTPS and the certificate, reviewing response headers, and saving findings. A stage is orchestration/progress reporting—not a separate probe. WebGuard uses a single HTTPS HEAD request to `/` (no redirect following), checks for common security headers, and reports suggestions. The observations are not a guarantee of safety, a full audit, or a substitute for expert review. Missing headers may be intentional for a particular site.

Domain ownership is verified through a DNS TXT challenge. DNS publication and propagation are controlled by the domain owner. The hostname is resolved and rejected if it points to non-public addresses; the request uses the checked address and normal TLS hostname verification.

## Development and verification

```powershell
npm run typecheck
npm test
npm run build
```

The backend tests cover migration initialization, password validation and hashing, roles, target validation, authorization boundaries, report formats, and local-address blocking. Tests use a temporary SQLite file and remove it afterward.

For production, build the workspaces and run the compiled API:

```powershell
npm run build
npm start
```

Serve `frontend/dist` from a static web server configured to proxy `/api` to the API. Set `NODE_ENV=production`, `FRONTEND_ORIGIN` to the deployed frontend origin, and a private `DATABASE_PATH` outside any public static directory.

## License

MIT

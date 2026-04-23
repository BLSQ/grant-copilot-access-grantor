# COPA AI Access Grantor

Web tool that provisions user access across Auth0, 1Password, and Resend in one step.

## What it does

For each email address submitted:

1. **Generates** a secure 24-character password
2. **Creates** a Login item in 1Password with the credentials
3. **Gets** a share link for the 1Password item (expires in 14 days)
4. **Creates** a user in Auth0 (EU) with the email + password in the specified connection
5. **Sends** an email via Resend with the 1Password share link

## Quick start

Only requires [Docker Desktop](https://www.docker.com/products/docker-desktop/).

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and make sure it's running
2. Copy `.env.example` to `.env` and fill in the credentials
3. **Windows:** double-click `start.bat`
   **Mac/Linux:** run `./start.sh`

The browser opens automatically at [http://localhost:9999](http://localhost:9999).

## Local development

Requires Python 3.11+.

```bash
# Install deps + start server + open browser
make
```

### Makefile targets

| Target | Description |
|---|---|
| `make` | Install deps, start server, open browser |
| `make docker` | Build and run via Docker |
| `make docker-build` | Build Docker image only |
| `make docker-run` | Run Docker container only |
| `make install-deps` | Install Python deps |
| `make run` | Start server on port 9999 |

## Architecture

```
Browser (index.html)
  │
  │  POST /api/grant  (SSE stream)
  ▼
FastAPI (app.py)
  ├── 1Password Python SDK (item create / share / delete)
  ├── Auth0 Management API (httpx)
  └── Resend API (httpx)
```

The frontend sends one request per email. The backend streams Server-Sent Events back so the UI shows real-time progress per step. If any step fails, previously created resources are rolled back automatically.

## Configuration reference

| Variable | Description |
|---|---|
| `AUTH0_DOMAIN` | Auth0 tenant domain, e.g. `my-tenant.eu.auth0.com` |
| `AUTH0_CLIENT_ID` | M2M application client ID |
| `AUTH0_CLIENT_SECRET` | M2M application client secret |
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password Service Account token |
| `OP_VAULT_ID` | UUID of the 1Password vault for storing credentials |
| `RESEND_API_KEY` | Resend API key |
| `RESEND_FROM` | Sender address for emails |

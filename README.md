# COPA AI Access Grantor

Web tool that provisions user access across Auth0, 1Password, and Mailgun/Resend in one step.

## What it does

For each email address submitted:

1. **Generates** a secure 24-character password
2. **Creates** a Login item in 1Password with the credentials
3. **Gets** a share link for the 1Password item (expires in 14 days)
4. **Creates** a user in Auth0 (EU) with the email + password in the specified connection
5. **Sends** an email via Mailgun/Resend with the 1Password share link

## Prerequisites

- **Python 3.11+**
- **1Password CLI (`op`)** — [install guide](https://developer.1password.com/docs/cli/get-started/) 
  - `brew install 1password-cli`
- **1Password Service Account token** with vault access
- **Auth0 Machine-to-Machine application** with Management API permissions (`create:users`)
- **Mailgun/Resend account** with a verified sending domain

## Setup

```bash
# Install all prerequisites (1Password CLI + Python deps)
make setup

# Copy .env.example and fill in your credentials
cp .env.example .env
# Edit .env with your values
```

## Run

```bash
make run
```

Open [http://localhost:9000](http://localhost:9000).

### Makefile targets

| Target | Description |
|---|---|
| `make setup` | Install 1Password CLI + Python deps |
| `make install-op` | Install 1Password CLI only |
| `make install-deps` | Install Python deps only |
| `make run` | Start server on port 9000 |

## Architecture

```
Browser (index.html)
  │
  │  POST /api/grant  (SSE stream)
  ▼
FastAPI (app.py)
  ├── 1Password CLI (op item create / op item share)
  ├── Auth0 Management API (httpx)
  └── Mailgun API (httpx)
```

The frontend sends one request per email. The backend streams Server-Sent Events back so the UI shows real-time progress per step.

## Configuration reference

| Variable | Description |
|---|---|
| `AUTH0_DOMAIN` | Auth0 tenant domain, e.g. `my-tenant.eu.auth0.com` |
| `AUTH0_CLIENT_ID` | M2M application client ID |
| `AUTH0_CLIENT_SECRET` | M2M application client secret |
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password Service Account token |
| `OP_VAULT_ID` | UUID of the 1Password vault for storing credentials |
| `MAILGUN_API_KEY` | Mailgun private API key |
| `MAILGUN_DOMAIN` | Mailgun sending domain |
| `MAILGUN_EU` | Set `True` for EU Mailgun region |
| `MAILGUN_FROM` | Sender address for emails |

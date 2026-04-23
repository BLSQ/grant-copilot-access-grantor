"""
COPA AI Access Grantor — Grant access via Auth0 + 1Password + Resend.

Usage:
    pip install -r requirements.txt
    python app.py

Then open http://localhost:9999
"""

import asyncio
import json
import os
import secrets
import string
import time

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from onepassword import (
    Client as OPClient,
    AutofillBehavior,
    Item,
    ItemCategory,
    ItemCreateParams,
    ItemField,
    ItemFieldType,
    AllowedRecipientType,
    AllowedType,
    ItemShareAccountPolicy,
    ItemShareDuration,
    ItemShareFiles,
    ItemShareParams,
    Website,
)
from pathlib import Path
from pydantic import BaseModel

load_dotenv()

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION — reads from .env (see .env.example)
# ═══════════════════════════════════════════════════════════════

COPA_AI_DOMAIN = "https://dev.copa-ai.org"

AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
AUTH0_CLIENT_ID = os.environ["AUTH0_CLIENT_ID"]
AUTH0_CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]

OP_SERVICE_ACCOUNT_TOKEN = os.environ["OP_SERVICE_ACCOUNT_TOKEN"]
OP_VAULT_ID = os.environ["OP_VAULT_ID"]

RESEND_API_KEY = os.environ["RESEND_API_KEY"]
RESEND_FROM = os.environ["RESEND_FROM"]

PASSWORD_LENGTH = int(os.getenv("PASSWORD_LENGTH", "24"))

# ═══════════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="COPA AI: Access Grantor")


# ───────────────────────────────────────────────────────────────
# Password generation
# ───────────────────────────────────────────────────────────────

def generate_password(length: int = PASSWORD_LENGTH) -> str:
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*_+-="
    all_chars = upper + lower + digits + special

    # Guarantee at least 2 of each character class
    chars = [
        secrets.choice(upper), secrets.choice(upper),
        secrets.choice(lower), secrets.choice(lower),
        secrets.choice(digits), secrets.choice(digits),
        secrets.choice(special), secrets.choice(special),
    ]
    chars += [secrets.choice(all_chars) for _ in range(length - 8)]

    # Fisher-Yates shuffle
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


# ───────────────────────────────────────────────────────────────
# 1Password (Python SDK)
# ───────────────────────────────────────────────────────────────

_op_client: OPClient | None = None


async def get_op_client() -> OPClient:
    global _op_client
    if _op_client is None:
        _op_client = await OPClient.authenticate(
            auth=OP_SERVICE_ACCOUNT_TOKEN,
            integration_name="COPA AI Access Grantor",
            integration_version="1.0.0",
        )
    return _op_client


async def create_op_item(email: str, password: str) -> Item:
    """Create a Login item in 1Password vault."""
    client = await get_op_client()

    params = ItemCreateParams(
        vault_id=OP_VAULT_ID,
        title=f"COPA AI: Access — {email}",
        category=ItemCategory.LOGIN,
        fields=[
            ItemField(id="username", title="username", value=email, field_type=ItemFieldType.TEXT),
            ItemField(id="password", title="password", value=password, field_type=ItemFieldType.CONCEALED),
        ],
        websites=[
            Website(url=COPA_AI_DOMAIN, label="website", autofill_behavior=AutofillBehavior.ANYWHEREONWEBSITE),
        ],
    )

    return await client.items.create(params)


async def create_share_link(item: Item) -> str:
    """Create a 14-day share link for a 1Password item."""
    client = await get_op_client()
    policy = ItemShareAccountPolicy(
        max_expiry=ItemShareDuration.FOURTEENDAYS,
        default_expiry=ItemShareDuration.FOURTEENDAYS,
        allowed_types=[AllowedType.AUTHENTICATED, AllowedType.PUBLIC],
        allowed_recipient_types=[AllowedRecipientType.EMAIL],
        files=ItemShareFiles(allowed=False, max_size=0),
    )
    params = ItemShareParams(
        expire_after=ItemShareDuration.FOURTEENDAYS,
        one_time_only=False,
    )
    return await client.items.shares.create(
        item=item,
        policy=policy,
        params=params,
    )


async def find_op_item(email: str) -> str | None:
    """Find a 1Password item by email. Returns item ID or None."""
    client = await get_op_client()
    items = await client.items.list(OP_VAULT_ID)
    target_title = f"COPA AI: Access — {email}"
    for item in items:
        if item.title == target_title:
            return item.id
    return None


async def delete_op_item(item_id: str) -> None:
    """Delete a 1Password item."""
    client = await get_op_client()
    await client.items.delete(vault_id=OP_VAULT_ID, item_id=item_id)


# ───────────────────────────────────────────────────────────────
# Auth0 Management API
# ───────────────────────────────────────────────────────────────

_auth0_token: str | None = None
_auth0_token_expiry: float = 0


async def get_auth0_token(http: httpx.AsyncClient) -> str:
    global _auth0_token, _auth0_token_expiry

    if _auth0_token and time.time() < _auth0_token_expiry:
        return _auth0_token

    resp = await http.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
        },
    )
    resp.raise_for_status()
    data = resp.json()

    _auth0_token = data["access_token"]
    _auth0_token_expiry = time.time() + data.get("expires_in", 3600) - 60
    return _auth0_token


async def create_auth0_user(
    http: httpx.AsyncClient, email: str, password: str, connection: str
) -> dict:
    token = await get_auth0_token(http)

    resp = await http.post(
        f"https://{AUTH0_DOMAIN}/api/v2/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "email": email,
            "password": password,
            "connection": connection,
            "email_verified": False,
        },
    )

    if resp.status_code == 409:
        raise RuntimeError(f"User {email} already exists in Auth0")

    resp.raise_for_status()
    return resp.json()


async def find_auth0_user(http: httpx.AsyncClient, email: str, connection: str) -> str | None:
    """Find an Auth0 user by email. Returns user_id or None."""
    token = await get_auth0_token(http)
    resp = await http.get(
        f"https://{AUTH0_DOMAIN}/api/v2/users",
        headers={"Authorization": f"Bearer {token}"},
        params={
            "q": f'email:"{email}" AND identities.connection:"{connection}"',
            "search_engine": "v3",
        },
    )
    resp.raise_for_status()
    users = resp.json()
    if users:
        return users[0]["user_id"]
    return None


async def delete_auth0_user(http: httpx.AsyncClient, user_id: str) -> None:
    """Delete an Auth0 user."""
    token = await get_auth0_token(http)
    resp = await http.delete(
        f"https://{AUTH0_DOMAIN}/api/v2/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()


# ───────────────────────────────────────────────────────────────
# Resend
# ───────────────────────────────────────────────────────────────

async def send_email(http: httpx.AsyncClient, to_email: str, share_link: str) -> dict:
    html_body = f"""\
<div style="font-family: -apple-system, sans-serif; max-width: 520px; margin: 0 auto; padding: 2rem;">
  <img src="https://dev.copa-ai.org/assets/gaia-logo-without-text-DEsdmCrX.png" alt="COPA AI" style="width: 48px; height: 48px; margin-bottom: 1rem;">
  <h2 style="color: #1a1a2e;">Your access has been granted</h2>
  <p>Hello,</p>
  <p>An account in copa-ai.org has been created for you. Your login credentials are stored securely in the following link.</p>
  <p>
    <a href="{share_link}"
       style="display: inline-block; background: #4f6ef7; color: #fff; padding: 0.6rem 1.5rem;
              border-radius: 6px; text-decoration: none; font-weight: 600;">
      View your credentials
    </a>
  </p>
  <p style="color: #888; font-size: 0.85rem;">This link will expire in 14 days.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 1.5rem 0;">
  <p style="color: #aaa; font-size: 0.8rem;">Sent by COPA AI </p>
</div>"""

    resp = await http.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
        json={
            "from": RESEND_FROM,
            "to": [to_email],
            "subject": "COPA AI: Your access credentials",
            "html": html_body,
        },
    )
    resp.raise_for_status()
    return resp.json()


# ───────────────────────────────────────────────────────────────
# SSE helpers
# ───────────────────────────────────────────────────────────────

def sse_event(step: str, status: str, error: str | None = None) -> str:
    payload = {"step": step, "status": status}
    if error:
        payload["error"] = error
    return f"data: {json.dumps(payload)}\n\n"


# ───────────────────────────────────────────────────────────────
# API routes
# ───────────────────────────────────────────────────────────────

class GrantRequest(BaseModel):
    email: str
    connection: str


@app.post("/api/grant")
async def grant(req: GrantRequest):
    async def stream():
        auth0_user_id: str | None = None

        async def cleanup(
            http: httpx.AsyncClient,
            failed_step: str,
            error: str,
            op_id: str | None = None,
            auth0_id: str | None = None,
        ):
            """Roll back previously created resources."""
            rollbacks = []
            if auth0_id:
                rollbacks.append(("auth0", delete_auth0_user(http, auth0_id)))
            if op_id:
                rollbacks.append(("1password", delete_op_item(op_id)))

            if not rollbacks:
                return

            yield sse_event("cleanup", "running", f"{failed_step} failed — rolling back")
            errors = []
            for name, coro in rollbacks:
                try:
                    await coro
                except Exception as re:
                    errors.append(f"{name}: {re}")

            if errors:
                yield sse_event("cleanup", "error", "; ".join(errors))
            else:
                yield sse_event("cleanup", "done")

        async with httpx.AsyncClient(timeout=30) as http:
            # Step 1 — Generate password
            yield sse_event("password", "running")
            try:
                password = generate_password()
                yield sse_event("password", "done")
            except Exception as e:
                yield sse_event("password", "error", str(e))
                return

            # Step 2 — Create 1Password item
            yield sse_event("1password", "running")
            try:
                op_item = await create_op_item(req.email, password)
                yield sse_event("1password", "done")
            except Exception as e:
                yield sse_event("1password", "error", str(e))
                return

            # Step 3 — Get share link
            yield sse_event("share", "running")
            try:
                share_link = await create_share_link(op_item)
                yield sse_event("share", "done")
            except Exception as e:
                yield sse_event("share", "error", str(e))
                async for event in cleanup(http, "share", str(e), op_id=op_item.id):
                    yield event
                return

            # Step 4 — Create Auth0 user
            yield sse_event("auth0", "running")
            try:
                auth0_user = await create_auth0_user(http, req.email, password, req.connection)
                auth0_user_id = auth0_user["user_id"]
                yield sse_event("auth0", "done")
            except Exception as e:
                yield sse_event("auth0", "error", str(e))
                async for event in cleanup(http, "auth0", str(e), op_id=op_item.id):
                    yield event
                return

            # Step 5 — Send email
            yield sse_event("email", "running")
            try:
                await send_email(http, req.email, share_link)
                yield sse_event("email", "done")
            except Exception as e:
                yield sse_event("email", "error", str(e))
                async for event in cleanup(http, "email", str(e), op_id=op_item.id, auth0_id=auth0_user_id):
                    yield event
                return

    return StreamingResponse(stream(), media_type="text/event-stream")


class RevokeRequest(BaseModel):
    email: str
    connection: str


@app.post("/api/revoke")
async def revoke(req: RevokeRequest):
    async def stream():
        async with httpx.AsyncClient(timeout=30) as http:
            # Step 1 — Find and delete Auth0 user
            yield sse_event("auth0_find", "running")
            try:
                user_id = await find_auth0_user(http, req.email, req.connection)
                if user_id:
                    yield sse_event("auth0_find", "done")
                    yield sse_event("auth0_delete", "running")
                    await delete_auth0_user(http, user_id)
                    yield sse_event("auth0_delete", "done")
                else:
                    yield sse_event("auth0_find", "done", "User not found in Auth0 — skipped")
            except Exception as e:
                yield sse_event("auth0_find", "error", str(e))
                return

            # Step 2 — Find and delete 1Password item
            yield sse_event("op_find", "running")
            try:
                op_item_id = await find_op_item(req.email)
                if op_item_id:
                    yield sse_event("op_find", "done")
                    yield sse_event("op_delete", "running")
                    await delete_op_item(op_item_id)
                    yield sse_event("op_delete", "done")
                else:
                    yield sse_event("op_find", "done", "Item not found in 1Password — skipped")
            except Exception as e:
                yield sse_event("op_find", "error", str(e))
                return

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/")
async def index():
    html = Path(__file__).parent / "index.html"
    return HTMLResponse(html.read_text())


# ───────────────────────────────────────────────────────────────
# Run
# ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9999)

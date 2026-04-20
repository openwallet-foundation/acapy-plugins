# 🔐 Authorization Server for OID4VCI

## 📌 Overview

🚀 Modular OAuth 2.0 authorization server for OpenID for Verifiable Credential Issuance (OID4VCI), decoupled from the Credential Issuer. The server handles authorization, grants, token issuance/validation, and introspection; the Issuer focuses on credential generation.

## ✨ Features

- 🧩 Admin API (tenants, keys, migrations) and Tenant API (tokens, introspection, OIDC discovery)
- 🔐 Pre‑Authorized Code flow
- 🛡️ DPoP‑bound access tokens (to be added)
- 📄 Authorization Details and 🧾 Attestation PoP verification
- 🔁 Refresh token rotation and 🧠 token introspection
- 🏷️ Multi‑tenant auth server (database‑per‑tenant isolation)

## ⚡️ Quick Start

- Prereqs: Python 3.12, PostgreSQL, Poetry
- Install dependencies: `poetry install`
- Configure env files (examples below)
- Run `alembic/sql/init.sql` to create the admin user and database
- Initialize Admin DB schema (Alembic): `python alembic/admin/migrate.py`
- Run Admin API (e.g., port 9000): `uvicorn admin.main:app --reload --port 9000`
- Run Tenant API (e.g., port 9001): `uvicorn tenant.main:app --reload --port 9001`

## 🔐 Environment Files

- Copy the example envs to local files and update values:
  - `cp resources/.env.admin.example .env.admin`
  - `cp resources/.env.tenant.example .env.tenant`
- Do not commit real `.env.*` files. The repo ignores them; only `resources/*.example` are tracked.

### Minimal .env.admin

```
ADMIN_DB_USER=postgres
ADMIN_DB_PASSWORD=postgres
ADMIN_DB_HOST=localhost
ADMIN_DB_PORT=5432
ADMIN_DB_NAME=auth_server_admin
ADMIN_DB_SCHEMA=admin
ADMIN_INTERNAL_AUTH_TOKEN=admin-internal-token
```

### Minimal .env.tenant

```
TENANT_ISSUER_BASE_URL=http://localhost:9001
TENANT_INTERNAL_BASE_URL=http://localhost:9000/internal
TENANT_INTERNAL_AUTH_TOKEN=admin-internal-token
```

## ✅ Health Checks

- Admin: GET `http://localhost:9000/healthz`
- Tenant: GET `http://localhost:9001/healthz`
- Tenant: GET `http://localhost:9001/tenants/{uid}/healthz

## 📚 Docs

- Architecture and API details: `docs/auth-server-design.md`

## 🧹 Repo Hygiene

- Local env files `.env.*` are ignored; use the `*.example` templates.
- Test and analysis outputs like `.test-reports/` and `.VSCodeCounter/` are ignored.
- Ruff is configured in `pyproject.toml`. Run `ruff check` locally if installed.

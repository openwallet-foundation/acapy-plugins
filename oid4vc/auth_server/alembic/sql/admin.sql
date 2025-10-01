CREATE TABLE IF NOT EXISTS tenant (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  uid TEXT NOT NULL UNIQUE, -- external id/uuid/did
  name TEXT UNIQUE, -- optional unique display name
  db_name TEXT,
  db_schema TEXT,
  db_user TEXT,
  db_pwd_enc TEXT, -- encrypted password
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS tenant_key (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id BIGINT NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  public_jwk JSONB NOT NULL,
  private_pem_enc TEXT, -- encrypted private key material (or KMS handle)
  status TEXT NOT NULL DEFAULT 'active', -- active | retiring | retired
  not_before TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  not_after TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ,
  UNIQUE (tenant_id, kid)
);

CREATE INDEX IF NOT EXISTS idx_tenant_active ON tenant (active);

CREATE INDEX IF NOT EXISTS idx_tenant_name ON tenant (name);

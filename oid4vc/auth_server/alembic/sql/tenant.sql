CREATE TABLE IF NOT EXISTS client (
  id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  client_id TEXT NOT NULL UNIQUE,
  client_auth_method TEXT NOT NULL,
  client_auth_signing_alg TEXT,
  client_secret TEXT,
  jwks JSONB,
  jwks_uri TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS subject (
  id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  uid TEXT NOT NULL UNIQUE,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS pre_auth_code (
  id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES subject (id) ON UPDATE CASCADE ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  user_pin TEXT,
  user_pin_required BOOLEAN NOT NULL DEFAULT FALSE,
  authorization_details JSONB,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS access_token (
  id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES subject (id) ON UPDATE CASCADE ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  cnf_jkt TEXT,
  metadata JSONB
);

CREATE TABLE IF NOT EXISTS refresh_token (
  id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES subject (id) ON UPDATE CASCADE ON DELETE CASCADE,
  access_token_id INTEGER NOT NULL REFERENCES access_token (id) ON UPDATE CASCADE ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  metadata JSONB
);

CREATE TABLE IF NOT EXISTS dpop_jti (
  id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES subject (id) ON UPDATE CASCADE ON DELETE CASCADE,
  jti TEXT NOT NULL UNIQUE,
  htm TEXT,
  htu TEXT,
  cnf_jkt TEXT,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_token_expires_at ON access_token (expires_at);

CREATE INDEX IF NOT EXISTS idx_access_token_cnf_jkt ON access_token (cnf_jkt);

CREATE INDEX IF NOT EXISTS idx_refresh_token_expires_at ON refresh_token (expires_at);

CREATE INDEX IF NOT EXISTS idx_refresh_token_active ON refresh_token (token_hash)
WHERE
  used = FALSE
  AND revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_pre_auth_code_expires_at ON pre_auth_code (expires_at);

CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires_at ON dpop_jti (expires_at);

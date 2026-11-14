CREATE SCHEMA st;
REVOKE ALL ON SCHEMA st FROM PUBLIC;
GRANT USAGE ON SCHEMA st TO shadowtrace_app;

CREATE TABLE st.workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,47}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 7 AND 365)
);
CREATE TABLE st.principals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer text NOT NULL,
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  UNIQUE (issuer, subject)
);
CREATE TABLE st.memberships (
  workspace_id uuid REFERENCES st.workspaces ON DELETE CASCADE,
  principal_id uuid REFERENCES st.principals ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('analyst','admin')),
  PRIMARY KEY(workspace_id,principal_id)
);
CREATE INDEX memberships_principal ON st.memberships(principal_id);
CREATE TABLE st.sessions (
  digest text PRIMARY KEY CHECK (length(digest) = 64),
  principal_id uuid NOT NULL REFERENCES st.principals ON DELETE CASCADE,
  csrf text NOT NULL,
  expires_at timestamptz NOT NULL,
  last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_expires ON st.sessions(expires_at);
CREATE TABLE st.keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES st.workspaces ON DELETE CASCADE,
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 60),
  prefix text NOT NULL,
  digest text NOT NULL UNIQUE CHECK (length(digest) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (workspace_id,id)
);
CREATE UNIQUE INDEX keys_active_name ON st.keys(workspace_id,lower(label)) WHERE revoked_at IS NULL;
CREATE TABLE st.policy (
  workspace_id uuid PRIMARY KEY REFERENCES st.workspaces ON DELETE CASCADE,
  version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  view_limit integer NOT NULL DEFAULT 500 CHECK(view_limit BETWEEN 1 AND 100000),
  export_limit integer NOT NULL DEFAULT 500 CHECK(export_limit BETWEEN 1 AND 100000)
);
CREATE TABLE st.events (
  workspace_id uuid NOT NULL REFERENCES st.workspaces ON DELETE CASCADE,
  event_id text NOT NULL,
  actor_id text NOT NULL,
  key_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('view','export')),
  resource_type text NOT NULL CHECK (resource_type IN ('customer','order','invoice')),
  records_accessed integer NOT NULL CHECK (records_accessed BETWEEN 0 AND 1000000),
  outcome text NOT NULL CHECK ((outcome = 'success' AND records_accessed > 0)
    OR (outcome = 'failure' AND records_accessed = 0)),
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  fingerprint text NOT NULL,
  PRIMARY KEY (workspace_id,event_id),
  FOREIGN KEY (workspace_id,key_id) REFERENCES st.keys(workspace_id,id)
);
CREATE INDEX events_recent ON st.events(workspace_id,received_at DESC,event_id DESC);
CREATE INDEX events_view_window ON st.events(workspace_id,actor_id,resource_type,received_at)
  WHERE action='view' AND outcome='success';
CREATE TABLE st.cases (
  id uuid DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES st.workspaces ON DELETE CASCADE,
  actor_id text NOT NULL,
  resource_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('high','critical')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_review','resolved','dismissed')),
  version integer NOT NULL DEFAULT 1,
  opened_at timestamptz NOT NULL,
  latest_at timestamptz NOT NULL,
  evidence_expired boolean NOT NULL DEFAULT false,
  PRIMARY KEY (workspace_id,id)
);
CREATE INDEX cases_recent ON st.cases(workspace_id,latest_at DESC,id DESC);
CREATE INDEX cases_active ON st.cases(workspace_id,actor_id,resource_type,latest_at DESC)
  WHERE status IN ('open','in_review');
CREATE TABLE st.signals (
  workspace_id uuid NOT NULL,
  case_id uuid NOT NULL,
  rule text NOT NULL CHECK (rule IN ('view_burst','large_export')),
  rule_version integer NOT NULL,
  threshold integer NOT NULL,
  observed bigint NOT NULL,
  detected_at timestamptz NOT NULL,
  PRIMARY KEY(workspace_id,case_id,rule,rule_version),
  FOREIGN KEY(workspace_id,case_id) REFERENCES st.cases(workspace_id,id) ON DELETE CASCADE
);
CREATE TABLE st.evidence (
  workspace_id uuid NOT NULL,
  case_id uuid NOT NULL,
  event_id text NOT NULL,
  PRIMARY KEY(workspace_id,case_id,event_id),
  FOREIGN KEY(workspace_id,case_id) REFERENCES st.cases(workspace_id,id) ON DELETE CASCADE,
  FOREIGN KEY(workspace_id,event_id) REFERENCES st.events(workspace_id,event_id) ON DELETE CASCADE
);
CREATE INDEX evidence_by_event ON st.evidence(workspace_id,event_id);
CREATE TABLE st.reviews (
  workspace_id uuid NOT NULL,
  case_id uuid NOT NULL,
  mutation_id uuid NOT NULL,
  author_id uuid NOT NULL REFERENCES st.principals,
  author text NOT NULL,
  status text NOT NULL CHECK (status IN ('open','in_review','resolved','dismissed')),
  note text NOT NULL CHECK(length(note) <= 1000),
  case_version integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(workspace_id,case_id,mutation_id),
  FOREIGN KEY(workspace_id,case_id) REFERENCES st.cases(workspace_id,id) ON DELETE CASCADE
);
CREATE INDEX reviews_recent ON st.reviews(workspace_id,case_id,created_at DESC);
CREATE TABLE st.audit (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES st.workspaces ON DELETE CASCADE,
  actor text NOT NULL,
  operation text NOT NULL,
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_recent ON st.audit(workspace_id,id DESC);
CREATE TABLE st.oidc_state (
  cache_key text PRIMARY KEY,
  payload text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX oidc_state_expires ON st.oidc_state(expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON st.oidc_state TO shadowtrace_app;
CREATE TABLE st.rate_limits (
  scope text NOT NULL,
  bucket bigint NOT NULL,
  uses integer NOT NULL DEFAULT 1,
  PRIMARY KEY (scope,bucket)
);
CREATE INDEX rate_bucket ON st.rate_limits(bucket);

CREATE FUNCTION st.tenant() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('st.tenant_id',true),'')::uuid $$;
CREATE FUNCTION st.principal() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('st.principal_id',true),'')::uuid $$;
CREATE FUNCTION st.identity(p_issuer text,p_subject text) RETURNS TABLE(id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$ SELECT id FROM st.principals WHERE issuer=p_issuer AND subject=p_subject $$;
REVOKE ALL ON FUNCTION st.identity(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION st.identity(text,text) TO shadowtrace_app;

ALTER TABLE st.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE st.workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE st.principals ENABLE ROW LEVEL SECURITY;
-- The migration owner performs the exact issuer/subject lookup using st.identity.
ALTER TABLE st.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE st.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE st.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE st.sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY own_identity ON st.principals TO shadowtrace_app USING (id=st.principal());
CREATE POLICY own_membership ON st.memberships TO shadowtrace_app USING (principal_id=st.principal());
CREATE POLICY member_workspace ON st.workspaces TO shadowtrace_app USING (
  EXISTS(SELECT 1 FROM st.memberships m WHERE m.workspace_id=id AND m.principal_id=st.principal())
);
CREATE POLICY match_session ON st.sessions TO shadowtrace_app USING (
  digest=nullif(current_setting('st.session_digest',true),'')
) WITH CHECK (
  digest=nullif(current_setting('st.session_digest',true),'')
);
GRANT SELECT ON st.workspaces,st.principals,st.memberships TO shadowtrace_app;
GRANT SELECT, INSERT, DELETE ON st.sessions TO shadowtrace_app;
GRANT UPDATE(last_seen) ON st.sessions TO shadowtrace_app;

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['keys','policy','events','cases','signals','evidence','reviews','audit']
  LOOP
    EXECUTE format('ALTER TABLE st.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE st.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY workspace ON st.%I TO shadowtrace_app USING (workspace_id=st.tenant()) WITH CHECK (workspace_id=st.tenant())',name);
  END LOOP;
END $$;
-- A key may be resolved and locked only after binding the presented digest.
CREATE POLICY match_key ON st.keys FOR SELECT TO shadowtrace_app USING (
  digest=nullif(current_setting('st.key_digest',true),'')
);

GRANT SELECT ON st.keys,st.policy,st.events,st.cases,st.signals,st.evidence,st.reviews,st.audit TO shadowtrace_app;
GRANT INSERT ON st.keys,st.events,st.cases,st.signals,st.evidence,st.reviews,st.audit TO shadowtrace_app;
GRANT UPDATE(revoked_at) ON st.keys TO shadowtrace_app;
GRANT UPDATE(view_limit,export_limit,version) ON st.policy TO shadowtrace_app;
GRANT UPDATE(severity,status,version,latest_at) ON st.cases TO shadowtrace_app;
GRANT UPDATE(observed) ON st.signals TO shadowtrace_app;
GRANT USAGE ON SEQUENCE st.audit_id_seq TO shadowtrace_app;
GRANT SELECT, INSERT, UPDATE ON st.rate_limits TO shadowtrace_app;

-- FORCE remains enabled for the owner. The operator is the schema owner and has
-- a separate explicit maintenance policy on these tables.
DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY[
      'workspaces','memberships','sessions','keys','policy','events','cases','signals','evidence','reviews','audit'
    ]
  LOOP
    EXECUTE format('CREATE POLICY maintenance ON st.%I TO %I USING (true) WITH CHECK (true)',name,current_user);
  END LOOP;
END $$;

CREATE FUNCTION st.ingest_retention(p_workspace uuid) RETURNS TABLE(retention_days integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT w.retention_days FROM st.workspaces w
  JOIN st.keys k ON k.workspace_id=w.id
  WHERE w.id=p_workspace AND p_workspace=st.tenant() AND k.revoked_at IS NULL
    AND k.digest=nullif(current_setting('st.key_digest',true),'')
$$;
REVOKE ALL ON FUNCTION st.ingest_retention(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION st.ingest_retention(uuid) TO shadowtrace_app;

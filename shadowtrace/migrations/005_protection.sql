ALTER TABLE st.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE st.keys ADD CONSTRAINT keys_purpose_check
  CHECK (purpose IN ('events','receipts','impact','protection'));

CREATE TABLE st.protection_policy (
  workspace_id uuid PRIMARY KEY REFERENCES st.workspaces ON DELETE CASCADE,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  mode text NOT NULL CHECK (mode IN ('active','paused')),
  export_limit integer NOT NULL CHECK (export_limit BETWEEN 0 AND 1000000),
  download_limit integer NOT NULL CHECK (download_limit BETWEEN 0 AND 1000000),
  share_limit integer NOT NULL CHECK (share_limit BETWEEN 0 AND 1000000),
  destinations text[] NOT NULL CHECK (cardinality(destinations) <= 20),
  CHECK (mode='paused' OR cardinality(destinations)>0)
);

CREATE TABLE st.protection_decisions (
  workspace_id uuid NOT NULL,
  key_id uuid NOT NULL,
  request_id uuid NOT NULL,
  actor_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('export','download','share')),
  resource_type text NOT NULL CHECK (resource_type IN ('customer','order','invoice')),
  record_count integer NOT NULL CHECK (record_count BETWEEN 1 AND 1000000),
  destination text NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  outcome text NOT NULL CHECK (outcome IN ('allowed','blocked')),
  reason text NOT NULL CHECK (reason IN ('allowed','paused','destination','disabled','limit')),
  revision integer NOT NULL CHECK (revision >= 0),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((outcome='allowed')=(reason='allowed')),
  PRIMARY KEY (workspace_id,request_id),
  FOREIGN KEY (workspace_id,key_id) REFERENCES st.keys(workspace_id,id)
);
CREATE INDEX protection_recent ON st.protection_decisions(workspace_id,decided_at DESC,request_id DESC,key_id DESC);
CREATE INDEX protection_source_recent ON st.protection_decisions(workspace_id,key_id,decided_at DESC);

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['protection_policy','protection_decisions']
  LOOP
    EXECUTE format('ALTER TABLE st.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE st.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY workspace ON st.%I TO shadowtrace_app USING (workspace_id=st.tenant()) WITH CHECK (workspace_id=st.tenant())',name);
    EXECUTE format('CREATE POLICY maintenance ON st.%I TO %I USING (true) WITH CHECK (true)',name,current_user);
    EXECUTE format('GRANT SELECT, INSERT ON st.%I TO shadowtrace_app',name);
  END LOOP;
END $$;
GRANT UPDATE (version,mode,export_limit,download_limit,share_limit,destinations)
  ON st.protection_policy TO shadowtrace_app;

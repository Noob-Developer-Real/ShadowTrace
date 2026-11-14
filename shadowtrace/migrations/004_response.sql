ALTER TABLE st.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE st.keys ADD CONSTRAINT keys_purpose_check CHECK (purpose IN ('events','receipts','impact'));
ALTER TABLE st.keys ADD COLUMN destination text, ADD COLUMN signing_public_key text,
  ADD COLUMN source_key_id uuid,
  ADD CONSTRAINT signing_registration CHECK (
    (destination IS NULL AND signing_public_key IS NULL) OR
    (purpose='receipts' AND destination IS NOT NULL AND signing_public_key IS NOT NULL
      AND signing_public_key ~ '^[0-9a-f]{64}$')),
  ADD CONSTRAINT impact_source CHECK ((purpose='impact')=(source_key_id IS NOT NULL)),
  ADD FOREIGN KEY (workspace_id,source_key_id) REFERENCES st.keys(workspace_id,id);
CREATE INDEX impact_source_key ON st.keys(workspace_id,source_key_id) WHERE source_key_id IS NOT NULL;

ALTER TABLE st.event_manifests ADD COLUMN artifact_sha256 text, ADD COLUMN expected_destination text,
  ADD COLUMN receipt_due_at timestamptz,
  ADD CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CHECK ((expected_destination IS NULL)=(receipt_due_at IS NULL));
CREATE INDEX manifests_monitored ON st.event_manifests(workspace_id,receipt_due_at,event_id)
  WHERE receipt_due_at IS NOT NULL;

ALTER TABLE st.destination_receipts ADD COLUMN artifact_sha256 text, ADD COLUMN signature text,
  ADD COLUMN manifest_sha256 text, ADD COLUMN file_comparison text,
  ADD COLUMN findings text[] NOT NULL DEFAULT '{}',
  ADD CHECK ((signature IS NULL AND artifact_sha256 IS NULL AND manifest_sha256 IS NULL AND file_comparison IS NULL)
    OR (signature IS NOT NULL AND artifact_sha256 IS NOT NULL AND manifest_sha256 IS NOT NULL
      AND file_comparison IS NOT NULL AND signature ~ '^[0-9a-f]{128}$'
      AND artifact_sha256 ~ '^[0-9a-f]{64}$' AND manifest_sha256 ~ '^[0-9a-f]{64}$'
      AND file_comparison IN ('same','different','unknown'))),
  ADD CHECK (findings <@ ARRAY['unexpected','different','extra']::text[]);

CREATE TABLE st.impact_requests (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  export_id text NOT NULL,
  case_id uuid NOT NULL,
  source_key_id uuid NOT NULL,
  requester_id uuid NOT NULL REFERENCES st.principals(id),
  requester text NOT NULL,
  approver_id uuid REFERENCES st.principals(id),
  approver text,
  scope text NOT NULL CHECK (scope IN ('export','received')),
  reason text NOT NULL CHECK (reason IN ('scoping','notification','remediation')),
  ticket text NOT NULL,
  fingerprints text[] NOT NULL CHECK (cardinality(fingerprints) BETWEEN 1 AND 1000),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','completed','cancelled')),
  matched_count integer CHECK (matched_count BETWEEN 0 AND cardinality(fingerprints)),
  completed_at timestamptz,
  completed_by uuid,
  FOREIGN KEY (workspace_id,completed_by) REFERENCES st.keys(workspace_id,id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours'),
  CHECK (approver_id IS NULL OR approver_id<>requester_id),
  PRIMARY KEY (workspace_id,id),
  FOREIGN KEY (workspace_id,export_id) REFERENCES st.event_manifests(workspace_id,event_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id,case_id) REFERENCES st.cases(workspace_id,id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id,source_key_id) REFERENCES st.keys(workspace_id,id)
);
CREATE INDEX impact_by_export ON st.impact_requests(workspace_id,export_id,created_at DESC,id);
CREATE INDEX impact_jobs ON st.impact_requests(workspace_id,source_key_id,created_at,id) WHERE state='approved';

CREATE TABLE st.followup_filters (
  workspace_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  reason text NOT NULL CHECK (reason IN ('','overdue','late','unexpected','different','extra')),
  state text NOT NULL CHECK (state IN ('needs','all','reviewed')),
  owner text NOT NULL CHECK (owner IN ('','me')),
  PRIMARY KEY (workspace_id,principal_id),
  FOREIGN KEY (workspace_id,principal_id) REFERENCES st.memberships(workspace_id,principal_id) ON DELETE CASCADE
);

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['impact_requests','followup_filters']
  LOOP
    EXECUTE format('ALTER TABLE st.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE st.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY maintenance ON st.%I TO %I USING (true) WITH CHECK (true)',name,current_user);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON st.%I TO shadowtrace_app',name);
  END LOOP;
END $$;
CREATE POLICY workspace ON st.impact_requests TO shadowtrace_app
  USING (workspace_id=st.tenant()) WITH CHECK (workspace_id=st.tenant());
CREATE POLICY workspace ON st.followup_filters TO shadowtrace_app
  USING (workspace_id=st.tenant() AND principal_id=st.principal())
  WITH CHECK (workspace_id=st.tenant() AND principal_id=st.principal());

CREATE FUNCTION st.receipt_workspace_slug(p_workspace uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT w.slug FROM st.workspaces w JOIN st.keys k ON k.workspace_id=w.id
  WHERE w.id=p_workspace AND w.id=st.tenant() AND k.purpose='receipts' AND k.revoked_at IS NULL
    AND k.digest=nullif(current_setting('st.key_digest',true),'')
$$;
REVOKE ALL ON FUNCTION st.receipt_workspace_slug(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION st.receipt_workspace_slug(uuid) TO shadowtrace_app;

CREATE INDEX receipt_exceptions ON st.destination_receipts(workspace_id,export_id)
  WHERE cardinality(findings)>0;
CREATE INDEX impact_completions ON st.impact_requests(workspace_id,completed_by,completed_at DESC)
  WHERE completed_by IS NOT NULL;

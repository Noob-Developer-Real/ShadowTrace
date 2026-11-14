ALTER TABLE st.protection_decisions ADD COLUMN intent jsonb NOT NULL DEFAULT '{}';
ALTER TABLE st.protection_decisions DROP CONSTRAINT protection_decisions_reason_check;
ALTER TABLE st.protection_decisions ADD CHECK
  (reason IN ('allowed','paused','destination','disabled','limit','cumulative','approval_denied'));

CREATE TABLE st.managed_links (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  recipient_id uuid NOT NULL REFERENCES st.principals(id),
  object_version text NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (workspace_id,id),
  FOREIGN KEY (workspace_id,id) REFERENCES st.protection_decisions(workspace_id,request_id) ON DELETE CASCADE
);

CREATE TABLE st.transfer_approvals (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  key_id uuid NOT NULL,
  requester_id uuid REFERENCES st.principals(id),
  reviewer_id uuid REFERENCES st.principals(id),
  intent jsonb NOT NULL,
  fingerprint text NOT NULL,
  revision integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','denied','consumed')),
  PRIMARY KEY (workspace_id,id),
  CHECK (reviewer_id IS NULL OR reviewer_id IS DISTINCT FROM requester_id),
  FOREIGN KEY (workspace_id,key_id) REFERENCES st.keys(workspace_id,id)
);
ALTER TABLE st.protection_policy
  ADD COLUMN approval_threshold integer NOT NULL DEFAULT 0 CHECK (approval_threshold BETWEEN 0 AND 1000000),
  ADD COLUMN cumulative_limit integer NOT NULL DEFAULT 0 CHECK (cumulative_limit BETWEEN 0 AND 10000000);
CREATE INDEX protection_actor_budget ON st.protection_decisions(workspace_id,actor_id,decided_at)
  INCLUDE (record_count) WHERE outcome='allowed';
CREATE INDEX transfer_review_recent ON st.transfer_approvals(workspace_id,created_at DESC,id DESC);

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['managed_links','transfer_approvals']
  LOOP
    EXECUTE format('ALTER TABLE st.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE st.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY workspace ON st.%I TO shadowtrace_app USING (workspace_id=st.tenant()) WITH CHECK (workspace_id=st.tenant())',name);
    EXECUTE format('CREATE POLICY maintenance ON st.%I TO %I USING (true) WITH CHECK (true)',name,current_user);
    EXECUTE format('GRANT SELECT, INSERT ON st.%I TO shadowtrace_app',name);
  END LOOP;
END $$;
GRANT UPDATE(revoked_at) ON st.managed_links TO shadowtrace_app;
GRANT UPDATE(state,reviewer_id) ON st.transfer_approvals TO shadowtrace_app;
GRANT UPDATE(approval_threshold,cumulative_limit) ON st.protection_policy TO shadowtrace_app;

CREATE FUNCTION st.protection_member(p_workspace uuid,p_member uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
 SELECT p_workspace=st.tenant() AND EXISTS(
   SELECT 1 FROM st.memberships m WHERE m.workspace_id=p_workspace AND m.principal_id=p_member
 ) AND EXISTS(
   SELECT 1 FROM st.keys k WHERE k.workspace_id=p_workspace AND k.purpose='protection'
     AND k.revoked_at IS NULL AND k.digest=nullif(current_setting('st.key_digest',true),'')
 )
$$;
REVOKE ALL ON FUNCTION st.protection_member(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION st.protection_member(uuid,uuid) TO shadowtrace_app;

CREATE FUNCTION st.protection_slug(p_workspace uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT w.slug FROM st.workspaces w JOIN st.keys k ON k.workspace_id=w.id
  WHERE w.id=p_workspace AND w.id=st.tenant() AND k.purpose='protection' AND k.revoked_at IS NULL
    AND k.digest=nullif(current_setting('st.key_digest',true),'')
$$;
REVOKE ALL ON FUNCTION st.protection_slug(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION st.protection_slug(uuid) TO shadowtrace_app;

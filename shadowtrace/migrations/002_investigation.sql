ALTER TABLE st.cases ADD COLUMN assignee_id uuid;
ALTER TABLE st.cases ADD CONSTRAINT case_assignee_membership
  FOREIGN KEY (workspace_id, assignee_id) REFERENCES st.memberships(workspace_id, principal_id)
  ON DELETE SET NULL (assignee_id);
CREATE INDEX cases_assignee ON st.cases(workspace_id,assignee_id,latest_at DESC);
GRANT UPDATE(assignee_id) ON st.cases TO shadowtrace_app;

ALTER TABLE st.reviews ADD COLUMN disposition text CHECK (
  disposition IN ('approved','policy_violation','false_positive','other')
  AND status IN ('resolved','dismissed')
);
CREATE INDEX events_actor_recent ON st.events(workspace_id,actor_id,received_at DESC,event_id DESC);
CREATE INDEX events_source_recent ON st.events(workspace_id,key_id,received_at DESC);

CREATE FUNCTION st.case_members() RETURNS TABLE (id uuid,name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT p.id,p.name FROM st.memberships m JOIN st.principals p ON p.id=m.principal_id
  WHERE m.workspace_id=st.tenant() AND EXISTS (
    SELECT 1 FROM st.memberships self WHERE self.workspace_id=m.workspace_id
      AND self.principal_id=st.principal()
  )
$$;
REVOKE ALL ON FUNCTION st.case_members() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION st.case_members() TO shadowtrace_app;

CREATE TABLE st.ingest_health (
  workspace_id uuid NOT NULL,
  key_id uuid NOT NULL,
  day date NOT NULL,
  accepted bigint NOT NULL DEFAULT 0,
  replayed bigint NOT NULL DEFAULT 0,
  rejected bigint NOT NULL DEFAULT 0,
  throttled bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (workspace_id,key_id,day),
  FOREIGN KEY (workspace_id,key_id) REFERENCES st.keys(workspace_id,id) ON DELETE CASCADE
);
ALTER TABLE st.ingest_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE st.ingest_health FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace ON st.ingest_health TO shadowtrace_app
  USING (workspace_id=st.tenant()) WITH CHECK (workspace_id=st.tenant());
DO $$
BEGIN
  EXECUTE format('CREATE POLICY maintenance ON st.ingest_health TO %I USING (true) WITH CHECK (true)', current_user);
END $$;
GRANT SELECT, INSERT ON st.ingest_health TO shadowtrace_app;
GRANT UPDATE(accepted,replayed,rejected,throttled) ON st.ingest_health TO shadowtrace_app;

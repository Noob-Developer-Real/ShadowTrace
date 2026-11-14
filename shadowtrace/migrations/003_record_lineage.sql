ALTER TABLE st.keys ADD COLUMN purpose text NOT NULL DEFAULT 'events'
  CHECK (purpose IN ('events','receipts'));

CREATE TABLE st.event_manifests (
  workspace_id uuid NOT NULL,
  event_id text NOT NULL,
  token_set uuid NOT NULL,
  fingerprints text[] NOT NULL CHECK (cardinality(fingerprints) BETWEEN 1 AND 1000),
  PRIMARY KEY (workspace_id,event_id),
  FOREIGN KEY (workspace_id,event_id) REFERENCES st.events(workspace_id,event_id) ON DELETE CASCADE
);

CREATE TABLE st.destination_receipts (
  workspace_id uuid NOT NULL,
  receipt_id text NOT NULL,
  export_id text NOT NULL,
  key_id uuid NOT NULL,
  destination text NOT NULL,
  fingerprints text[] NOT NULL CHECK (cardinality(fingerprints) BETWEEN 1 AND 1000),
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  fingerprint text NOT NULL,
  PRIMARY KEY (workspace_id,receipt_id),
  FOREIGN KEY (workspace_id,export_id) REFERENCES st.event_manifests(workspace_id,event_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id,key_id) REFERENCES st.keys(workspace_id,id)
);
CREATE INDEX receipts_export ON st.destination_receipts(workspace_id, export_id, occurred_at, receipt_id);
CREATE INDEX receipts_source ON st.destination_receipts(workspace_id, key_id, received_at DESC);

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['event_manifests','destination_receipts']
  LOOP
    EXECUTE format('ALTER TABLE st.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE st.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY workspace ON st.%I TO shadowtrace_app USING (workspace_id=st.tenant()) WITH CHECK (workspace_id=st.tenant())',name);
    EXECUTE format('CREATE POLICY maintenance ON st.%I TO %I USING (true) WITH CHECK (true)',name,current_user);
    EXECUTE format('GRANT SELECT, INSERT ON st.%I TO shadowtrace_app',name);
  END LOOP;
END $$;

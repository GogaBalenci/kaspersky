CREATE TABLE threats (
    md5 CHAR(32) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    description TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT threats_md5_format CHECK (md5 ~ '^[a-f0-9]{32}$'),
    CONSTRAINT threats_type_valid CHECK (type IN ('trojan', 'ransomware', 'worm', 'adware', 'spyware', 'other')),
    CONSTRAINT threats_severity_valid CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT threats_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT threats_tags_limit CHECK (cardinality(tags) <= 20),
    CONSTRAINT threats_seen_dates_valid CHECK (
        first_seen_at IS NULL
        OR last_seen_at IS NULL
        OR first_seen_at <= last_seen_at
    )
);

CREATE INDEX threats_severity_idx ON threats (severity);
CREATE INDEX threats_type_idx ON threats (type);
CREATE INDEX threats_updated_at_idx ON threats (updated_at DESC);
CREATE INDEX threats_tags_gin_idx ON threats USING GIN (tags);

CREATE OR REPLACE FUNCTION set_threat_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER threats_set_updated_at
BEFORE UPDATE ON threats
FOR EACH ROW
EXECUTE FUNCTION set_threat_updated_at();

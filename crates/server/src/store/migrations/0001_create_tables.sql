-- What a number is: a collector reports metrics, and each metric on each agent, for
-- each thing it describes, is a series. A new collector only ever adds rows here.
CREATE TABLE collectors (
    id   INTEGER NOT NULL,
    name VARCHAR NOT NULL
);

CREATE TABLE metrics (
    id           INTEGER NOT NULL,
    collector_id INTEGER NOT NULL,
    name         VARCHAR NOT NULL,
    data_type    VARCHAR NOT NULL
);

CREATE TABLE agents (
    id       INTEGER NOT NULL,
    agent_id VARCHAR NOT NULL
);

CREATE TABLE series (
    id        BIGINT  NOT NULL,
    metric_id INTEGER NOT NULL,
    agent     INTEGER NOT NULL
);

-- What a series describes, like a disk's mount point. Most have one or none.
CREATE TABLE series_labels (
    series_id BIGINT  NOT NULL,
    name      VARCHAR NOT NULL,
    value     VARCHAR NOT NULL
);

-- New numbers land here in the order they arrive.
CREATE TABLE samples_recent (
    time      TIMESTAMP NOT NULL,
    metric_id INTEGER   NOT NULL,
    series_id BIGINT    NOT NULL,
    value     DOUBLE    NOT NULL
);

-- Finished hours, sorted so that a query only reads the blocks it needs. Bools are
-- stored as 0 or 1, and a metric's `data_type` says what a number really is.
CREATE TABLE samples (
    time      TIMESTAMP NOT NULL,
    metric_id INTEGER   NOT NULL,
    series_id BIGINT    NOT NULL,
    value     DOUBLE    NOT NULL
);

CREATE VIEW all_samples AS
    SELECT * FROM samples UNION ALL SELECT * FROM samples_recent;

-- Text, only when it changes. An empty value means it stopped being reported.
CREATE TABLE texts (
    time      TIMESTAMP NOT NULL,
    series_id BIGINT    NOT NULL,
    value     VARCHAR
);

-- What a number is: a collector reports metrics, and each metric on each host, for
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

-- A host is known here by a number, to keep series small, and by the main
-- database's ID, as everywhere else.
CREATE TABLE hosts (
    number  INTEGER NOT NULL,
    host_id VARCHAR NOT NULL
);

CREATE TABLE series (
    id          BIGINT  NOT NULL,
    metric_id   INTEGER NOT NULL,
    host_number INTEGER NOT NULL
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

-- What each chart in the catalog showed, 5 minutes and an hour at a time, so long
-- ranges are quick and outlast the samples. Each keeps the lowest and highest value,
-- so spikes survive, and the total and how many there were, so averages stay exact
-- however many are combined. `metric` is the catalog's name, like cpu.usage, and
-- `series` is the name of the line, like a disk's mount point.
CREATE TABLE rollups_five_minute (
    metric      VARCHAR   NOT NULL,
    host_number INTEGER   NOT NULL,
    series      VARCHAR   NOT NULL,
    time        TIMESTAMP NOT NULL,
    low         DOUBLE    NOT NULL,
    high        DOUBLE    NOT NULL,
    summed      DOUBLE    NOT NULL,
    samples     BIGINT    NOT NULL
);

CREATE TABLE rollups_hour (
    metric      VARCHAR   NOT NULL,
    host_number INTEGER   NOT NULL,
    series      VARCHAR   NOT NULL,
    time        TIMESTAMP NOT NULL,
    low         DOUBLE    NOT NULL,
    high        DOUBLE    NOT NULL,
    summed      DOUBLE    NOT NULL,
    samples     BIGINT    NOT NULL
);

-- How far each metric is rolled up: every hour before this, in milliseconds.
CREATE TABLE rollup_progress (
    metric        VARCHAR NOT NULL,
    done_until_ms BIGINT  NOT NULL
);

-- Hours that got samples after they were rolled up, to be rolled up again.
CREATE TABLE rollup_redo (
    hour_ms BIGINT NOT NULL
);

-- What each chart in the catalog showed, a minute and an hour at a time, so long ranges
-- are quick and outlast the samples. Each keeps the lowest and highest value, so spikes
-- survive, and the total and how many there were, so averages stay exact however many
-- are combined. `metric` is the catalog's name, like cpu.usage, and `series` is the
-- name of the line, like a disk's mount point.
CREATE TABLE rollups_minute (
    metric  VARCHAR   NOT NULL,
    agent   INTEGER   NOT NULL,
    series  VARCHAR   NOT NULL,
    time    TIMESTAMP NOT NULL,
    low     DOUBLE    NOT NULL,
    high    DOUBLE    NOT NULL,
    summed  DOUBLE    NOT NULL,
    samples BIGINT    NOT NULL
);

CREATE TABLE rollups_hour (
    metric  VARCHAR   NOT NULL,
    agent   INTEGER   NOT NULL,
    series  VARCHAR   NOT NULL,
    time    TIMESTAMP NOT NULL,
    low     DOUBLE    NOT NULL,
    high    DOUBLE    NOT NULL,
    summed  DOUBLE    NOT NULL,
    samples BIGINT    NOT NULL
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

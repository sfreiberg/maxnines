-- Rollups of 5 minutes instead of 1, which are as fine as a chart of 20 hours or more
-- can show and take a fifth of the space. Made from the minutes already rolled up, which
-- gives exactly what rolling up the samples again would.
CREATE TABLE rollups_five_minute (
    metric  VARCHAR   NOT NULL,
    agent   INTEGER   NOT NULL,
    series  VARCHAR   NOT NULL,
    time    TIMESTAMP NOT NULL,
    low     DOUBLE    NOT NULL,
    high    DOUBLE    NOT NULL,
    summed  DOUBLE    NOT NULL,
    samples BIGINT    NOT NULL
);

INSERT INTO rollups_five_minute
SELECT metric, agent, series, time_bucket(INTERVAL 5 MINUTE, time),
       min(low), max(high), sum(summed), sum(samples)::BIGINT
FROM rollups_minute
GROUP BY metric, agent, series, time_bucket(INTERVAL 5 MINUTE, time);

DROP TABLE rollups_minute;

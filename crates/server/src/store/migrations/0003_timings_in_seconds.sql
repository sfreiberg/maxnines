-- Timings were milliseconds, named so, and are now seconds: checks' stages and
-- pings, disks' latency, and databases' latencies and waits. Each stored number is
-- made seconds, and each metric takes its new name. The catalog's own names don't
-- change, so only the values of what's rolled up do.
CREATE TEMPORARY TABLE timings (collector VARCHAR, old VARCHAR, new VARCHAR);
INSERT INTO timings VALUES
    ('checks', 'response_ms', 'response_secs'),
    ('checks', 'dns_ms', 'dns_secs'),
    ('checks', 'connect_ms', 'connect_secs'),
    ('checks', 'tls_ms', 'tls_secs'),
    ('checks', 'first_byte_ms', 'first_byte_secs'),
    ('checks', 'download_ms', 'download_secs'),
    ('checks', 'rtt_min_ms', 'rtt_min_secs'),
    ('checks', 'rtt_max_ms', 'rtt_max_secs'),
    ('checks', 'rtt_stddev_ms', 'rtt_stddev_secs'),
    ('disk', 'read_latency_ms', 'read_latency_secs'),
    ('disk', 'write_latency_ms', 'write_latency_secs'),
    ('databases', 'mongodb.reads_latency_ms', 'mongodb.reads_latency_secs'),
    ('databases', 'mongodb.writes_latency_ms', 'mongodb.writes_latency_secs'),
    ('databases', 'clickhouse.latency_ms', 'clickhouse.latency_secs'),
    ('databases', 'clickhouse.select_latency_ms', 'clickhouse.select_latency_secs'),
    ('databases', 'clickhouse.insert_latency_ms', 'clickhouse.insert_latency_secs'),
    ('databases', 'clickhouse.keeper_latency_ms', 'clickhouse.keeper_latency_secs'),
    ('databases', 'clickhouse.overcommit_wait_ms', 'clickhouse.overcommit_wait_secs'),
    ('databases', 'clickhouse.insert_delay_ms', 'clickhouse.insert_delay_secs'),
    ('databases', 'clickhouse.p50_ms', 'clickhouse.p50_secs'),
    ('databases', 'clickhouse.p95_ms', 'clickhouse.p95_secs'),
    ('databases', 'clickhouse.p99_ms', 'clickhouse.p99_secs');

CREATE TEMPORARY TABLE renamed AS
    SELECT metrics.id, timings.new
    FROM metrics
    JOIN collectors ON collectors.id = metrics.collector_id
    JOIN timings ON timings.collector = collectors.name AND timings.old = metrics.name;

UPDATE samples SET value = value / 1000 WHERE metric_id IN (SELECT id FROM renamed);
UPDATE samples_recent SET value = value / 1000 WHERE metric_id IN (SELECT id FROM renamed);
UPDATE metrics SET name = renamed.new FROM renamed WHERE metrics.id = renamed.id;

CREATE TEMPORARY TABLE timed_charts (metric VARCHAR);
INSERT INTO timed_charts VALUES
    ('check.response'), ('check.first_byte'), ('check.dns'), ('check.connect'),
    ('check.tls'), ('check.download'), ('disk.read_latency'), ('disk.write_latency'),
    ('mongodb.read_latency'), ('mongodb.write_latency'), ('clickhouse.latency'),
    ('clickhouse.select_latency'), ('clickhouse.insert_latency'), ('clickhouse.insert_delay'),
    ('clickhouse.overcommit_wait'), ('clickhouse.keeper_latency'), ('clickhouse.query_p50'),
    ('clickhouse.query_p95'), ('clickhouse.query_p99');

UPDATE rollups_five_minute
    SET low = low / 1000, high = high / 1000, summed = summed / 1000
    WHERE metric IN (SELECT metric FROM timed_charts);
UPDATE rollups_hour
    SET low = low / 1000, high = high / 1000, summed = summed / 1000
    WHERE metric IN (SELECT metric FROM timed_charts);

DROP TABLE timings;
DROP TABLE renamed;
DROP TABLE timed_charts;

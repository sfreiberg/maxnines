-- PostgreSQL's database stats were kept under `pg`, and are now under `postgres`, as
-- its check is named everywhere else, so `pg.connections` is `postgres.connections`.
UPDATE metrics SET name = 'postgres.' || substr(name, 4)
    WHERE name LIKE 'pg.%'
    AND collector_id IN (SELECT id FROM collectors WHERE name = 'databases');
UPDATE rollups_five_minute SET metric = 'postgres.' || substr(metric, 4)
    WHERE metric LIKE 'pg.%';
UPDATE rollups_hour SET metric = 'postgres.' || substr(metric, 4) WHERE metric LIKE 'pg.%';
UPDATE rollup_progress SET metric = 'postgres.' || substr(metric, 4) WHERE metric LIKE 'pg.%';

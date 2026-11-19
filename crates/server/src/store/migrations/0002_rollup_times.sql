-- How far each metric is rolled up, and the hours to roll up again, are times like
-- everything else here, rather than milliseconds since 1970.
ALTER TABLE rollup_progress ALTER COLUMN done_until_ms TYPE TIMESTAMP USING epoch_ms(done_until_ms);
ALTER TABLE rollup_progress RENAME COLUMN done_until_ms TO done_until;

ALTER TABLE rollup_redo ALTER COLUMN hour_ms TYPE TIMESTAMP USING epoch_ms(hour_ms);
ALTER TABLE rollup_redo RENAME COLUMN hour_ms TO hour;

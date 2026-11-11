-- A host is known here by a number, to keep series small, and by the main
-- database's ID, as everywhere else. The columns say which.
ALTER TABLE hosts RENAME COLUMN id TO number;
ALTER TABLE series RENAME COLUMN host TO host_number;
ALTER TABLE rollups_five_minute RENAME COLUMN host TO host_number;
ALTER TABLE rollups_hour RENAME COLUMN host TO host_number;

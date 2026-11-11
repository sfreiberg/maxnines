-- The computer being watched is a host everywhere, so what said agent says host.
ALTER TABLE agents RENAME TO hosts;
ALTER TABLE hosts RENAME COLUMN agent_id TO host_id;
ALTER TABLE series RENAME COLUMN agent TO host;
ALTER TABLE rollups_five_minute RENAME COLUMN agent TO host;
ALTER TABLE rollups_hour RENAME COLUMN agent TO host;

-- The server's own count of hosts, read from these fields, keeps its history.
UPDATE metrics SET name = replace(name, 'agents_', 'hosts_')
WHERE name IN ('agents_online', 'agents_approved', 'agents_waiting')
  AND collector_id IN (SELECT id FROM collectors WHERE name = 'server');
UPDATE rollups_hour SET metric = 'server.hosts' WHERE metric = 'server.agents';
UPDATE rollups_five_minute SET metric = 'server.hosts' WHERE metric = 'server.agents';
UPDATE rollup_progress SET metric = 'server.hosts' WHERE metric = 'server.agents';

-- What the writer numbers is numbered once, which the database makes sure of rather
-- than the writer alone. Only these small tables have keys: they gain rows only for
-- something new, and DuckDB leaves each key's index on disk until a lookup needs it.
-- The tables of numbers have none, as sorting them is what makes reading them quick.
-- A unique index of a name would stop the table being altered until it was dropped,
-- as DuckDB won't change a table an index depends on, which a key doesn't.
ALTER TABLE collectors ADD PRIMARY KEY (id);
ALTER TABLE metrics ADD PRIMARY KEY (id);
ALTER TABLE hosts ADD PRIMARY KEY (number);
ALTER TABLE series ADD PRIMARY KEY (id);

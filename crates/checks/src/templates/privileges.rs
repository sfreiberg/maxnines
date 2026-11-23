//! What the account a template signs in as may do beyond reading. MaxNines only
//! ever reads, in transactions that can't write, but an account that could do more
//! is one a template's SQL, or anyone who learns its password, could misuse. So
//! it's reported, and an alert says so, though the account is still used: whoever
//! gave it to MaxNines decides what it may do.
//!
//! On PostgreSQL it's one query over the account's role. On MySQL and MariaDB it's
//! the account's grants, as `SHOW GRANTS` lists them, with those of each role it's
//! been given, whether or not the role is in use, as the account could start using
//! it. MySQL lists a role's grants when asked with `USING`; MariaDB only lists those
//! of the role in use, so each is put in use in turn, and the one in use before is
//! put back after, so what templates run is run as before. On ClickHouse it's
//! one query over `system.grants`, for the account and the roles it's been given
//! and those roles' own, which an account that can read `system.*` can see.

use anyhow::{Result, bail};
use maxnines_protocol::CheckKind;

use super::{Cell, Open, Row, STATEMENT_LIMIT, Session};

/// What an account may do beyond reading, each true if it may.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Privileges {
    /// It may do anything: a PostgreSQL superuser, or MySQL's `SUPER` or every
    /// privilege on everything.
    pub superuser: bool,
    /// It may change data or tables: insert, update, delete, create, alter or drop,
    /// anywhere at all.
    pub writes: bool,
    /// It may manage accounts or the server: create accounts or roles, pass on its
    /// own privileges, create databases, replicate, or, on MySQL, shut the server
    /// down or anything named an admin privilege.
    pub manages: bool,
    /// It may read or write the database server's own files, or run programs there.
    pub server_files: bool,
}

impl Privileges {
    /// Whether it may do anything beyond reading.
    pub fn overprivileged(&self) -> bool {
        self.superuser || self.writes || self.manages || self.server_files
    }
}

/// PostgreSQL: the account's own role, and the roles it's a member of. Writing
/// counts in any schema but PostgreSQL's own, by a table's privileges or a column's,
/// as does being able to create a schema or a table.
const POSTGRES: &str = r"SELECT r.rolsuper AS superuser,
       r.rolsuper
         OR EXISTS (SELECT 1 FROM pg_roles g
                    WHERE g.rolname = 'pg_write_all_data'
                      AND pg_has_role(current_user, g.oid, 'MEMBER'))
         OR has_database_privilege(current_database(), 'CREATE')
         OR EXISTS (SELECT 1 FROM pg_namespace n
                    WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%'
                      AND has_schema_privilege(n.oid, 'CREATE'))
         OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
                      AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%'
                      AND (has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
                           OR has_any_column_privilege(c.oid, 'INSERT, UPDATE')))
         AS writes,
       r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication
         OR EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid AND m.admin_option)
         AS manages,
       r.rolsuper
         OR EXISTS (SELECT 1 FROM pg_roles g
                    WHERE g.rolname IN ('pg_read_server_files', 'pg_write_server_files',
                                        'pg_execute_server_program')
                      AND pg_has_role(current_user, g.oid, 'MEMBER'))
         AS server_files
FROM pg_roles r WHERE r.rolname = current_user";

/// MySQL privileges that change data or tables.
const MYSQL_WRITES: &[&str] = &[
    "INSERT",
    "UPDATE",
    "DELETE",
    "DELETE HISTORY",
    "CREATE",
    "DROP",
    "ALTER",
    "INDEX",
    "CREATE VIEW",
    "CREATE ROUTINE",
    "ALTER ROUTINE",
    "TRIGGER",
    "EVENT",
    "CREATE TABLESPACE",
];

/// MySQL privileges that manage accounts or the server, besides any named an admin
/// privilege, such as `SYSTEM_VARIABLES_ADMIN` or MariaDB's `BINLOG ADMIN`.
const MYSQL_MANAGES: &[&str] = &[
    "CREATE USER",
    "CREATE ROLE",
    "DROP ROLE",
    "GRANT OPTION",
    "PROXY",
    "SHUTDOWN",
    "RELOAD",
    "SET USER",
    "SET_USER_ID",
    "SET_ANY_DEFINER",
    "SYSTEM_USER",
];

/// ClickHouse: what the account's grants, and its roles', allow, by kind of
/// privilege. Creating a temporary table isn't counted, as it lasts only as long
/// as its session.
const CLICKHOUSE: &str = r"WITH
  (SELECT groupArray(granted_role_name) FROM system.role_grants
   WHERE user_name = currentUser()) AS given,
  (SELECT groupArray(granted_role_name) FROM system.role_grants
   WHERE has(given, role_name)) AS nested,
  arrayConcat(given, nested, enabledRoles()) AS roles,
  toString(access_type) AS access,
  match(access, '^(CREATE|ALTER|DROP) (USER|ROLE|ROW POLICY|MASKING POLICY|QUOTA|SETTINGS PROFILE|NAMED COLLECTION)$') AS of_access
SELECT
  countIf(access = 'ALL' AND database IS NULL) > 0 AS superuser,
  countIf(access IN ('ALL', 'INSERT', 'ALTER', 'CREATE', 'DROP', 'UNDROP TABLE',
                     'TRUNCATE', 'OPTIMIZE', 'MOVE PARTITION BETWEEN SHARDS',
                     'CREATE DATABASE', 'CREATE TABLE', 'CREATE VIEW',
                     'CREATE DICTIONARY', 'CREATE FUNCTION')
          OR (match(access, '^(ALTER|DROP) ') AND NOT of_access)) > 0 AS writes,
  countIf(grant_option = 1 OR of_access OR startsWith(access, 'SYSTEM')
          OR access IN ('ALL', 'ACCESS MANAGEMENT', 'ROLE ADMIN', 'IMPERSONATE',
                        'SET DEFINER', 'ALLOW SQL SECURITY NONE', 'CREATE TOKEN',
                        'KILL QUERY', 'KILL TRANSACTION', 'NAMED COLLECTION ADMIN')) > 0
    AS manages,
  countIf(access IN ('ALL', 'BACKUP', 'FILE', 'URL', 'REMOTE', 'MONGO', 'REDIS', 'MYSQL',
                     'POSTGRES', 'SQLITE', 'ODBC', 'JDBC', 'HDFS', 'S3', 'HIVE', 'AZURE',
                     'KAFKA', 'NATS', 'RABBITMQ', 'YTSAURUS', 'ARROW FLIGHT', 'BIGQUERY',
                     'ELASTICSEARCH', 'DISK', 'SOURCES', 'READ', 'WRITE')) > 0 AS server_files
FROM system.grants
WHERE is_partial_revoke = 0
  AND (user_name = currentUser() OR has(roles, ifNull(role_name, '')))";

impl Session {
    /// What the account it signs in as may do beyond reading, connecting first if
    /// it has to.
    pub async fn privileges(&mut self) -> Result<Privileges> {
        match self.database.check.kind {
            CheckKind::Postgres | CheckKind::Clickhouse => {
                let sql = match self.database.check.kind {
                    CheckKind::Postgres => POSTGRES,
                    _ => CLICKHOUSE,
                };
                let rows = self.run(sql, STATEMENT_LIMIT).await?;
                // PostgreSQL says true or false, and ClickHouse 1 or 0.
                let flag = |name: &str| {
                    rows.first()
                        .and_then(|row| row.iter().find(|(column, _)| column == name))
                        .is_some_and(|(_, cell)| {
                            matches!(cell, Cell::Bool(true))
                                || matches!(cell, Cell::Number(n) if *n != 0.0)
                        })
                };
                Ok(Privileges {
                    superuser: flag("superuser"),
                    writes: flag("writes"),
                    manages: flag("manages"),
                    server_files: flag("server_files"),
                })
            }
            CheckKind::Mysql => {
                let grants = lines(&self.run("SHOW GRANTS", STATEMENT_LIMIT).await?);
                let roles = roles_in(&grants);
                let mariadb = matches!(self.open, Some(Open::Mysql { mariadb: true, .. }));
                let more = match (roles.is_empty(), mariadb) {
                    (true, _) => Vec::new(),
                    (false, false) => {
                        let ask =
                            format!("SHOW GRANTS FOR CURRENT_USER() USING {}", roles.join(", "));
                        lines(&self.run(&ask, STATEMENT_LIMIT).await?)
                    }
                    (false, true) => self.mariadb_role_grants(roles).await?,
                };
                Ok(mysql_privileges(grants.iter().chain(&more)))
            }
            other => bail!("templates can't read {} yet", other.as_str()),
        }
    }
}

impl Session {
    /// What MariaDB's roles give, each the account is given put in use in turn, with
    /// the role that was in use put back after, whatever happens. MariaDB lists what
    /// roles given to a role give with it, and won't put one of those in use itself.
    async fn mariadb_role_grants(&mut self, roles: Vec<String>) -> Result<Vec<String>> {
        let rows = self
            .run("SELECT CURRENT_ROLE() AS role", STATEMENT_LIMIT)
            .await?;
        let before = match rows.first().and_then(|row| row.first()) {
            Some((_, Cell::Text(role))) => format!("`{}`", role.replace('`', "``")),
            _ => "NONE".to_string(),
        };
        let mut grants = Vec::new();
        let outcome = async {
            for role in &roles {
                self.run(&format!("SET ROLE {role}"), STATEMENT_LIMIT)
                    .await?;
                grants.extend(lines(&self.run("SHOW GRANTS", STATEMENT_LIMIT).await?));
            }
            anyhow::Ok(())
        }
        .await;
        self.run(&format!("SET ROLE {before}"), STATEMENT_LIMIT)
            .await?;
        outcome.map(|()| grants)
    }
}

/// The roles that grants give, as they're named in them.
fn roles_in(grants: &[String]) -> Vec<String> {
    grants
        .iter()
        .filter_map(|line| match grant(line)? {
            Grant::Role { role, .. } => Some(role),
            Grant::Privileges { .. } => None,
        })
        .flat_map(|roles| {
            split_outside_quotes(&roles)
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The text of each row's first column, as `SHOW GRANTS` gives one grant a row.
fn lines(rows: &[Row]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| match row.first() {
            Some((_, Cell::Text(text))) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// One line of `SHOW GRANTS`.
#[derive(Debug, PartialEq)]
enum Grant {
    /// `GRANT SELECT, INSERT ON db.* TO …`: privileges, and what they're on.
    Privileges {
        privileges: Vec<String>,
        on: String,
        passed_on: bool,
    },
    /// `GRANT role TO …`: a role, as it's named.
    Role { role: String, passed_on: bool },
}

/// What one line of `SHOW GRANTS` gives, or `None` for anything else, such as a
/// partial `REVOKE`.
fn grant(line: &str) -> Option<Grant> {
    let rest = line.trim().strip_prefix("GRANT ")?;
    let to = find_outside_quotes(rest, " TO ")?;
    let passed_on = rest.ends_with(" WITH GRANT OPTION") || rest.ends_with(" WITH ADMIN OPTION");
    match find_outside_quotes(&rest[..to], " ON ") {
        Some(on) => Some(Grant::Privileges {
            privileges: split_outside_quotes(&rest[..on])
                .into_iter()
                .map(|privilege| {
                    // A column privilege, `UPDATE (a, b)`, is still that privilege.
                    let name = privilege.split('(').next().unwrap_or_default();
                    name.trim().to_uppercase()
                })
                .collect(),
            on: rest[on + " ON ".len()..to].trim().to_string(),
            passed_on,
        }),
        None => Some(Grant::Role {
            role: rest[..to].trim().to_string(),
            passed_on,
        }),
    }
}

/// What a MySQL or MariaDB account's grants let it do beyond reading.
fn mysql_privileges<'a>(grants: impl IntoIterator<Item = &'a String>) -> Privileges {
    let mut found = Privileges::default();
    for line in grants {
        match grant(line) {
            Some(Grant::Privileges {
                privileges,
                on,
                passed_on,
            }) => {
                let everywhere = on == "*.*";
                found.manages |= passed_on;
                for privilege in privileges {
                    let privilege = privilege.as_str();
                    let all = matches!(privilege, "ALL" | "ALL PRIVILEGES");
                    found.superuser |= privilege == "SUPER" || (all && everywhere);
                    found.writes |= all || MYSQL_WRITES.contains(&privilege);
                    found.manages |= (all && everywhere)
                        || privilege == "SUPER"
                        || MYSQL_MANAGES.contains(&privilege)
                        || privilege.ends_with("_ADMIN")
                        || privilege.ends_with(" ADMIN");
                    found.server_files |= privilege == "FILE" || (all && everywhere);
                }
            }
            Some(Grant::Role { passed_on, .. }) => found.manages |= passed_on,
            None => {}
        }
    }
    found
}

/// Where `needle` first is in `text`, outside backticks, quotes and brackets.
fn find_outside_quotes(text: &str, needle: &str) -> Option<usize> {
    let mut quote = None;
    let mut depth = 0_u32;
    for (at, character) in text.char_indices() {
        match (quote, character) {
            (Some(open), _) if character == open => quote = None,
            (Some(_), _) => {}
            (None, '`' | '\'' | '"') => quote = Some(character),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.saturating_sub(1),
            (None, _) if depth == 0 && text[at..].starts_with(needle) => return Some(at),
            (None, _) => {}
        }
    }
    None
}

/// `text` split at each comma outside backticks, quotes and brackets.
fn split_outside_quotes(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(at) = find_outside_quotes(rest, ",") {
        parts.push(rest[..at].trim());
        rest = &rest[at + 1..];
    }
    parts.push(rest.trim());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(grants: &[&str]) -> Privileges {
        let grants: Vec<String> = grants.iter().map(|line| line.to_string()).collect();
        mysql_privileges(&grants)
    }

    #[test]
    fn the_roles_grants_give_are_each_named() {
        let grants = [
            "GRANT `a`@`%`,`b, c`@`%` TO `mx`@`%`".to_string(),
            "GRANT `d` TO `mx`@`%`".to_string(),
            "GRANT SELECT ON *.* TO `mx`@`%`".to_string(),
        ];
        assert_eq!(roles_in(&grants), ["`a`@`%`", "`b, c`@`%`", "`d`"]);
    }

    #[test]
    fn grant_lines_are_read_as_mysql_and_mariadb_write_them() {
        assert_eq!(
            grant("GRANT SELECT, UPDATE (`a`, `b`) ON `shop`.`orders` TO `mx`@`%`"),
            Some(Grant::Privileges {
                privileges: vec!["SELECT".to_string(), "UPDATE".to_string()],
                on: "`shop`.`orders`".to_string(),
                passed_on: false,
            })
        );
        assert_eq!(
            grant("GRANT `writer`@`%`,`other`@`%` TO `mx`@`127.0.0.1` WITH ADMIN OPTION"),
            Some(Grant::Role {
                role: "`writer`@`%`,`other`@`%`".to_string(),
                passed_on: true,
            })
        );
        // MariaDB adds the password, and names in backticks may hold anything.
        assert_eq!(
            grant("GRANT USAGE ON *.* TO `a TO b`@`localhost` IDENTIFIED BY PASSWORD '*AB'"),
            Some(Grant::Privileges {
                privileges: vec!["USAGE".to_string()],
                on: "*.*".to_string(),
                passed_on: false,
            })
        );
        assert_eq!(grant("REVOKE INSERT ON `mysql`.* FROM `mx`@`%`"), None);
    }

    #[test]
    fn an_account_that_only_reads_and_watches_can_do_nothing_more() {
        let found = of(&[
            "GRANT PROCESS, REPLICATION CLIENT ON *.* TO `mx`@`127.0.0.1`",
            "GRANT SELECT ON `performance_schema`.* TO `mx`@`127.0.0.1`",
            "GRANT SELECT, SHOW VIEW ON `shop`.* TO `mx`@`127.0.0.1`",
            "GRANT BINLOG MONITOR, REPLICA MONITOR ON *.* TO `mx`@`127.0.0.1`",
        ]);
        assert_eq!(found, Privileges::default());
        assert!(!found.overprivileged());
    }

    #[test]
    fn each_kind_of_privilege_beyond_reading_is_found() {
        let writes = of(&["GRANT UPDATE (`note`) ON `shop`.`orders` TO `mx`@`%`"]);
        assert!(writes.writes && !writes.manages && writes.overprivileged());
        let all_of_one = of(&["GRANT ALL PRIVILEGES ON `shop`.* TO `mx`@`%`"]);
        assert!(all_of_one.writes && !all_of_one.superuser && !all_of_one.server_files);
        let files = of(&["GRANT FILE ON *.* TO `mx`@`%`"]);
        assert!(files.server_files && !files.writes);
        let passes_on = of(&["GRANT SELECT ON `shop`.* TO `mx`@`%` WITH GRANT OPTION"]);
        assert!(passes_on.manages && !passes_on.writes);
        let admin = of(&["GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO `mx`@`%`"]);
        assert!(admin.manages);
        let maria_admin = of(&["GRANT CONNECTION ADMIN ON *.* TO `mx`@`%`"]);
        assert!(maria_admin.manages);
        let root = of(&["GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION"]);
        assert_eq!(
            root,
            Privileges {
                superuser: true,
                writes: true,
                manages: true,
                server_files: true,
            }
        );
        let role_admin = of(&["GRANT `writer`@`%` TO `mx`@`%` WITH ADMIN OPTION"]);
        assert!(role_admin.manages);
    }

    /// A throwaway server the tests may make accounts on, from
    /// `MAXNINES_TEST_CHECK_POSTGRES` or `_MYSQL`, as `host:port username`, with
    /// what's needed to sign in to it as `username`.
    fn server(variable: &str) -> Option<(String, String)> {
        let value = std::env::var(variable).ok()?;
        let mut words = value.split_whitespace();
        Some((words.next()?.to_string(), words.next()?.to_string()))
    }

    fn session(kind: CheckKind, target: &str, username: &str) -> Session {
        Session::new(crate::databases::Database {
            check: maxnines_protocol::Check::new("real", kind, target),
            credentials: crate::sign_in::Credentials {
                username: Some(username.to_string()),
                password: None,
                private_key: None,
            },
        })
    }

    #[tokio::test]
    async fn a_real_postgres_account_is_found_to_read_or_write() {
        let Some((target, admin)) = server("MAXNINES_TEST_CHECK_POSTGRES") else {
            return;
        };
        let (host, port) = target.split_once(':').unwrap();
        let (client, connection) = tokio_postgres::connect(
            &format!("host={host} port={port} user={admin} dbname=postgres"),
            tokio_postgres::NoTls,
        )
        .await
        .unwrap();
        tokio::spawn(connection);
        let name = format!("maxnines_privileges_{}", std::process::id());
        client
            .batch_execute(&format!(
                "DROP TABLE IF EXISTS {name}; DROP ROLE IF EXISTS {name}; \
                 CREATE ROLE {name} LOGIN; GRANT pg_monitor TO {name}; \
                 CREATE TABLE {name} (a int, b int); GRANT SELECT ON {name} TO {name}"
            ))
            .await
            .unwrap();

        let mut reads = session(CheckKind::Postgres, &target, &name);
        assert_eq!(reads.privileges().await.unwrap(), Privileges::default());

        client
            .batch_execute(&format!("GRANT UPDATE (b) ON {name} TO {name}"))
            .await
            .unwrap();
        let mut writes = session(CheckKind::Postgres, &target, &name);
        let found = writes.privileges().await.unwrap();
        assert!(
            found.writes && !found.superuser && !found.manages,
            "{found:?}"
        );

        let mut superuser = session(CheckKind::Postgres, &target, &admin);
        let found = superuser.privileges().await.unwrap();
        assert!(found.superuser && found.server_files, "{found:?}");

        drop((reads, writes));
        client
            .batch_execute(&format!("DROP TABLE {name}; DROP ROLE {name}"))
            .await
            .unwrap();
    }

    /// Runs a statement as the throwaway ClickHouse's own account, as a POST, which
    /// it lets change things.
    async fn clickhouse_admin(target: &str, admin: &str, sql: &str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(target).await.unwrap();
        let request = format!(
            "POST /?user={admin} HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{sql}",
            sql.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{sql}: {answer}");
    }

    #[tokio::test]
    async fn a_real_clickhouse_account_is_found_to_write_through_its_roles() {
        let Some((target, admin)) = server("MAXNINES_TEST_CHECK_CLICKHOUSE") else {
            return;
        };
        let name = format!("maxnines_privileges_{}", std::process::id());
        for statement in [
            format!("DROP USER IF EXISTS {name}"),
            format!("DROP ROLE IF EXISTS {name}_role"),
            format!("CREATE USER {name} IDENTIFIED WITH no_password"),
            format!("GRANT SELECT ON system.* TO {name}"),
            format!("CREATE ROLE {name}_role"),
        ] {
            clickhouse_admin(&target, &admin, &statement).await;
        }
        let mut reads = session(CheckKind::Clickhouse, &target, &name);
        assert_eq!(reads.privileges().await.unwrap(), Privileges::default());

        for statement in [
            format!("GRANT INSERT ON default.* TO {name}_role"),
            format!("GRANT {name}_role TO {name}"),
        ] {
            clickhouse_admin(&target, &admin, &statement).await;
        }
        let mut writes = session(CheckKind::Clickhouse, &target, &name);
        let found = writes.privileges().await.unwrap();
        assert!(
            found.writes && !found.manages && !found.server_files,
            "{found:?}"
        );

        // The server's own account, which can do anything.
        let mut everything = session(CheckKind::Clickhouse, &target, &admin);
        let found = everything.privileges().await.unwrap();
        assert!(
            found.writes && found.manages && found.server_files,
            "{found:?}"
        );

        for statement in [
            format!("DROP USER {name}"),
            format!("DROP ROLE {name}_role"),
        ] {
            clickhouse_admin(&target, &admin, &statement).await;
        }
    }

    #[tokio::test]
    async fn a_real_mysql_account_is_found_to_write_through_roles_it_isnt_using() {
        use mysql_async::prelude::Queryable;
        let Some((target, admin)) = server("MAXNINES_TEST_CHECK_MYSQL") else {
            return;
        };
        let mut connection = mysql_async::Conn::from_url(format!("mysql://{admin}@{target}/"))
            .await
            .unwrap();
        let name = format!("maxnines_privileges_{}", std::process::id());
        let account = format!("'{name}'@'%'");
        let role = format!("'{name}_role'");
        for statement in [
            format!("DROP USER IF EXISTS {account}"),
            format!("DROP ROLE IF EXISTS {role}"),
            format!("CREATE USER {account} IDENTIFIED BY ''"),
            format!("GRANT PROCESS, REPLICATION CLIENT ON *.* TO {account}"),
            format!("GRANT SELECT ON performance_schema.* TO {account}"),
        ] {
            connection.query_drop(statement).await.unwrap();
        }

        let mut reads = session(CheckKind::Mysql, &target, &name);
        assert_eq!(reads.privileges().await.unwrap(), Privileges::default());

        // A role it's been given but isn't using still counts, and so does one given
        // to that role, which MariaDB won't put in use on its own.
        let inner = format!("'{name}_inner'");
        for statement in [
            format!("DROP ROLE IF EXISTS {inner}"),
            format!("CREATE ROLE {role}"),
            format!("CREATE ROLE {inner}"),
            format!("GRANT INSERT ON maxnines_nowhere.* TO {inner}"),
            format!("GRANT {inner} TO {role}"),
            format!("GRANT {role} TO {account}"),
        ] {
            connection.query_drop(statement).await.unwrap();
        }
        let mut writes = session(CheckKind::Mysql, &target, &name);
        let found = writes.privileges().await.unwrap();
        assert!(
            found.writes && !found.superuser && !found.manages,
            "{found:?}"
        );

        let mut root = session(CheckKind::Mysql, &target, &admin);
        let found = root.privileges().await.unwrap();
        assert!(
            found.superuser && found.manages && found.server_files,
            "{found:?}"
        );

        drop((reads, writes));
        for statement in [
            format!("DROP USER {account}"),
            format!("DROP ROLE {role}"),
            format!("DROP ROLE {inner}"),
        ] {
            connection.query_drop(statement).await.unwrap();
        }
    }
}

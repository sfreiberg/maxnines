# Web servers

Agents can read Apache's, nginx's and PHP-FPM's own status pages, which give
requests per second, how busy the workers are and more from a single request.
Turn on the `apache`, `nginx` or `php_fpm` collector in a config rule. Each reads
the usual address on the machine itself unless the rule lists others, such as one
page for each PHP-FPM pool.

| Collector | Usual address | What the server needs |
| --- | --- | --- |
| `apache` | `http://localhost/server-status?auto` | `mod_status` enabled. Debian and Ubuntu do this already |
| `nginx` | `http://localhost/nginx_status` | A `location /nginx_status { stub_status; allow 127.0.0.1; allow ::1; deny all; }` block |
| `php_fpm` | `http://localhost/status` | `pm.status_path = /status` in the pool, passed through by the web server |

Keep these pages limited to the machine itself, as Apache's does by default.
Addresses with a username or password in them aren't accepted, so they never show
up on the rules pages.

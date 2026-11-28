# nginx

The `nginx` collector reads nginx's own status page, `stub_status`, which gives its
connections and requests from a single request.

## Turning it on

1. **On the web server**, add a status page, limited to the host itself:

   ```nginx
   location /nginx_status {
       stub_status;
       allow 127.0.0.1;
       allow ::1;
       deny all;
   }
   ```

2. **In MaxNines**, turn on `nginx` in a config rule, under **Collectors**. It reads
   `http://localhost/nginx_status` unless the rule lists other pages under **nginx
   status pages**, one to a line, which also turns it on.

Addresses with a username or password in them aren't accepted, so they never show up
on the rules pages. The agent reads each page every sample, and gives up on one after
10 seconds.

## What's reported

Each metric has a series for each page, named by its address, such as
`http://localhost/nginx_status`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `nginx.up` | 1 or 0 | Each page | Whether the status page answered |
| `nginx.connections` | Number | Each page | Open client connections |
| `nginx.requests` | A second | Each page | Requests served |
| `nginx.accepted` | A second | Each page | Connections accepted |
| `nginx.dropped` | A second | Each page | Connections accepted but never handled, usually because it ran out of worker connections |
| `nginx.reading` | Number | Each page | Connections whose request it's reading |
| `nginx.writing` | Number | Each page | Connections it's answering |
| `nginx.waiting` | Number | Each page | Idle connections kept open for the client's next request |

Running totals are turned into rates between one read and the next, so a page that
stops answering starts afresh when it's back, rather than counting the gap as one
burst.

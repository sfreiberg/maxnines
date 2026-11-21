# Filters API

Filters find hosts the same way as the box on the Hosts page. Separate terms with
spaces, and every term has to match. Remember to URL-encode them, so `os=linux`
becomes `os%3Dlinux`. With curl, `-G --data-urlencode` does this for you.

| Filter | Finds |
| --- | --- |
| `web` | Hostnames containing "web" |
| `hostname=web*` | Hostnames starting with "web" |
| `id=3f2a1c9d*` | The host whose ID starts like that, as hostnames needn't be unique |
| `os=linux` | That operating system family. `os` is short for `os.family` |
| `networking.addresses=10.0.*` | Any of the host's IP addresses. Loopback and link-local addresses aren't listed |
| `networking.fqdn=*.leeds.example.com` | The host's fully qualified name, as its resolver gives it. `networking.hostname` is the short name and `networking.domain` the rest |
| `os!=windows` | Everything else, including hosts that haven't said |
| `cpu.logical_cores=8` | Any fact by its full name |
| `custom.tags=eu` | A list containing that value |
| `os.long_version="Ubuntu 24*"` | A value with spaces, in double quotes |
| `os=linux custom.role=web` | Hosts matching both |

Values ignore case, and can use `*` for anything and `?` for one character. Facts from
an agent's own config are under `custom.`, so `role` in its config is `custom.role`.

```sh
curl -G -H "Authorization: Bearer $MAXNINES_API_KEY" \
  --data-urlencode 'q=os=linux hostname=web*' \
  "$MAXNINES_URL/api/v1/hosts"
```

A filter that can't be read gets a `400` saying why.

## Get filter suggestions

`GET /api/v1/hosts/filter-options`

What the filter box offers for the word being typed: fact names, or values once there's
an `=`. Put `text` in place of the word.

| Parameter | Description |
| --- | --- |
| `term` | The word being typed |

```sh
curl -G -H "Authorization: Bearer $MAXNINES_API_KEY" \
  --data-urlencode 'term=os=' \
  "$MAXNINES_URL/api/v1/hosts/filter-options"
```

```json
[
  { "text": "os=linux", "label": "linux" },
  { "text": "os=macos", "label": "macos" }
]
```

# Map API

The map puts hosts in places with location rules. Each rule has a filter, in the
same form as the Hosts list, and a point on the map. Where several rules match a
host, the one with the highest `priority` decides, and of two with the same
priority the older one. A host placed from its own page is a rule whose filter is
`id=` and its host ID, at priority 100.

| Field | Meaning |
|---|---|
| `name` | Required. What the map calls the hosts the rule covers, such as `Leeds office`. |
| `filter` | Which hosts, as in the Hosts list. Leave it out for every host. |
| `place` | Where it is in words, such as `Leeds, England, United Kingdom`. |
| `latitude` | Required. From -90 to 90. |
| `longitude` | Required. From -180 to 180. |
| `priority` | A whole number. Defaults to 0. |

## Get the map

`GET /api/v1/map`

Every place with hosts in it, those most in need of attention first, and the
approved hosts no rule places. A place's `health` is that of its worst host:
`critical`, `warning`, `offline` or `online`.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/map"
```

```json
{
  "sites": [
    {
      "rule_id": 1,
      "name": "Leeds office",
      "place": "Leeds, England, United Kingdom",
      "latitude": 53.79648,
      "longitude": -1.54785,
      "health": "warning",
      "counts": { "critical": 0, "warning": 1, "offline": 0, "online": 3 },
      "hosts": [
        { "id": "8c1f…", "short_id": "8c1f02ab", "hostname": "web-1", "health": "warning" }
      ]
    }
  ],
  "unplaced": []
}
```

## List location rules

`GET /api/v1/location-rules`

Highest priority first.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/location-rules"
```

## Add a location rule

`POST /api/v1/location-rules`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Leeds office", "filter": "networking.addresses=10.1.*", "place": "Leeds, England, United Kingdom", "latitude": 53.79648, "longitude": -1.54785}' \
  "$MAXNINES_URL/api/v1/location-rules"
```

Returns `201` with the new `id`.

## Get a location rule

`GET /api/v1/location-rules/{id}`

```json
{
  "id": 1,
  "name": "Leeds office",
  "filter": "networking.addresses=10.1.*",
  "place": "Leeds, England, United Kingdom",
  "latitude": 53.79648,
  "longitude": -1.54785,
  "priority": 0
}
```

## Update a location rule

`PUT /api/v1/location-rules/{id}`

Takes the same fields as creating one, and returns `204`.

## Delete a location rule

`DELETE /api/v1/location-rules/{id}`

Returns `204`.

## Search for a place

`GET /api/v1/places`

Towns and cities whose name starts with the `q` parameter, up to 10, an exact name first and then
the biggest. Words after a comma narrow it to a region or country, as in
`portland, maine` or `paris, us`. The list is every place with 1,000 people or more,
from [GeoNames](https://www.geonames.org/) under CC BY 4.0, and is built into the
server, so searching never leaves it.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/places?q=portland,%20maine"
```

```json
[
  {
    "name": "Portland",
    "region": "Maine",
    "country": "United States",
    "country_code": "US",
    "latitude": 43.66147,
    "longitude": -70.25533,
    "population": 68408,
    "label": "Portland, Maine, United States"
  }
]
```

## Find the nearest place

`GET /api/v1/places/nearest`

The listed place closest to the point given by the `lat` and `lon` parameters, in the same form as a search result.

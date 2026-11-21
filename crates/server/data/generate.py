"""Builds the map's data from public sources. Run it again to update them.

    python3 crates/server/data/generate.py <folder with the downloads>

The folder needs these, unchanged from where they're published:

- ne_110m_admin_0_countries.geojson, from Natural Earth (public domain):
  https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/
- cities1000.txt (unzipped), admin1CodesASCII.txt and countryInfo.txt, from
  GeoNames (CC BY 4.0): https://download.geonames.org/export/dump/

It writes two files:

- assets/static/map/world.json: country outlines, lines of latitude and longitude,
  and the outline of the globe, already projected, as SVG paths.
- data/places.tsv.gz: every place GeoNames lists with 1,000 people or more, for
  looking up where somewhere is.
"""

import gzip
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORLD_OUT = HERE.parent / "assets" / "static" / "map" / "world.json"
PLACES_OUT = HERE / "places.tsv.gz"

# ---- Equal Earth, an equal-area projection with a rounded outline. The server's
# map.js uses the same numbers to place things on it.
A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2
XMAX = math.pi / (M * A1)
WIDTH = 1000.0
SCALE = WIDTH / (2 * XMAX)

# The map is cut off just past the land at either end. Antarctica is left out, as
# no one runs servers there and it takes a lot of room.
NORTH, SOUTH = 84, -58


def project(lon, lat):
    lam, phi = math.radians(lon), math.radians(lat)
    theta = math.asin(M * math.sin(phi))
    t2, t6 = theta * theta, theta**6
    x = lam * math.cos(theta) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
    y = theta * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
    return (x + XMAX) * SCALE, -y * SCALE


def ring_path(ring):
    points = []
    for lon, lat in ring:
        x, y = project(lon, lat)
        point = (round(x, 1), round(y, 1))
        if not points or points[-1] != point:
            points.append(point)
    if len(points) < 3:
        return ""
    return f"M{points[0][0]:g} {points[0][1]:g}" + "".join(f"L{x:g} {y:g}" for x, y in points[1:]) + "Z"


def line(points):
    return "M" + "L".join(f"{x:.1f} {y:.1f}" for x, y in (project(lon, lat) for lon, lat in points))


def world(source):
    countries = json.loads((source / "ne_110m_admin_0_countries.geojson").read_text())
    land = []
    for feature in countries["features"]:
        if feature["properties"].get("ADM0_A3") == "ATA":
            continue
        geometry = feature["geometry"]
        polygons = geometry["coordinates"]
        if geometry["type"] == "Polygon":
            polygons = [polygons]
        for polygon in polygons:
            land.extend(ring_path(ring) for ring in polygon)

    graticule = [line([(lon, lat) for lon in range(-180, 181, 3)]) for lat in (-30, 0, 30, 60)]
    graticule += [line([(lon, lat) for lat in range(-90, 91, 3)]) for lon in range(-150, 180, 30)]
    sphere = line([(-180, lat) for lat in range(-90, 91, 3)] + [(180, lat) for lat in range(90, -91, -3)]) + "Z"

    top = round(project(0, NORTH)[1] - 4, 1)
    bottom = round(project(0, SOUTH)[1] + 6, 1)
    return {
        "source": "Natural Earth, public domain",
        "width": WIDTH,
        "top": top,
        "height": round(bottom - top, 1),
        "sphere": sphere,
        "graticule": "".join(graticule),
        "land": "".join(land),
    }


def places(source):
    """Countries, then regions, then places, biggest first. A place names its region by
    its line number among the regions, which keeps the file small."""
    countries = {}
    for row in (source / "countryInfo.txt").read_text(encoding="utf-8").splitlines():
        if row and not row.startswith("#"):
            fields = row.split("\t")
            countries[fields[0]] = fields[4]
    region_names = {}
    for row in (source / "admin1CodesASCII.txt").read_text(encoding="utf-8").splitlines():
        code, name, _ascii, _id = row.split("\t")
        region_names[code] = name

    regions, region_index, found = [], {}, []
    for row in (source / "cities1000.txt").read_text(encoding="utf-8").splitlines():
        f = row.split("\t")
        name, ascii_name, country = f[1], f[2], f[8]
        region = region_names.get(f"{country}.{f[10]}", "")
        key = (region, country)
        if key not in region_index:
            region_index[key] = len(regions)
            regions.append(key)
        found.append((name, ascii_name if ascii_name != name else "", region_index[key],
                      round(float(f[4]), 3), round(float(f[5]), 3), int(f[14] or 0)))
    found.sort(key=lambda place: -place[5])

    def clean(text):
        return text.replace("\t", " ").replace("\n", " ")

    lines = ["# Places from GeoNames, CC BY 4.0, https://www.geonames.org/"]
    lines.append(f"countries\t{len(countries)}")
    lines += [f"{code}\t{clean(name)}" for code, name in sorted(countries.items())]
    lines.append(f"regions\t{len(regions)}")
    lines += [f"{clean(region)}\t{country}" for region, country in regions]
    lines.append(f"places\t{len(found)}")
    lines += [f"{clean(n)}\t{clean(a)}\t{r}\t{lat:g}\t{lon:g}\t{p}" for n, a, r, lat, lon, p in found]
    return "\n".join(lines) + "\n", len(found)


def main():
    source = Path(sys.argv[1])
    WORLD_OUT.parent.mkdir(parents=True, exist_ok=True)
    WORLD_OUT.write_text(json.dumps(world(source), separators=(",", ":")))
    text, count = places(source)
    # A fixed time in the header, so the same downloads always give the same file.
    with open(PLACES_OUT, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as out:
        out.write(text.encode("utf-8"))
    print(f"{WORLD_OUT.name}: {WORLD_OUT.stat().st_size / 1e3:.0f} KB")
    print(f"{PLACES_OUT.name}: {count} places, {PLACES_OUT.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()

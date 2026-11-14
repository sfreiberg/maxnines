# Map

The **Map** page shows where hosts are, coloured by how they're doing. A location
rule puts the hosts its filter matches in one place, using the same filter as the
Hosts list. Add rules under **Map > Location rules**:

- One rule for each office or data centre, with a filter such as
  `networking.addresses=10.1.*` or `networking.domain=leeds.example.com`.
- An empty filter covers every host, which suits a single site, or a catch-all at
  a low priority.
- To place a single host, use the link beside **Location** on its page. That makes
  a rule for that host alone, at priority 100, so it outranks the broader rules.

Where several rules match a host, the highest priority decides. Hosts no rule
covers are listed beside the map to be placed.

Find a place by typing its name, with a comma to narrow it down, as in
`portland, maine`, or click the map. The places are every town and city with 1,000
people or more, built into the server, so nothing leaves it to look one up. The map
only shows country outlines, never streets.

Places come from [GeoNames](https://www.geonames.org/) under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), and the outlines from
[Natural Earth](https://www.naturalearthdata.com/), which is in the public domain.

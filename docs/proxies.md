# Proxies

A proxy or load balancer in front of MaxNines passes on each person's address in an
`X-Forwarded-For` header. Anyone can send that header, so MaxNines only believes it
from a proxy it trusts. Until a proxy is trusted, MaxNines sees everyone at the proxy's
address:

- sign-in attempts are limited per address, so one person's wrong passwords can lock
  everyone out for a minute;
- the audit log and **Settings > Users > Sign-ins** can't say where anyone was.

## What's trusted

- A proxy on the same machine, such as nginx or Caddy in front of MaxNines.
- Whatever an admin trusts under **Settings > Proxies**.
- `trusted_proxies` in `server.hcl`, if it's set. It replaces the same-machine default,
  so `trusted_proxies = []` trusts nothing there.

```hcl
trusted_proxies = ["127.0.0.1", "10.0.1.0/24"]
```

## When MaxNines notices a proxy

When someone signed in comes through an address that passes on a forwarded address
but isn't trusted, admins see a notice on every page until they decide. **Settings >
Proxies** shows what's known about each:

- whether your own request just came through it, and the address it gave for you. If
  that's your address, it's a proxy your requests go through;
- who came through it, and how often;
- what kind of address it is: this machine, a private network, a known provider's, or
  somewhere else on the internet.

Then choose:

| Button | What it does |
| --- | --- |
| **Trust** | Believes what it passes on from now on. For a private address, this offers the `/24` around it, as load balancers inside your network move between addresses |
| **Trust only** | Just that one address |
| **Not a proxy** | No more notices. Its header is still never believed |

Each decision is in the audit log, and can be deleted from the same page.

Strangers can't make a notice appear: only requests from someone signed in count.

## Cloud load balancers

| Where | What to trust |
| --- | --- |
| Cloudflare | `cloudflare`, its published ranges, which MaxNines keeps up to date |
| Google Cloud load balancers | `google-cloud`, its load balancer ranges. Google adds its own address after the client's, which MaxNines skips |
| AWS and Azure load balancers | The subnet they're in, such as `10.0.1.0/24`. They connect from addresses there, which change |
| Kubernetes ingress | The cluster's pod network |

The proxy has to send `X-Forwarded-For`. Most do on their own; nginx needs:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

A range wider than `/8`, or `/32` for IPv6, is refused, as anyone in it could claim to
be anyone.

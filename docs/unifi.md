# UniFi

A UniFi check reads a UniFi console, such as a Dream Machine, a Cloud Gateway or a
Cloud Key, through the console's own Network API, and makes each device the console
has adopted a [host without an agent](agentless-hosts.md) of its own: the gateway,
each switch and each access point. A switch that goes offline is then a host going
offline, with the same alert, charts and silences as any other.

It needs UniFi Network 9.1 or later, the oldest version Ubiquiti documents the API
for. The check only ever asks, with GET, and never changes anything on the console.

## Making an API key

The API key has whatever rights the account that makes it has, so make it as an
account that can only look:

1. **On the console**, sign in as an owner or a super admin, open **Admins & Users**,
   and add an admin, such as `maxnines`, with **Restrict to local access only**
   and the role **View Only** for UniFi Network.
2. **Sign in as that admin**, open UniFi Network, then **Settings**, then
   **Control Plane**, then **Integrations**, and choose **Create New API Key**. Name it
   `MaxNines`, and copy the key, which is shown only once.

Where these pages are moves a little between versions of UniFi Network. If
**Integrations** isn't under **Control Plane**, look for it in the menu on the left.

## Adding the check

On the **Checks** page, press **Add check**, and choose **UniFi console** as its kind.

| Setting | What it's for |
| --- | --- |
| **Target** | The console's address, with `https://` and nothing after it, such as `https://192.168.1.1` |
| **API key** | The key from the console. It's kept in the database and never shown again. Or name an environment variable of the server's that holds it, starting with `MAXNINES_SECRET_`, which is read each time the check runs |
| **Site** | To read only one of the console's sites, its name, such as `Default`, or its internal name, such as `default`. Leave it empty for all of them |
| **Don't count a bad certificate as down** | A console comes with a certificate of its own making, which nothing trusts. Tick this unless you've given it one from a certificate authority |
| **Run every** | A minute is plenty |
| **Timeout** | The check asks for each device's statistics in turn, so a console with many devices may need longer than the 10 seconds it has unless you say |

The check itself is about a host as every check is, named after the console's
address unless you choose one. It's up when the console answers and takes the key,
whatever its devices are doing, and down when the console can't be reached, the key
is refused, or the site isn't there. Its chart shows how long reading everything
took.

The key is sent to the console only once its certificate has been checked, or the
box above is ticked, so an address typed wrong never gets it.

## A host for each device

The first time the check finds a device, it makes a host for it, named as the device
is on the console, already approved, as adding the check was the decision to watch
what the console has. A device with no name is named by its model and MAC address.
Each device is known by the console's own ID for it, never its name, so renaming it
on the console keeps its host and history. The host keeps the name it was given, so
rename it in MaxNines too if you like.

A device's host is online while the console says the device is, so the built-in
**Host offline** alert fires for a device that's gone. A device the console stops
listing, such as one removed from it, stays a host, offline, until you delete it.
When the console can't be read, its devices are left as they were, as nothing new is
known of them: the check being down is the alert then. A check that's paused or
deleted stops saying anything of its devices, which are then **Not read**. Deleting a
device's host while the console still has it brings it back on the next run.

Each device's host has facts under `unifi`, which the host's page shows and alert
rules and config rules can use: `unifi.model`, `unifi.mac`, `unifi.ip`,
`unifi.firmware`, `unifi.site`, `unifi.features`, which says what it does, such as
`gateway` or `switching, accessPoint`, and `unifi.id`.

## What's reported

Each device's host has these, each a single series. Statistics are only read from a
device that's online, and anything the console leaves out for a device is left out
here.

| Metric | Unit | What it is |
| --- | --- | --- |
| `unifi.up` | 1 or 0 | Whether the console says the device is online |
| `unifi.uptime` | Seconds | How long since the device started |
| `unifi.cpu` | % | The device's CPU in use |
| `unifi.memory` | % | The device's memory in use |
| `unifi.load` | Number | Its load average, over 1, 5 and 15 minutes |
| `unifi.uplink_received` | Bytes a second | What it's receiving over its connection to the device above it, or for a gateway, the internet |
| `unifi.uplink_sent` | Bytes a second | What it's sending over that connection |
| `unifi.clients` | Number | Wired and wireless clients connected through it. VPN clients aren't through a device, so aren't counted |
| `unifi.firmware_update` | 1 or 0 | Whether newer firmware is waiting to be put on it |

The console gives its uplink's rates as they are now, in bits a second, which are
kept in bytes as every other rate is.

## Alerts

The built-in **UniFi** template has these, on hosts with `unifi` facts. A device
offline is the **Host offline** alert every host has.

| Alert | Warning | Critical |
| --- | --- | --- |
| **UniFi device CPU high** | Over 80% for 10 minutes | Over 95% |
| **UniFi device memory high** | Over 90% for 15 minutes | Over 97% |
| **UniFi firmware update available** | Waiting for a day. Off until turned on | |

A console keeps most of its memory busy on purpose, so only nearly all of it counts.
Change any of these, or turn on the firmware one, on the template's page.

## What it asks the console for

Each run asks, under `https://<console>/proxy/network/integration/v1`:

| Request | For |
| --- | --- |
| `GET /info` | UniFi Network's version |
| `GET /sites` | The sites, by name |
| `GET /sites/{site}/devices` | Each site's devices, a page of 200 at a time |
| `GET /sites/{site}/clients` | Each site's clients, to count them by device |
| `GET /sites/{site}/devices/{device}/statistics/latest` | Each online device's latest statistics |

Every request carries the key in the `X-API-KEY` header, on one connection kept open
between them, except devices' statistics, which are asked for four at a time, each on
a connection of its own, so a console with hundreds of devices answers in time.

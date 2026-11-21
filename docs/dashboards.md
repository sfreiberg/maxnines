# Dashboards

A dashboard is a grid of widgets that everyone signed in shares. Each widget asks one
question about the fleet: a metric, how to combine hosts' values, what gets a line
of its own, and which hosts, using the same filter as the Hosts list. A widget can
be a chart, a single number or a table with the highest first.

Make one under **Dashboards**, then **Edit** it to add widgets and drag them around.
Their places are saved as they're moved.

## Variables

A variable is a picker at the top of a dashboard, so one dashboard can show any
host instead of needing one for each. Add one under **Edit > Add variable**. It
picks either:

- **One host.** The picker lists the hosts by hostname, and starts on the first.
- **A value of a fact**, such as `role` or `os.name`, or **All** of them. The picker
  lists the values the hosts have, and starts on All.

Its **Hosts** filter limits what's offered, so a picker for Windows hosts alone
has `os=windows`.

A widget follows a variable when its filter has the variable as a term on its own,
with a `$` in front:

| Filter | What the widget shows |
| --- | --- |
| `$host` | The host that's picked. |
| `$role os=linux` | Linux hosts with the role that's picked, or every Linux host for All. |
| `os=linux` | Every Linux host, whatever's picked. |

A widget's title can mention a variable the same way, as in `CPU on $host`, and
shows what's picked.

What's picked is kept in the page's address, so a link to a dashboard opens on the
same host. Changing the time range keeps it too.

A variable that a widget uses can't be removed or renamed until the widget's filter
stops using it, and a widget can only use the variables its dashboard has.

# Local publishing interface

Barev exposes a session-bus interface for desktop frontends. The plugin supplies
account state; frontends discover services and request data
through typed D-Bus methods. GIO's GDBus implementation supplies the transport.

## Building

The Linux build enables the adapter by default and requires `gio-2.0` development
files, version 2.54 or newer. Python 3 embeds the introspection XML during the
build. GIO is part of GLib. Pidgin's own D-Bus build option is independent of this
interface. Build with `DBUS=0` to omit the adapter and its GIO dependency.

## Discovery

| Plugin | Bus name | Object path | Implementation |
| --- | --- | --- | --- |
| Oberon | `org.barev.Native` | `/org/barev/Native/Publishing` | `oberon` |
| C | `org.barev.C` | `/org/barev/C/Publishing` | `c` |

Both objects implement `org.barev.Publishing1`. Their distinct paths allow both
plugins to run in the same host process. The interface definition is distributed
as `dbus-interface.xml` with the adapter sources.

Services start when their plugins load. They do not request activation of another
process, replace an existing name owner or queue behind one. A second host using
the same bus name keeps its chat functionality but does not expose this service.
The interface is also optional at runtime: an unavailable session bus does not
prevent chat accounts from connecting.

## Methods and signals

`GetInfo() → (u version, s implementation, as capabilities)` returns interface
version `1`, the implementation identifier above and supported capabilities.
The current capability list contains only `accounts`.

`ListAccounts() → a(sss) accounts` returns connected accounts. Each row contains:

1. The persistent Ed25519 public-key identifier, as 64 hexadecimal characters.
2. The account's UTF-8 nickname.
3. The current local address, without the nickname prefix.

Private key material is never included. Account identifiers remain stable across
reconnects; addresses may change. Row order is unspecified. Disconnected accounts
are absent. Results contain at most 64 rows; exceeding this limit or encountering
invalid account data returns `org.barev.Publishing1.Unavailable` rather than a
partial list. Nicknames are bounded to 256 UTF-8 bytes and addresses to 384 bytes.

`AccountsChanged()` signals that clients should retrieve the list again. Subscribe
before the initial read. Signals are invalidation hints, not a persistent event
log. Watch the service's name owner and discard session state when it changes;
after reconnecting, subscribe and retrieve a fresh snapshot.

The current interface supplies account discovery. Publishing, following, cached
posts, unread counts and discussions require additional backend operations and
are not advertised as capabilities yet.

## Desktop trust and lifecycle

The interface uses the normal session/user bus and trusts applications running as
the same Unix user. The bus's local authentication and policy exclude other
ordinary users under the standard configuration. Multiple login sessions of the
same Unix user may share the bus. No additional application-pairing secret is
required by this trust model.

The adapter runs on the host's default GLib main context. It starts asynchronously
and detaches backend callbacks before shutdown. Hosts must keep the context alive
until `BarevDBus_Idle()` reports that GIO has released all adapter callbacks.
Plugin unloading is deferred while those callbacks remain reachable. Losing the
bus does not terminate the host.

## Inspection

With the Oberon plugin loaded:

```sh
gdbus call --session --dest org.barev.Native \
  --object-path /org/barev/Native/Publishing \
  --method org.barev.Publishing1.GetInfo
```

Use `ListAccounts` as the method name to inspect connected accounts. For the C
plugin, use destination `org.barev.C` and path `/org/barev/C/Publishing`.

## Tests

Run `make dbus-test` in the Oberon repository or `make test-dbus` in the C
repository. These adapter tests create a disposable bus with `dbus-run-session`
and separately exercise an unavailable bus. They do not use the desktop bus.
Run `make dbus-plugin-test` in the Oberon repository or `make test-dbus-plugin`
in the C repository for account discovery, reconnection and name collisions
through isolated plugin hosts.

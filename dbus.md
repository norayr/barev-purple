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
`accounts` advertises discovery. `local-posts` is added only when the host attaches
a publishing backend. The Oberon plugin supplies a durable account backend and
advertises `accounts` and `local-posts`. The C plugin advertises `accounts` while
its publishing backend is pending; its publishing methods return `NotSupported`.

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

## Capability-gated local posts

Clients check for `local-posts` before using these methods. Calls without an
attached backend return `org.barev.Publishing1.NotSupported`. Account IDs are
64 lowercase hexadecimal characters; each operation targets one connected local
account. An implementation must retire pending work when that account closes.

| Method | Inputs | Outputs |
| --- | --- | --- |
| `GetPublishingState` | `s account` | `s state` |
| `InitializePublishing` | `s account` | none |
| `ReloadPublishing` | `s account` | none |
| `ListDestinations` | `s account` | `a(ssu) destinations` |
| `CreateDestination` | `s account, s node, s title, u model, as names` | none |
| `Publish` | `s account, s node, s token, s title, s text, s parent` | `s item, s id` |
| `ListPosts` | `s account, s node, s cursor, u maximum` | `a(ssssssss) posts, s next` |
| `GetPost` | `s account, s node, s item` | `(ssssssss) post` |

State labels are `loading`, `uninitialized`, `ready`, `saving` and `unavailable`.
Committed posts remain readable while a candidate is `saving`; another mutation
returns `Busy`. Initialization is an explicit first-setup operation;
missing established history requires recovery rather than silent reinitialization.
`ReloadPublishing` asynchronously reloads and validates the account checkpoint,
invalidating previous cursors. After a storage failure, reload before inspecting
retained IDs or retrying a write. Reloading does not initialize missing history.
Destination rows contain node ID, display title and access model: `1` for open,
`2` for roster and `3` for whitelist. Audience names are interpreted and validated
by the backend according to that model.

Post tuples contain PubSub item ID, Atom ID, author, title, text, published time,
updated time and parent Atom ID, in that order. The backend binds the publication
token to durable IDs, generates author/timestamp metadata and applies audience
and Atom wire-budget checks.
An empty parent denotes a root post. A parent reference requires authenticated
audience context before a reply can be accepted.

Before publishing, clients retain a fresh canonical UUIDv4 token represented as
32 lowercase hexadecimal digits without hyphens. Retries reuse that token and
the same destination/title/text/parent. The backend derives the item and Atom IDs
from the token and returns an already committed matching publication without
creating a second post. Reusing a token for different content or a retracted ID
is a conflict. This contract lets a client resolve an uncertain save or lost
reply by reloading the token's retained identity before retrying.

List requests contain at most 32 posts per page. An empty cursor begins a page
sequence, and an empty `next` marks its end. Cursor strings are opaque and at
most 64 bytes. The native backend binds cursors to the account, client unique bus
name and destination, rotates them after each page, and rejects stale cursors
after committed changes or reloads. Each account permits 16 cursors, expiring
after 300 seconds. Keep one bus connection for a page sequence; separate command
processes cannot advance one another's cursors. Destination lists contain at most 16 rows.
Malformed backend rows fail the whole response rather than returning partial data.

Titles, text, author addresses, item IDs and Atom references retain the backend's
byte bounds: 256, 16,384, 384, 128 and 1,024 respectively. Audience lists contain
at most 128 names, each at most 384 bytes. Input parameters are bounded to 64 KiB
and result-row text to 1 MiB per call. The application backend supplies syntax and
authorization checks beyond these transport limits.

`PublishingChanged(s account)` invalidates local destination/post snapshots.
Subscribe before reading, and reload snapshots after a hint. Hosts emit the hint
only after a durable mutation completes successfully. Loads, reloads, failed
writes and exact publication retries emit no mutation hint. Methods report mutation
success after checkpoint completion; acceptance into a worker queue is pending
work. This capability covers durable local storage. Remote PubSub delivery and
following require service-side integration.

Application errors use the `org.barev.Publishing1` prefix and the names
`InvalidArgument`, `Denied`, `NotFound`, `Conflict`, `Full`, `Stale`, `StorageError`,
`Changed`, `WireFull`, `Unavailable` and `Busy`. After an uncertain storage failure,
inspect reloaded retained IDs and revisions before retrying a publication.

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

Publishing dispatch receives plain C request/post records, independently of
GVariant and widget types. It owns a `BarevDBusCall` until `BarevDBus_Release`,
including when a request is deferred. Request strings remain valid until release;
added result rows are copied. `BarevDBus_Complete` consumes a reply once, returning
whether that completion was accepted, including error replies.
`request.client` is the transport-supplied unique sender name, valid until release;
it is suitable for binding cursors without accepting a caller-chosen identity.

There are at most 32 retained calls per service and eight per client bus name.
Completed calls still count until the backend releases them. All dispatch,
result, attach/detach and lifecycle operations belong to the service's owning
thread and default main context.

Backend detachment, bus loss and shutdown abort pending replies as `Unavailable`
and prevent late success replies. They retain backend-owned call handles until
release, so `BarevDBus_Idle` remains false while backend work can still reach the
adapter. Account retirement must finish or abandon its backend operations and
release those handles. Module unloading also waits for any background file work
to drain.

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

Run `make dbus-publishing-test` in the Oberon repository or
`make test-dbus-publishing` in the C repository for capability gating, typed
requests/results, byte/row bounds, deferred request ownership, queue limits,
error replies, change hints, backend detachment and retained-call shutdown.
These tests use standalone backend fixtures on a disposable bus.

Run `make dbus-publishing-plugin-test` in the Oberon repository for the connected
account backend. A disposable plugin host checks initialization, persisted setup
markers, Unicode posts, retry identity, private-reply isolation, paging, mutation
hints, lock failures, explicit reload and disconnect with a pending save. Accepted
writes may finish after disconnect; reconnect reloads them without reviving the
retired call. These fixtures do not contact configured peers.

# Feed audience policies

`feed-access.c` supplies immutable audience policies and current contact snapshots
for the publishing backend. Its access models follow XEP-0060: `open` for public
nodes, `roster` for selected contact groups and `whitelist` for named contacts.
The corresponding Oberon implementation is `BarevFeedAccess`.

## Authorization

A reader captures the peer identity and 32-byte public key from a live mutual
TLS/SASL EXTERNAL session. Private access also requires a current manually
authorized contact snapshot with the matching verified pin. Callers supply that
snapshot for every discovery, retrieval and notification check.

Roster access uses current membership in any configured group. Adding a member
grants access to retained history; removing membership withdraws future retrieval
and notification access. Whitelist membership matches the complete canonical
contact identity. Nicknames and group labels are case sensitive. Empty private
audiences deny all readers.

An anonymous reader may access open nodes. Closing a reader or failing an
authentication attempt clears its captured authority. Replacing a saved pin
invalidates an older session until a new connection authenticates with the newly
approved key. Public access remains independent of private contact settings.

## Ownership and limits

All calls belong to the application thread. Policies copy their inputs and use
explicit `ref`/`unref` lifetime management. Contact snapshots copy their identity,
pin and groups and are released with `barev_feed_contact_free`. Reader records
copy captured keys and are cleared with `barev_feed_reader_close`.

Policies permit 256 whitelist contacts or 16 roster groups. Group labels contain
at most 256 UTF-8 bytes, excluding control characters. Contact identities use the
existing Barev address parser. Duplicate groups and canonically equivalent
whitelist entries are rejected. Count, supplied-array and key-length validation
precedes indexing or copying.

The standalone policy core is the first C publishing application layer. The C
plugin continues to advertise account discovery while its storage and account
bindings are being developed.

## Tests

`make test-feed-access` exercises access models, current authorization and pins,
binary-key capture, group changes, canonical addresses, immutable input copies,
Unicode, malformed configuration and maximum audience sizes.

For cross-implementation checks, build `make feed-access-matrix` in the Oberon
repository, then run from this repository:

```sh
python3 tests/check-feed-access.py tests/feed-access-test /path/to/FeedAccessMatrix
```

The independently implemented fixtures compare 480 decisions across audience,
authentication and current-contact states. Validation uses Linux, GCC/Clang and
VOC; other Oberon compilers and Windows require separate runs.

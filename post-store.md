# Local post records and snapshots

`post.c` and `post-store.c` implement bounded immutable text posts and local
account-owned storage. The corresponding native modules are `BarevPost` and
`BarevPostStore`. Both implementations use the same version-one snapshot format.

## Records and ownership

Each post contains a persistent owner-key identifier, PubSub item ID, absolute
Atom ID, canonical Barev author identity, title, content, publication/update UTC
timestamps and optional parent Atom ID. Validation applies byte bounds, UTF-8 and
XML character checks, Gregorian calendar rules and absolute ASCII URI component
checks. URI escapes for NUL are rejected. Updates preserve publication identity,
author, publication time and parent and require a later update timestamp.

Record construction copies caller data. Post references belong to the application
thread and use explicit `barev_post_ref`/`barev_post_unref` lifetimes. Header and
content getters expose immutable borrowed views. UUIDv4 identifier formatting
uses sixteen caller-supplied random bytes; it leaves entropy unchanged. UTC
formatting accepts nonnegative 64-bit epoch seconds through year 9999.

Stores permit at most 16 destinations, 256 reserved post identities and 4 MiB of
logical record data. Each store has an immutable owner binding. Destination
access models remain fixed; roster or whitelist membership can change within the
same model. Policy objects are retained by reference.

Only matching immutable retries succeed without a mutation. Edits check the
expected revision. Retractions retain both identifiers as tombstones, consuming
reserved slots and preventing reuse. Private-parent references cannot cross into
another destination; public parents can have independent replies in private
destinations. Reply chains are checked for cycles. The owner-facing core can
retain external parent references; the publishing facade must supply authorized
parent context before accepting an external reply.

## Reads and lifetime

Private reads, discovery and page continuation recheck the current reader and
contact snapshot using the feed-audience policy core. Per-node cursors return at
most 32 live posts per page in reverse publication order. Mutations invalidate
that node's generation; unrelated destinations retain their cursors.

Cursor records initially contain zeroes and are released with
`barev_post_cursor_clear`. Closing the store invalidates retained cursors.
Returned pages own references to their posts and remain usable after edits,
retractions or store closure. Individual store getters return borrowed posts;
retain a post reference before mutating or closing its store.

## Binary snapshots

`barev_post_store_encode` produces a `BAREVPS1` image of at most 6 MiB. Integer
words are four-byte, most-significant-byte-first values. Strings are byte lengths
followed by UTF-8 bytes without terminators. The header stores owner identity,
quotas and destination/reserved-slot counts. Destinations retain access models
and audience names; slots retain destination indices, live/tombstone state and
immutable identifiers. Live slots also contain their complete post metadata and
content.

The final word is reflected IEEE CRC-32, using polynomial `EDB88320`, initial
value `FFFFFFFF` and final XOR `FFFFFFFF`. This detects accidental corruption;
filesystem permissions provide the local trust boundary. Snapshots contain
plaintext private posts and audience configuration.

Decoding validates owner, version, counts, quotas, policies, records and reserved
identities before returning a complete store. Invalid input returns `NULL`.
Encoding returns an independently allocated image, freed with `g_free`. Lineage
checks preserve destination/slot prefixes, access models, identifiers and valid
revision or tombstone transitions before a checkpoint can advance.

## Validation and integration

`make test-post-store` checks validators, immutable records, revisions, audience
checks, independent replies, cycles, paging, retained lifetimes, quota boundaries,
large images, every fixture truncation and single-byte checksum corruption, and
structural mutations with recomputed checksums.

Build `make post-interop-fixtures` in the native repository, then run:

```sh
python3 tests/check-post-store.py tests/post-store-test /path/to/native/build
```

The independent fixtures compare 2,295 validator decisions, generate identical
snapshot bytes, exchange images in both directions and check malformed and
canonicalized snapshots with an independent Python codec. Validation uses GCC,
Clang ASan/UBSan and VOC on Linux.

The C plugin keeps its discovery-only capability list while account publishing
integration is being completed.

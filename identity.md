# Barev account identities

Each local account has a persistent Ed25519 key. **My Barev address** displays
the public key and its fingerprint, `SHA256:` followed by the lowercase
hexadecimal SHA-256 digest of the 32 public-key bytes.

Pidgin stores identities inside its libpurple profile, normally:

```text
~/.purple/barev/
  identities/<public-key>.key
  accounts/<account-hash>.identity
  peer-<pin-hash>.pin
```

Custom Pidgin profile directories are honored. Telepathy-Haze uses
`~/.purple/barev/` because its active libpurple profile can be temporary.
The C and Oberon plugins share these formats. The same exact account nickname
in the same persistent profile resolves to the same identity in either plugin.

The public identifier is also saved as the `barev_identity` account setting in
`accounts.xml`. The account link lets Haze recover that association across
temporary profiles. Renaming an account preserves its configured public key;
an existing link to a different identity is an error. Old links and keys are
retained when accounts are renamed or removed.

## Pinning a contact's key

Open **Peer identity...** from an existing contact's menu. Paste the contact's
64 hexadecimal Ed25519 public-key digits from **My Barev address**, then compare
the displayed SHA-256 fingerprint through an independent trusted channel.
Approval saves that public key. Contact information shows the saved key,
fingerprint and **Manually pinned** status.

Changing a pin requires another explicit approval displaying both the old and
new fingerprints. Canceling preserves the existing pin. An unreadable or corrupt
record is an error; restore it from backup before proceeding. If the saved key
changes while the dialog is open, reopen the dialog and compare again.

Pins are scoped to the local public identity and the contact's canonical
`nickname@IPv6` address. Numeric and encoded IPv6 spellings resolve to the same
record; nickname case remains significant. A different peer address or local
identity has a separate pin. Removing a contact retains its pin independently
of `blist.xml`; saving a pin does not add a contact to the manual allowlist.

Peer-pin files contain public data and use ordinary file APIs inside the private
`barev` directory. Use one active client per persistent profile. Keep that
directory private and include pin files in profile backups.

## Authenticated chats

Both contacts must save each other's verified public key before reconnecting
their accounts. Adding or replacing a pin applies to new connections; it does
not upgrade an existing connection.

A new connection to a pinned contact requires STARTTLS, mutual TLS 1.3 and
SASL EXTERNAL. Each peer proves possession of its persistent Ed25519 key using
a self-signed TLS certificate. Trust comes from the exact public-key pin.
Certificates can be renewed without changing the persistent identity or pin.

The initially selected canonical contact and key remain fixed across the TLS
and SASL stream restarts. Presence, messages and other application stanzas wait
until authentication completes. A key mismatch, malformed pin, missing TLS or
failed SASL exchange closes the connection without a plaintext retry.

Contacts without a saved pin retain legacy transport without identity
authentication. Pin both sides and reconnect to require authenticated chats.
TLS protects the XML chat stream; separate file-transfer data connections use
their existing Yggdrasil transport.

### Conversation security indicator

Pidgin's conversation information pane shows a single shield on the right only
after the active connection completes mutual TLS and SASL EXTERNAL. Hover over
the shield to see **Pinned identity authenticated** and the peer fingerprint.
The fingerprint belongs to the key captured when that connection opened;
changing a saved pin does not change an existing connection's identity.

Opening, legacy and closed connections do not display the shield. Switching the
active account in a merged conversation updates the indicator.
The indicator describes the chat stream, not individual message signatures or
separate file-transfer connections.

The optional adapter builds automatically when Pidgin/GTK 2 development headers
are available. Use `make PIDGIN_UI=1` to require it or `make PIDGIN_UI=0` to omit
GTK integration. Other libpurple frontends retain their existing UI.

## Backup and recovery

Back up the entire profile, including `barev/`, `accounts.xml` and `blist.xml`.
Stop clients using the profile while making or restoring a backup. Haze users
should explicitly include the persistent `~/.purple/barev/` directory.

Key files contain **unencrypted secret seeds**. Protect backups as carefully as
the live keys. The `barev`, `identities` and `accounts` directories require mode
`0700`; key and account-link files require mode `0600`, owned by the current
user. A profile directory must be owned by that user and not group/world
writable. The storage boundary rejects symbolic links and multiply linked key
or account-link files.

A configured identity that is missing, unreadable or corrupt causes login to
fail. Restore the key from backup or correct its ownership and permissions;
deleting identity data is not a repair procedure. If both the account setting
and its account link are lost, the software cannot distinguish that account
from a new account. Preserve both in backups.

## File formats

All records are binary and must have exactly the stated length:

| File | Bytes |
| --- | --- |
| Identity key | ASCII `BAREVID1` (8), seed (32), public key (32): 72 bytes. |
| Account link | ASCII `BAREVAC1` (8), public key (32): 40 bytes. |
| Peer pin | ASCII `BAREVPN1` (8), local public key (32), pin hash (32), peer public key (32): 104 bytes. |

The key filename uses the 64 lowercase hexadecimal public-key digits. The
account hash is SHA-256 of the ASCII bytes `Barev account v1\n`, followed by
the exact UTF-8 account nickname, with no terminating NUL. The link filename
uses its 64 lowercase hexadecimal digits.

The pin hash is SHA-256 of the ASCII bytes `Barev peer pin v1\n`, followed by
the raw 32-byte local public key and the UTF-8 canonical `nickname@IPv6` address,
without a terminating NUL. Pin filenames use its 64 lowercase hexadecimal digits.
Loading checks the record header, length, local public key and pin hash.

Loading an identity derives the public key from the seed and checks both the
stored key and filename. New identity and account-link records are synchronized
and installed atomically without overwriting an existing file. A nonblocking
directory lock serializes local identity initialization; a busy profile can be
retried after the other client finishes.

## Implementation and authentication

The Oberon plugin uses VOC's native Ed25519, SHA and TLS 1.3 implementations.
The C plugin uses OpenSSL libcrypto and libssl 1.1.1 or newer. Peer-pin
persistence in the Oberon plugin uses VOC's `oocFiles` byte channels and
temporary-file registration.
Private identity-file operations are kept in a dedicated native filesystem
boundary. The current storage boundary is implemented for Unix-like systems and
tested on Linux. Accounts with a configured identity fail login if protected
identity storage is unavailable. Peer connections fail closed when their local
identity or pin policy cannot be loaded.

The native cryptographic implementation has not been independently security
audited; constant-time execution and complete memory erasure are not guaranteed.

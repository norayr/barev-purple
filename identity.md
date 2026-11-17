# Barev account identities

Each local account has a persistent Ed25519 key. **My Barev address** displays
the public key and its fingerprint, `SHA256:` followed by the lowercase
hexadecimal SHA-256 digest of the 32 public-key bytes.

Pidgin stores identities inside its libpurple profile, normally:

```text
~/.purple/barev/
  identities/<public-key>.key
  accounts/<account-hash>.identity
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

The key filename uses the 64 lowercase hexadecimal public-key digits. The
account hash is SHA-256 of the ASCII bytes `Barev account v1\n`, followed by
the exact UTF-8 account nickname, with no terminating NUL. The link filename
uses its 64 lowercase hexadecimal digits.

Loading derives the public key from the seed and checks both the stored key
and filename. New records are synchronized and installed atomically without
overwriting an existing file. A nonblocking directory lock serializes local
initialization; a busy profile can be retried after the other client finishes.

## Implementation and authentication

The Oberon plugin uses VOC's native Ed25519 and SHA implementations. The C
plugin uses OpenSSL libcrypto 1.1.1 or newer. Private file operations are kept
in a dedicated native filesystem boundary. The current storage boundary is
implemented for Unix-like systems and tested on Linux. Windows accounts without
a configured identity retain their existing chat behavior, with identity storage
shown as unavailable. A configured identity cannot be bypassed on Windows; its
login fails until protected Windows storage is available.

Persistent local keys provide the foundation for peer authentication. Chat
connections currently retain their existing Yggdrasil transport and do not yet
negotiate Ed25519 identity proofs. The fingerprint display states this explicitly.
Peer-key pinning, manual fingerprint verification and following remain separate
features; local key creation does not establish trust in a peer key or change
the manual contact allowlist.

The native cryptographic implementation has not been independently security
audited; constant-time execution and complete memory erasure are not guaranteed.

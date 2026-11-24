# Changelog

## 3.2.1 — 2026-11-24

### Chat fixes and troubleshooting

- Normalizing colons in outgoing image filenames so timestamped PNG/JPEG files
  can be sent, while preserving source files and strict incoming-name validation.
- Fixing account-disable crashes with pending file transfers and cleaning up
  transfers whose streamhost has not yet been selected.
- Reporting peer authentication state and Pidgin shield-adapter availability
  independently, with additional shutdown diagnostics.
- Documenting Colorize's outgoing-image removal, Conversation Colors' incoming
  image suppression, and Debian's `pidgin-dev` requirement for the shield.

### Local publishing infrastructure

- Adding session-bus account discovery through the optional GIO/GDBus interface.
  The C plugin advertises account discovery; local publishing calls remain
  capability-gated and return `NotSupported` until its account backend is attached.
- Adding bounded post records, immutable feed audiences, interoperable snapshots
  and asynchronous validated checkpoints as backend components. Remote delivery,
  following and a social frontend remain under development.
- Requiring GIO 2.54 or newer and Python 3 for the default Linux build. Use
  `DBUS=0` to omit the local D-Bus interface. See [the interface guide](dbus.md).

### Validation

Linux full-feature builds, headless ASan/UBSan regressions and authenticated
C/Oberon BoB/IBB interoperability pass. Builds with GTK and D-Bus disabled and
temporary installation checks also pass. Windows and BSD validation remains
outstanding.

Back up the libpurple profile before upgrading. Existing identities and pins
remain valid. See [image troubleshooting](images.md) and
[shield build requirements](identity.md#why-is-the-shield-missing-on-debian).

## 3.2.0 — 2026-11-19

- Adding persistent Ed25519 account identities, public keys and SHA-256
  fingerprints, with shared identity storage for C and Oberon Barev.
- Adding manually verified peer-key pins, explicit replacement confirmation and
  persistent pins scoped to the local identity and canonical contact address.
- Requiring mutual TLS 1.3 and SASL EXTERNAL for pinned contacts, with exact-key
  verification and no plaintext fallback after authentication failure. Both
  contacts must pin each other's verified key and reconnect. Unpinned contacts
  retain legacy transport.

- Showing live pinned-identity authentication as one shield in Pidgin's conversation
  header, with authentication details and the captured peer fingerprint in a tooltip.
  Pending, legacy and closed connections hide the shield. The optional GTK adapter
  follows account switching in merged conversations and can be disabled with
  `PIDGIN_UI=0`.
- Passing Linux authentication, C/Oberon interoperability and ASan/UBSan checks,
  with interactive Pidgin validation of the shield-only indicator.

Back up the libpurple profile, including `barev/`, before upgrading. TLS protects
the chat stream; separate file-transfer connections retain their existing
Yggdrasil transport. See [account identities](identity.md) for trust, backup and
recovery details.

## 3.1.1 — 2026-11-11

### Fixed

- Enforcing complete peer identities and actual socket addresses during stream
  establishment, including the expected contact on outgoing connections.
- Validating stream recipients, versions and namespaces, and checking stanza
  addresses against the established identities.
- Preserving established connections, resolving simultaneous connections
  consistently for case-only nicknames, and rejecting unknown or over-limit
  incoming peers.
- Bounding stream headers and incomplete XML frames, enforcing connection
  deadlines, and closing malformed streams before further stanza delivery.
- Escaping stream identities and using complete numeric identities on outgoing
  stanzas, including saved Haze nickname contacts.

## 3.1.0 — 2026-11-09

### Added

- Locally encoded `nick@<encoded>.barev.v6.alt` addresses, with contact lookup,
  information windows, and a **My Barev address** account action. Alternate valid
  spellings resolve to the same numeric identity; generated names are canonical.
- Bounded inline image exchange using BoB and IBB, image resizing and previews,
  and explicit consent for original-image transfers.
- XHTML formatting controls and status messages in contact information.
- A 32-bit Windows port for Pidgin.
- Cached avatar reuse across account logins.

### Fixed

- Rejecting missing or empty stream identities, and avoiding a freed-string read
  in parser debug logging.
- Rejecting malformed buddy additions and removing rejected local entries.
- Correcting image resize actions and invalid-selection notices.
- Improving connection collision handling, unreachable-peer detection, and
  presence preservation across pings and stream replacement.
- Improving media negotiation and teardown, and accepting pending Linux
  connections reliably.
- Fixing crash, leak, and contact-persistence issues.

### Build and compatibility

- Existing numeric IPv6 contacts remain supported. Encoded contacts are converted
  locally and continue using numeric identities on the wire; no DNS is required.
- Voice/video support remains optional through `USE_VV`, with automatic detection
  when GStreamer and Farstream are available.
- Haze manager installation is optional, and the installed icon style is
  configurable.
- Build identities are inspectable; source archives retain the release version
  without requiring Git metadata.

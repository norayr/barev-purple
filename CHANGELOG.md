# Changelog

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

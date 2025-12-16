# Barev — Bonjour like Pidgin/libpurple plugin & protocol for Yggdrasil network

**Barev** was started initially as a fork of Pidgin’s Bonjour protocol plugin, adapted for **manual peer addressing** (no mDNS / no Avahi required).
It’s meant for direct peer-to-peer chats (and related features) over IPv6—commonly used with **Yggdrasil**.

Before making **Barev**, the [attempt](https://github.com/norayr/ybb) of using **Bonjour** over Yggdrasil was made. It works, but is limited. Thus this project.

# Compile

## Requirements

You need Pidgin (libpurple) development headers and common build tools.

## Dependencies

On Gentoo: net-im/pidgin, dev-libs/libxml2

On Debian: libpurple-dev, libxml2-dev

## Actual build

```
git clone https://github.com/norayr/barev
cd barev
make
```

then
```
sudo make install
```
or just manually copy libbarev.so to ~/.purple/plugins
```
cp libbarev.so ~/.purple/plugins
```

restart pidgin.

# Usage
Because Barev does not do discovery, you must exchange contact details out-of-band.

Each side provides the other party their
* nick
* yggdrasil ip
* port (on which barev is listening)

Add your buddy (Buddies -> Add Buddy).

Enter the peer's nick@ipv6

The contact will be added to ` ~/.purple/barev-contacts-<nick>.txt`

Currently, if you want to change your contact's port, you need to

* Stop pidgin
* Edit that file, change port
* Start pidgin

# What works

* p2p Serverless Messaging (XEP-0174) - This is the core protocol for serverless (peer-to-peer) XMPP. However, note that Barev uses a version without full XEP-0174, but the idea is similar, the MDNS parts are replaced with the XEPs below.
**  Messaging like described in Core XMPP (RFC 6120 and RFC 6121)

*** Stream management (the stream:stream opening and closing, and the basic stanza exchange).

*** Presence stanzas for status.

*** Message stanzas for chat.

* XMPP pings (XEP-0199) - Used for ping/pong to keep the connection alive and check availability.

* file transfers based on
** Stream initiation(XEP-0095) - Used for initiating the file transfer stream.
** SI File Transfer (XEP-0096) - Used for the actual file transfer over the stream.

* statuses: available, away, do not disturb, status lines.
* avatars (XEP-0153)
* Chat State Notification (XEP-0085) - a bit of composing events.

# What does not work

but nice to have

audio/video.
no mucs.

# Dreams

XMPP publishing.

---

# Appendix

# Barev XMPP Extension Protocols (XEPs) Reference

## Core XEPs Used in Barev

### 1. **XMPP Core (RFC 6120)**
The foundation of all XMPP protocols. Barev implements a minimal subset:
- **Streams**: `<stream:stream>` with `jabber:client` namespace
- **Stanzas**: `<message>`, `<presence>`, `<iq>`
- **Basic Addressing**: JIDs with `localpart@domain` format

### 2. **XMPP IM (RFC 6121)**
Basic instant messaging functionality:
- **Presence**: `<show>` and `<status>` elements
- **Messages**: Basic `<message>` stanzas with `<body>`
- **Roster**: Simplified buddy list management

### 3. **XEP-0174: Serverless Messaging**
**This is the core of Barev!**
- Peer-to-peer XMPP without servers
- Direct TCP connections between peers
- DNS-SD for service discovery (replaced by Yggdrasil addressing in Barev)
- **Barev modification**: Uses Yggdrasil IPv6 addresses instead of mDNS

### 4. **XEP-0095: Stream Initiation (SI)**
File transfer initiation:
- `<si>` element for transfer offers
- Session ID management
- MIME type and file size negotiation

### 5. **XEP-0096: SI File Transfer**
Actual file transfer protocol:
- Bytestreams negotiation (`<bytestreams>`)
- Streamhost selection
- Direct TCP data transfer

### 6. **XEP-0199: XMPP Ping**
Connection keepalive:
- `<ping xmlns="urn:xmpp:ping">`
- Periodic ping/pong for connection health
- **Barev addition**: Also supports `urn:yggb:ping` namespace for compatibility

### 7. **XEP-0085: Chat State Notifications**
Typing indicators:
- `<composing/>` element in `jabber:x:event` namespace
- implemented.

### 8. **XEP-0004: Data Forms**
Form-based data negotiation:
- Used in file transfer method selection
- `<x xmlns="jabber:x:data" type="form">`

### 9. **XEP-0071: XHTML-IM**
Formatted messaging:
- `<html xmlns="http://www.w3.org/1999/xhtml">`
- iChat compatibility with custom extensions
- **iChat extensions**: `ABSZ`, `ichatballooncolor`, `ichattextcolor`

---

## Barev-Specific Extensions and Modifications

### 1. **Yggdrasil Addressing**
**Not a standard XEP**
- Uses Yggdrasil IPv6 addresses (0200::/7 range) in JIDs
- Replaces traditional domain names
- Example: `inky@201:af82:9f2f:7809:be0c:360a:1587:6be7`

### 2. **Direct Connection Model**
**Modified from XEP-0174**
- No DNS-SD or mDNS
- Direct TCP connections only
- No fallback to server-based routing
- Port 5299 fixed (vs. dynamic port assignment in XEP-0174)

### 3. **Simplified Stream Features**
**Stripped-down from RFC 6120**
- No TLS negotiation
- No SASL authentication
- No compression
- No stream features exchange

### 4. **One-Pipe Connection Model**
**Barev-specific optimization**
- Single bidirectional connection per buddy pair
- No parallel connections
- Connection persistence until failure

---

## Presence Status Mapping

### Standard XMPP Presence to Barev Status:

| XMPP `<show>` | Barev Status | Description |
|---------------|--------------|-------------|
| (none) | `available` | Online/available |
| `away` | `away` | Temporarily away |
| `xa` | `away` | Extended away |
| `dnd` | `busy` | Do not disturb |
| `type="unavailable"` | `offline` | Offline |

### Barev Status Codes:
- `BONJOUR_STATUS_ID_AVAILABLE`
- `BONJOUR_STATUS_ID_AWAY`
- `BONJOUR_STATUS_ID_BUSY`
- `BONJOUR_STATUS_ID_OFFLINE`

---

## Message Format Support

### 1. **Plain Text Messages**
```xml
<message type="chat">
  <body>Hello world</body>
</message>
```

### 2. **XHTML-IM Messages (iChat compatibility)**
```xml
<message type="chat">
  <body>Hello world</body>
  <html xmlns="http://www.w3.org/1999/xhtml">
    <body>
      <font face="Helvetica" ABSZ="14" color="#000000">
        Hello world
      </font>
    </body>
  </html>
</message>
```

### 3. **Typing Notifications**
```xml
<message type="chat">
  <x xmlns="jabber:x:event">
    <composing/>
  </x>
</message>
```

---

## IQ Stanza Types Used

### 1. **Get/Result (Ping)**
```xml
<!-- Request -->
<iq type="get" id="ping-123">
  <ping xmlns="urn:xmpp:ping"/>
</iq>

<!-- Response -->
<iq type="result" id="ping-123"/>
```

### 2. **Set/Result (File Transfer)**
```xml
<!-- File offer -->
<iq type="set" id="ft-123">
  <si xmlns="http://jabber.org/protocol/si">...</si>
</iq>

<!-- Acceptance -->
<iq type="result" id="ft-123">...</iq>
```

### 3. **Error Responses**
```xml
<iq type="error" id="some-id">
  <error code="403" type="auth">
    <forbidden xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/>
  </error>
</iq>
```

---

## Namespaces Used

### Core Namespaces:
- `jabber:client` - Main stream namespace
- `http://etherx.jabber.org/streams` - Stream namespace
- `urn:ietf:params:xml:ns:xmpp-stanzas` - Error namespace

### Extension Namespaces:
- `urn:xmpp:ping` - Ping/pong (also `urn:yggb:ping` in Barev)
- `http://jabber.org/protocol/si` - Stream initiation
- `http://jabber.org/protocol/bytestreams` - File transfer
- `http://jabber.org/protocol/feature-neg` - Feature negotiation
- `jabber:x:data` - Data forms
- `jabber:x:event` - Chat events
- `http://www.w3.org/1999/xhtml` - Formatted messages

---

## Protocol Flow Summary

### 1. **Connection Establishment** (XEP-0174 inspired)
```
Client A                                  Client B
    |                                         |
    |-- TCP Connect to B:5299 -------------->|
    |                                         |
    |-- <stream:stream from="A" to="B"> ---->|
    |                                         |
    |<-- <stream:stream from="B" to="A"> ----|
    |                                         |
    |-- <presence/> ------------------------>|
    |                                         |
    |<-- <presence/> ------------------------|
    |                                         |
    [Connection established for messaging]
```

### 2. **File Transfer** (XEP-0095 + XEP-0096)
```
    |                                         |
    |-- <iq type="set"><si>...</si></iq> --->| (XEP-0095)
    |                                         |
    |<-- <iq type="result">...--------------->| (XEP-0095)
    |                                         |
    |-- <iq type="set"><bytestreams>...</iq>->| (XEP-0096)
    |                                         |
    |<-- <iq type="result"><streamhost-used>--| (XEP-0096)
    |                                         |
    |<-- TCP Connect to streamhost -----------|
    |                                         |
    |-- File data over TCP ------------------>|
    |                                         |
    |-- <iq type="set">(complete) ----------->|
    |                                         |
    |<-- <iq type="result"/> -----------------|
```

### 3. **Keepalive** (XEP-0199)
```
    |                                         |
    |-- <iq type="get"><ping/></iq> -------->| (every 30s)
    |                                         |
    |<-- <iq type="result"/> ----------------| (within 10s)
    |                                         |
    [If 3 failures: mark buddy offline]
```

---

## Omitted XEPs (Not Used in Barev)

### 1. **Security**
- **XEP-0035**: TLS - Not used (no encryption)
- **XEP-0038**: SASL - Not used (no authentication)
- **XEP-0116**: Encryption - Not used

### 2. **Advanced Features**
- **XEP-0045**: MUC - No group chat
- **XEP-0047**: In-band Bytestreams - Uses direct TCP instead
- **XEP-0065**: SOCKS5 Bytestreams - Not used
- **XEP-0234**: Jingle - No voice/video

### 3. **Discovery & Capabilities**
- **XEP-0030**: Service Discovery - Not used
- **XEP-0115**: Entity Capabilities - Not used
- **XEP-0128**: Service Discovery Extensions - Not used

### 4. **Time & Version**
- **XEP-0090**: Entity Time - Not used
- **XEP-0092**: Software Version - Not used

---

## Implementation References in Code

### 1. **XEP-0174 (Serverless Messaging)**
- `bonjour_find_buddy_by_localpart()` - JID matching
- Direct TCP connections without servers
- Peer-to-peer presence broadcasting

### 2. **XEP-0095/0096 (File Transfer)**
- `xep_si_parse()` - Stream initiation parsing
- `xep_bytestreams_parse()` - Bytestreams negotiation
- `bonjour_jabber_get_local_ips()` - Yggdrasil address selection

### 3. **XEP-0199 (XMPP Ping)**
- `bonjour_jabber_send_ping_request()`
- `bonjour_jabber_handle_ping()`
- `bonjour_jabber_ping_timeout_cb()`

### 4. **XEP-0085 (Chat States)**
- `<composing/>` element parsing in `_jabber_parse_and_write_message_to_ui()`
- `jabber:x:event` namespace handling

### 5. **XEP-0071 (XHTML-IM)**
- `_jabber_parse_and_write_message_to_ui()` - HTML message parsing
- `_font_size_ichat_to_purple()` - iChat compatibility

---

## Compatibility Notes

### 1. **Interoperability with Standard XMPP**
- **Not compatible** with standard XMPP servers
- **Not compatible** with clients that require TLS/SASL
- **Only compatible** with other Barev implementations

### 2. **Backwards Compatibility**
- All versions must support basic stanzas (`message`, `presence`, `iq`)
- New versions can add optional features
- Unknown stanzas should be ignored (not rejected)

### 3. **Forward Compatibility**
- Future versions should maintain basic protocol flow
- Can add new XEPs but must not break existing functionality
- Should gracefully handle missing optional features

---

## Quick XEP Reference Table

| XEP | Purpose | Barev Implementation | Notes |
|-----|---------|---------------------|-------|
| RFC 6120 | Core XMPP | Partial | Streams and stanzas only |
| RFC 6121 | IM | Partial | Basic presence and messaging |
| XEP-0174 | Serverless Messaging | Core | Modified for Yggdrasil |
| XEP-0095 | Stream Initiation | Full | File transfer offers |
| XEP-0096 | SI File Transfer | Full | Direct TCP bytestreams |
| XEP-0199 | XMPP Ping | Full | Keepalive mechanism |
| XEP-0085 | Chat States | Partial | Parsed but not fully used |
| XEP-0071 | XHTML-IM | Partial | iChat compatibility |
| XEP-0004 | Data Forms | Partial | File transfer negotiation |
| XEP-0030 | Service Discovery | None | Not needed in Yggdrasil |
| XEP-0115 | Entity Capabilities | None | Not implemented |

---

## For Client Developers: Required XEP Support

**Minimum required for Barev compatibility:**
1. XMPP Core (RFC 6120) - Streams and stanzas
2. XMPP IM (RFC 6121) - Presence and messages
3. XEP-0174 - Serverless messaging model
4. XEP-0199 - Ping/pong keepalive

**Recommended for full compatibility:**
1. XEP-0095/0096 - File transfer
2. XEP-0071 - Formatted messages
3. XEP-0085 - Typing notifications

**Optional (can be ignored):**
1. XEP-0030 - Service discovery
2. XEP-0115 - Entity capabilities
3. Any other XEPs

---


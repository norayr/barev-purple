# Barev Protocol Specification v0.1
*A Simplified Peer-to-Peer XMPP Protocol for Yggdrasil Networks*

---

## Overview
Barev is a simplified peer-to-peer XMPP/Jabber protocol designed for Yggdrasil IPv6 networks. It enables direct messaging between nodes without central servers using a "one pipe per buddy" connection model.

---

## Encoded Barev addresses

Contacts can be added as either `nick@IPv6` or
`nick@<encoded>.barev.v6.alt`. For example, `nick@200::1` and
`nick@ai-e.barev.v6.alt` identify the same contact. Existing IPv6 input and
Haze's saved bare-nickname contacts continue to work. Nickname case remains
significant; Pidgin aliases are independent local display labels and are preserved.

**Get Info** shows the contact's IPv6 and full encoded **Barev address**, including
when the contact is offline. While connected, choose **Accounts → your Barev
account → My Barev address** to view and copy your own full address. The account
action uses the current account's numeric wire identity. If you use a nondefault
listening port, share that port separately; the encoded address contains only
the IPv6 address. The default chat port remains 1337.

Conversion is local to the plugin and requires no DNS queries or additional
software. Encoded input is stored and sent as a numeric IPv6 identity, preserving
compatibility with older peers. Contact lookup treats both address spellings as
the same identity.

The label follows the [v6.alt scheme](https://modules.prosody.im/mod_s2s_v6mesh.html):
26 lowercase, unpadded RFC 4648 base32 characters encoding the 16 IPv6 bytes,
with the first longest interior run of at least two `a` characters replaced by
`-`, followed by `.barev.v6.alt`. Input accepts uppercase hostnames, an optional
final dot, uncompressed labels, and alternate valid zero-run compression.
Multiple hyphens, invalid characters, nonzero base32 padding bits, and encoded
contact addresses outside Yggdrasil's `200::/7` range are rejected.

The local codec is in `address.c`. Run `make test-addresses` for its independent
reference, malformed-input, information-window, alias, and persistence tests.

---

## Core Concepts

### 1. Basic Architecture
- **JID Format**: `localpart@yggdrasil_ipv6_address` (e.g., `inky@201:af82:9f2f:7809:be0c:360a:1587:6be7`)
- **Port**: 5299 (default, user-configurable)
- **Protocol**: TCP over IPv6 (Yggdrasil addresses only)
- **Encoding**: UTF-8 XML
- **Security**: No TLS, no authentication (direct trusted connections); Security is taken care of by Yggdrasil network.

### 2. Connection Model: One Pipe Per Buddy
**Key Principle**: Each buddy pair maintains exactly ONE active TCP connection:
- An established connection is preserved when a duplicate arrives.
- Same pipe handles all bidirectional communication
- Subsequent connection attempts are either:
  - Rejected if from unknown IP
  - Rejected when an established pipe already exists
- Simultaneous pending connections use a deterministic identity order: compare
  canonical identities ignoring ASCII case, then use their exact spelling to
  distinguish case-only nicknames. The smaller identity keeps its outgoing
  connection; the larger identity keeps its incoming connection.
- Once connected, all communication flows through this single pipe until it dies

---

## Implementation Guide

### 1. Listening (Accepting Incoming Connections)

#### Using netcat:
```bash
nc -6 -l -p 5299
```

#### Using socat (more robust):
```bash
socat TCP6-LISTEN:5299,fork STDOUT
```

### 2. Connecting (Initiating Outgoing Connections)

#### Using netcat:
```bash
nc -6 201:7a74:aa1e:101a::a1 5299
```

### 3. Stream Initialization Protocol

#### Step 1: First Message After Connection
The **INITIATOR** sends stream header first:
```xml
<?xml version="1.0" encoding="UTF-8" ?>}
<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" from="yourname@your_ygg_ip" to="buddy@buddy_ygg_ip">
```

#### Step 2: Response (Listener Replies)
The **RECEIVER** responds with their stream header:
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" from="buddy@buddy_ygg_ip" to="yourname@your_ygg_ip">
```

**Critical Rules:**
1. The opening element must be `stream` in the
   `http://etherx.jabber.org/streams` namespace. XML uses UTF-8 and version 1.0.
2. An unqualified, nonempty `from` attribute must identify a saved contact. Its
   decoded IPv6 address must match the actual socket peer. Nickname case is
   significant. An outgoing connection must identify the contact it was opened
   for, even when several contacts share the same address.
3. The local socket address must match the account's Yggdrasil IPv6 address.
   Incoming connections require an already saved peer address; there can be at
   most four connections to or from one peer address per account, and 64
   connections across all accounts.
4. If present, `to` must identify the local account, and `version` must be `1.0`.
   Numeric IPv6 variants and encoded Barev addresses are compared by canonical
   identity. A saved Haze nickname uses its explicitly stored IPv6 address.
5. Stream headers are exchanged once. An empty or repeated stream opening,
   malformed XML, and a DOCTYPE declaration cause the connection to close.
6. On every subsequent top-level stanza, optional `from` and `to` attributes must
   match the established peer and local account. Stanzas in `jabber:client` are
   processed; other namespaces are ignored, except that a stream error closes
   the connection. Offline presence also closes the connection.

The opening header is limited to 4096 bytes and must complete within 30 seconds.
Stanzas are limited to 524288 bytes, 24 element levels and 512 nodes, including
attributes and text fragments;
unfinished frames expire after 120 seconds on established connections. Invalid
or incomplete input cannot be used to postpone these deadlines indefinitely.

Run `make test-parser` for stream identity, namespace, recipient, version,
collision, input-limit, connection-admission and deadline regressions.

---

## Communication Stanzas

### 1. Presence (Online/Offline Status)

#### Basic presence (available):
```xml
<presence/>
```

#### Presence with status message:
```xml
<presence>
  <show>away</show>
  <status>I'm away from keyboard</status>
</presence>
```

#### Presence values:
- `<show>away</show>` - Away status
- `<show>xa</show>` - Extended away
- `<show>dnd</show>` - Do not disturb
- No `<show>` element - Available (online)

#### Offline presence:
```xml
<presence type="unavailable"/>
```

### 2. Messaging

#### Basic message:
```xml
<message to="buddy@buddy_ygg_ip" type="chat">
  <body>Hello world!</body>
</message>
```

#### Formatted message (optional, iChat style):
```xml
<message to="buddy@buddy_ygg_ip" type="chat">
  <body>Hello world!</body>
  <html xmlns="http://www.w3.org/1999/xhtml">
    <body>
      <font face="Helvetica" ABSZ="14">Hello world!</font>
    </body>
  </html>
  <x xmlns="jabber:x:event">
    <composing/>
  </x>
</message>
```

### 3. Ping/Pong (Keepalive)

#### Ping request (send every 30 seconds):
```xml
<iq type="get" id="ping-1234567890-1" from="you@your_ip" to="buddy@buddy_ip">
  <ping xmlns="urn:xmpp:ping"/>
</iq>
```

#### Ping response (required when receiving ping):
```xml
<iq type="result" id="ping-1234567890-1" to="buddy@buddy_ip" from="you@your_ip"/>
```

**Note**: After 3 consecutive ping failures, buddy is marked offline.

### 4. Avatars (XEP-0153)

Peers advertise avatars in presence using `vcard-temp:x:update`. The `photo`
value is the 40-digit hexadecimal SHA-1 of the original image bytes, before
Base64 encoding:

```xml
<presence>
  <x xmlns="vcard-temp:x:update">
    <photo>0123456789abcdef0123456789abcdef01234567</photo>
  </x>
</presence>
```

The hash above illustrates the wire format. Each sender computes it from its
actual image. Receivers compare the advertised hash with the SHA-1 of locally
cached image bytes. A matching, available image is reused across stream
reconnections and account logins without an automatic download. Cached checksum
metadata alone is insufficient when the image file is missing or its bytes have
changed.

If the image is missing or its hash differs, request the peer's vCard:

```xml
<iq type="get" id="avatar-1">
  <vCard xmlns="vcard-temp"/>
</iq>
```

The peer replies with the same IQ ID and a `vCard` containing `PHOTO/TYPE` and
Base64-encoded `PHOTO/BINVAL`. Decode the image and recompute SHA-1 before
installing it. The bytes must match the advertised hash associated with that
request. An obsolete response must not replace a more recently advertised
avatar. Keep at most one automatic request outstanding per peer; retire it on
response, error, or a bounded timeout so repeated presence does not create
duplicate downloads. Clients also apply their supported image-format and size
limits.

An explicit `<photo/>` removes the avatar and its cached entry. Presence without
a `photo` element leaves the known avatar unchanged. An explicit user request
for full contact information may still retrieve a vCard independently of the
automatic avatar cache.

#### libpurple storage

Use `purple_buddy_icons_set_for_user()` to store received image bytes and their
verified SHA-1. Use `purple_buddy_icons_find()` and
`purple_buddy_icon_get_data()` to load an existing peer image for validation.
Libpurple manages cache filenames, references, and buddy-list metadata. Its
default cache on Linux is `~/.purple/icons/`; the configured profile or cache
directory can change that location. Implementations use these APIs instead of
constructing cache paths from peer-supplied data.

### 5. Stream Termination

#### Graceful close:
```xml
</stream:stream>
```

#### Note: Socket should be closed immediately after sending stream end.

---

## Complete Example Sessions

### Example 1: You Connect First (Initiator)
```
YOUR CLIENT                                BUDDY'S CLIENT
     |                                           |
     |-- TCP Connect to buddy_ip:5299 --------->|
     |                                           |
     |<?xml ...?><stream:stream from="you@your_ip" to="buddy@buddy_ip">|
     |                                           |
     |<-- <?xml ...?><stream:stream from="buddy@buddy_ip" to="you@your_ip"> --|
     |                                           |
     |-- <presence/> --------------------------->|
     |                                           |
     |<-- <presence/> ---------------------------|
     |                                           |
     |-- <message><body>Hi!</body></message> --->|
     |                                           |
     |<-- <message><body>Hello!</body></message>-|
     |                                           |
     |-- </stream:stream> ---------------------->|
     |                                           |
     | *close socket*                            |
```

### Example 2: Buddy Connects First (Listener)
```
YOUR CLIENT                                BUDDY'S CLIENT
     |                                           |
     |<-- TCP Connect from buddy_ip:5299 --------|
     |                                           |
     |<?xml ...?><stream:stream from="buddy@buddy_ip" to="you@your_ip">|
     |                                           |
     |-- <?xml ...?><stream:stream from="you@your_ip" to="buddy@buddy_ip"> ->|
     |                                           |
     |<-- <presence/> ---------------------------|
     |                                           |
     |-- <presence/> --------------------------->|
     |                                           |
     | ... chat continues ...                    |
```

---

## Protocol State Machine
```
START
  |
  |---[Create LISTENER socket on 5299]---[Incoming connection]---[Accept, create PIPE]
  |        (Server role)                          |                           |
  |                                              |                    [Send stream response]
  |                                              |                           |
  |                                              |                    [Exchange presence]
  |                                              |                           |
  |                                              |                    [Chat phase]
  |                                              |                           |
  |---[Create CLIENT socket (random port)]---[Connect to buddy:5299]---[Send stream header]
  |        (Client role)                              |                           |
  |                                              [Wait for response]---[Exchange presence]
  |                                                                          |
  |                                                                   [Chat phase]
  |
  |---[Periodic ping]---->[If no response in 10s]---[Fail counter++]
  |                         |                           |
  |                         |                    [If fails >= 3: mark offline]
  |                         |                           |
  |---[Send message]----->[If PIPE dead]---[Try reconnect (new client socket)]
  |                         |                           |
  |                         |                    [If success: new PIPE]
  |                         |                           |
  |---[Receive </stream:stream>]---[Close PIPE socket]---[Mark buddy offline]
  |
END
```

---

## Important Implementation Notes

### 1. IP Address Consistency
- Your JID's IP **must** match your actual connection source IP
- If you have multiple Yggdrasil IPs, choose one consistently
- Example problem: Buddy has `adam@201:7b74:aa1e:101a::a1` but connects from `::aaf1`

### 2. Message Ordering
- All stanzas (presence, messages, iq) are sent over the same pipe
- TCP guarantees in-order delivery
- No need for message IDs for ordering (but ping uses them)

### 3. Port Architecture

Barev uses a traditional client-server socket model:

| Component | Local Port | Remote Port | Purpose |
|-----------|------------|-------------|---------|
| **Listener** | 5299 (fixed) | N/A | Accepts incoming connections |
| **Outgoing Connection** | Random (OS-chosen) | 5299 | Initiates connection to buddy |
| **Established Pipe** | Depends on who connected: <br>• If you connected: Random <br>• If buddy connected: 5299 | Opposite of local | All bidirectional communication |

**Key Insight**: The "pipe" is just the established TCP connection, which uses:
- Your listening port (5299) if buddy connected to you
- Your random outgoing port if you connected to buddy

**No Dual-Role Sockets**: Unlike some P2P protocols, Barev does NOT use a single socket that both listens and connects. Instead, it maintains separate sockets for listening and connecting.

### 4. Error Handling
- Socket errors = close connection, mark buddy offline
- XML parse errors = log, but keep connection alive
- Unknown stanza types = log warning, ignore

### 5. Concurrent Connections
- Only one active connection per buddy
- If new connection arrives for same buddy:
  - Close old connection (if exists)
  - Accept new connection
  - Update buddy's IP if different

### 6. Buddy Matching Logic
The protocol matches buddies by:
1. **Exact JID match** (preferred)
2. **IP address match** (last resort)

---

## Troubleshooting Guide

### Common Issues & Solutions:

| Problem | Likely Cause | Solution |
|---------|--------------|----------|
| "Rejecting connection from unknown IP" | JID IP doesn't match connection IP | Ensure your JID uses the IP you connect from |
| Connection refused | Buddy not listening on 5299 | Verify buddy is running Barev client |
| No response after stream header | XML malformed | Check XML formatting, UTF-8 encoding |
| Buddy shows offline but is online | Ping failures | Check network connectivity, firewall rules |
| Multiple connections appearing | Race condition | Accept only one connection, close duplicates |

### Debug Commands:
```bash
# Test connectivity
ping6 201:2a74:aa1e:101a::a1

# Check if port is open
telnet 201:2a74:aa1e:101a::a1 5299

# Monitor traffic (requires sudo)
sudo tcpdump -i any port 5299 -X

# View Yggdrasil IPs
yggdrasilctl getSelf
```

---

## Quick Reference Card

### Connection:
```bash
# Listen (binds to port 5299, accepts incoming connections)
nc -6 -l -p 5299

# Connect (creates new socket with random port, connects to buddy's port 5299)
nc -6 BUDDY_IP 5299
```

### Stream Headers:
```xml
<!-- Initiator sends -->
<?xml version="1.0" encoding="UTF-8" ?>
<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" from="YOU@YOUR_IP" to="BUDDY@BUDDY_IP">

<!-- Listener responds -->
<?xml version="1.0" encoding="UTF-8" ?>
<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" from="BUDDY@BUDDY_IP" to="YOU@YOUR_IP">
```

### Common Stanzas:
```xml
<!-- Presence -->
<presence/>
<presence><show>away</show><status>Message</status></presence>

<!-- Message -->
<message to="BUDDY@BUDDY_IP" type="chat"><body>Text</body></message>

<!-- Ping -->
<iq type="get" id="ping-TIMESTAMP"><ping xmlns="urn:xmpp:ping"/></iq>

<!-- Pong -->
<iq type="result" id="ping-TIMESTAMP"/>

<!-- Close -->
</stream:stream>
```

---

## For Client Developers

### Required Implementation:
1. **Dual-capability**: Both listen AND connect but using separate sockets:

- **Listening socket**: Binds to port 5299 to accept incoming connections
   - **Connecting sockets**: Create new sockets with random ports to initiate outgoing connections
   - **Established pipe**: Whichever connection succeeds first becomes the single bidirectional pipe

2. **Buddy state tracking**: Track `conversation` pointer per buddy
3. **Auto-reconnect**: Attempt reconnect on connection loss
4. **Ping/pong**: 30-second keepalive with 10-second timeout
5. **IP consistency**: Ensure JID matches connection IP

### Recommended Architecture:
```python
class BarevClient:
    def __init__(self):
        self.buddies = {}  # buddy_jid -> Buddy object
        self.listener = None  # Listening socket
        self.conversations = {}  # buddy_jid -> Conversation

    class Buddy:
        def __init__(self, jid):
            self.jid = jid
            self.conversation = None  # Active connection
            self.ips = []  # Known IPs for this buddy

    class Conversation:
        def __init__(self, socket, buddy):
            self.socket = socket
            self.buddy = buddy
            self.last_activity = time.time()
```

### Critical Code Logic (from actual implementation):
- Only ONE `bb->conversation` pointer per buddy
- Incoming connections check: `if (bb->conversation != NULL)` → close old
- Auto-connect skips buddies with active conversations
- Ping timeout after 10 seconds, mark offline after 3 failures

---

## Version History & Compatibility

- **v0.1** (Current): Basic XMPP subset with one-pipe model
- **Backwards compatibility**: All versions must accept stream headers and basic stanzas
- **Forward compatibility**: Ignore unknown stanza types, preserve connection

---

## License & Attribution

Use freely for Yggdrasil-based messaging applications. When implementing, please maintain compatibility with existing Barev clients.

---

## Appendix
Example:

** When you listen **

I ran mc to listen on 5299

```
$ nc -6 -l -p 5299
```
If someone had added you to their contacts, very soon you should get something like:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" from="inky@201:af82:9f2f:7809:be0c:360a:1587:6be7" to="inky@201:b570:cf40:54ee:9756:dfa0:7da1:f4b5">
```

To reply I have pasted:
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" from="inky@201:b570:cf40:54ee:9756:dfa0:7da1:f4b5" to="inky@201:af82:9f2f:7809:be0c:360a:1587:6be7">
```

At this moment my client that initiated a connection showed me who replied as online.

---

*Last Updated: 2025-12-10*
*Based on Pidgin Bonjour plugin with Barev modifications*
*Primary Author: inkubo*
*Protocol Version: 0.1*

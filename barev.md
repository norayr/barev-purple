# Barev Protocol Specification v0.1
*A Simplified Peer-to-Peer XMPP Protocol for Yggdrasil Networks*

---

## Overview
Barev is a simplified peer-to-peer XMPP/Jabber protocol designed for Yggdrasil IPv6 networks. It enables direct messaging between nodes without central servers using a "one pipe per buddy" connection model.

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
- First connection established wins (whoever connects first)
- Same pipe handles all bidirectional communication
- Subsequent connection attempts are either:
  - Rejected if from unknown IP
  - Replace existing pipe if from known buddy
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
1. `from` attribute must match actual source IP
2. `to` attribute must match exactly what's in buddy list
3. Stream headers are exchanged exactly once per connection
4. The pipe is now established for all future communication

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

### 4. Stream Termination

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
  |---[Listen on 5299]---[Incoming connection]---[Receive stream header]
  |                         |                           |
  |                         |                    [Send stream response]
  |                         |                           |
  |                         |                    [Exchange presence]
  |                         |                           |
  |                         |                    [Chat phase]
  |                         |                           |
  |---[Connect to buddy]---[Send stream header]---[Wait for response]
  |                         |                           |
  |                         |                    [Exchange presence]
  |                         |                           |
  |                         |                    [Chat phase]
  |                         |                           |
  |---[Periodic ping]---->[If no response in 10s]---[Fail counter++]
  |                         |                           |
  |                         |                    [If fails >= 3: mark offline]
  |                         |                           |
  |---[Send message]----->[If pipe dead]---[Try reconnect]
  |                         |                           |
  |                         |                    [If success: resume]
  |                         |                           |
  |---[Receive </stream:stream>]---[Close socket]---[Mark buddy offline]
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

### 3. Error Handling
- Socket errors = close connection, mark buddy offline
- XML parse errors = log, but keep connection alive
- Unknown stanza types = log warning, ignore

### 4. Concurrent Connections
- Only one active connection per buddy
- If new connection arrives for same buddy:
  - Close old connection (if exists)
  - Accept new connection
  - Update buddy's IP if different

### 5. Buddy Matching Logic
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
# Listen
nc -6 -l -p 5299

# Connect
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
1. **Dual-role socket**: Both listen AND connect capability
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

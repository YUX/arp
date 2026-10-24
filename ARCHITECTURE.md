# ARP Architecture

## Overview

ARP is a stateless WebSocket relay protocol for autonomous agent communication. The codebase is a Rust workspace with three crates: `arp-common` (shared types and crypto), `arps` (relay server), and `arpc` (client daemon). All crates use `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`. MSRV is 1.88.

## Workspace Layout

```
.
├── Cargo.toml              # Workspace definition
├── crates/
│   ├── arp-common/         # Shared protocol types
│   │   ├── src/
│   │   │   ├── lib.rs      # Crate root with module exports
│   │   │   ├── types.rs    # Pubkey alias, protocol constants
│   │   │   ├── frame.rs    # Binary TLV frame encoding
│   │   │   ├── crypto.rs   # Ed25519 signing, PoW, timestamps
│   │   │   └── base58.rs   # Base58 encoding utilities
│   │   └── Cargo.toml
│   ├── arps/               # Relay server binary
│   │   ├── src/
│   │   │   ├── lib.rs      # Crate root
│   │   │   ├── main.rs     # CLI entry point
│   │   │   ├── config.rs   # CLI args, ServerConfig
│   │   │   ├── server.rs   # Accept loop, ServerState
│   │   │   ├── connection.rs # Per-connection handling
│   │   │   ├── router.rs   # DashMap-based routing table
│   │   │   ├── admission.rs # Challenge-response handshake
│   │   │   ├── ratelimit.rs # Sliding window rate limiter
│   │   │   ├── metrics.rs  # Prometheus endpoint
│   │   │   └── error.rs    # ArpsError types
│   │   └── Cargo.toml
│   └── arpc/               # Client daemon binary
│       ├── src/
│       │   ├── lib.rs      # Crate root with module list
│       │   ├── main.rs     # CLI entry point
│       │   ├── config.rs   # TOML config, Cli args
│       │   ├── relay.rs    # WebSocket connection manager
│       │   ├── hpke_seal.rs # HPKE Auth mode E2E encryption
│       │   ├── local_api.rs # TCP/Unix socket JSON API
│       │   ├── contacts.rs # Contact management
│       │   ├── dedup.rs    # Message deduplication for multi-relay
│       │   ├── keypair.rs  # Ed25519 key generation
│       │   ├── backoff.rs  # Exponential backoff
│       │   ├── webhook.rs  # HTTP push for inbound messages
│       │   ├── bridge.rs   # OpenClaw gateway integration
│       │   └── update.rs   # Self-update from GitHub
│       └── Cargo.toml
```

## arp-common

Core types and serialization shared between client and server.

### Binary TLV Framing

Frames are type-length-value messages with a single-byte type prefix:

| Byte | Type | Description |
|------|------|-------------|
| `0x01` | `TYPE_ROUTE` | Client → relay: deliver payload to destination |
| `0x02` | `TYPE_DELIVER` | Relay → client: payload from source |
| `0x03` | `TYPE_STATUS` | Relay → client: delivery status code |
| `0x04` | `TYPE_PING` | Application keepalive request |
| `0x05` | `TYPE_PONG` | Application keepalive response |
| `0xC0` | `TYPE_CHALLENGE` | Relay → client: admission challenge |
| `0xC1` | `TYPE_RESPONSE` | Client → relay: admission response |
| `0xC2` | `TYPE_ADMITTED` | Relay → client: admission granted |
| `0xC3` | `TYPE_REJECTED` | Relay → client: admission denied |

Size limits (from `frame.rs`):
- `MAX_PAYLOAD`: 65,535 bytes (64 KiB - 1)
- `MAX_FRAME_SIZE`: 65,568 bytes (type byte + 32-byte pubkey + max payload)

The `Frame` enum in `frame.rs` provides constructors like `Frame::route()`, `Frame::deliver()`, and methods `serialize()` / `parse()` for wire encoding.

### Crypto Primitives

`crypto.rs` provides:

**Ed25519 Signatures**
- `sign_admission(signing_key, challenge, timestamp)` → 64-byte signature
- `verify_admission(verifying_key, challenge, timestamp, signature)` → bool

Both operate on `challenge ‖ timestamp` (32 + 8 bytes). Uses stack buffers to avoid heap allocation.

**SHA-256 Proof-of-Work**
- `pow_solve(challenge, pubkey, timestamp, difficulty)` → 8-byte nonce
- `pow_verify(challenge, pubkey, timestamp, nonce, difficulty)` → bool

Hash: `SHA-256(challenge ‖ pubkey ‖ timestamp_be ‖ nonce)`. Difficulty = required leading zero bits. Difficulty 0 disables PoW.

**Timestamp Utility**
- `unix_now()` → u64 seconds since epoch (panics if system clock is before Unix epoch)

### Type Definitions

`types.rs`:
- `pub type Pubkey = [u8; 32]` — Ed25519 public key alias
- `PROTOCOL_VERSION = "arp.v2"` — WebSocket subprotocol identifier
- Status codes: `DELIVERED=0x00`, `OFFLINE=0x01`, `RATE_LIMITED=0x02`, `OVERSIZE=0x03`, `REJECTED_BY_DEST=0x04`
- Rejection reasons: `BAD_SIG=0x01`, `TIMESTAMP_EXPIRED=0x02`, `RATE_LIMITED=0x03`, `OUTDATED_CLIENT=0x10`, `INVALID_POW=0x04`

## arps — Relay Server

Stateless WebSocket relay. Routes opaque payloads, never decrypts content.

### Accept Loop and Server State

`server.rs` contains the main `run()` function:

```rust
pub async fn run(listener: TcpListener, state: Arc<ServerState>) -> Result<(), ArpsError>
```

`ServerState` fields:
- `router: Router` — DashMap routing table (pubkey → ConnHandle)
- `server_keypair: ed25519_dalek::SigningKey` — signs challenges
- `config: ServerConfig` — runtime configuration
- `ip_connections: DashMap<IpAddr, usize>` — per-IP connection counter
- `pre_auth_semaphore: Semaphore` — limits unauthenticated connections

The accept loop:
1. Accept TCP connection
2. Check global `max_conns` limit against `router.len()`
3. Spawn `handle_connection()` task

### Connection Lifecycle

`connection.rs` — `handle_connection()` orchestrates the full lifecycle:

1. **Acquire pre-auth semaphore** — prevents DoS before authentication
2. **HTTP landing page** — peeks at incoming bytes; plain HTTP requests (no `Upgrade: websocket`) get a neutral HTML landing page, or a redirect if `--redirect-url` / `ARPS_REDIRECT_URL` is configured
3. **WebSocket upgrade** — `tokio_tungstenite::accept_hdr_async_with_config()` extracts client IP from Cloudflare headers (`CF-Connecting-IP`, `X-Forwarded-For`)
4. **Protocol version check** — rejects clients with wrong `Sec-WebSocket-Protocol`
5. **Admission handshake** — `perform_admission()` → `admit()`
6. **Registration** — insert into router, spawn message loop
7. **Cleanup** — remove from router on disconnect, decrement gauges

`IpGuard` (Drop impl) ensures per-IP counters are decremented on disconnect.

### Admission Handshake

`admission.rs` — challenge/response flow:

```
Relay                                    Client
  │ ──Challenge(challenge[32], server_pubkey[32], difficulty)──► │
  │ ◄──────Response(pubkey[32], timestamp[8], signature[64],    │
  │                      pow_nonce[8]? optional)─────────────────│
  │ ──Admitted or Rejected(reason)────────────────────────────► │
```

Verification steps (in order):
1. Parse Response frame
2. Check timestamp within ±30s (`TIMESTAMP_TOLERANCE`)
3. Verify Ed25519 signature over `challenge ‖ timestamp`
4. If `difficulty > 0`: verify PoW nonce

Rejection reasons mapped to wire codes in `types.rs`.

### Rate Limiting

`ratelimit.rs` — sliding window rate limiter per connection:

- Window: 60 seconds (`WINDOW_SECS`)
- Tracks: message count + byte count per message
- Limits: `msg_rate` (messages/min) and `bw_rate` (bytes/min)
- Cap: `MAX_BUCKET_ENTRIES = 1000` prevents unbounded growth

`check_and_record(msg_rate, bw_rate, bytes)` returns `Some(reason)` if limited, `None` if allowed. Old entries expire automatically.

### Metrics

`metrics.rs` — Prometheus HTTP server on configured `metrics_addr`:

Endpoints:
- `GET /metrics` — Prometheus format
- `GET /health` — `{"status": "healthy"}` (200)
- `GET /ready` — `{"status": "ready", "ready": true/false}` (200/503)

Counters:
- `arp_admissions_total{status}` — admitted, rejected, timeout
- `arp_messages_relayed_total`
- `arp_messages_dropped_total{reason}` — oversize, rate_limit, offline, unknown_frame
- `arp_payload_bytes_total{direction}` — in, out

Gauges:
- `arp_connections_active`

Histograms:
- `arp_relay_latency_seconds`

### Configuration

`config.rs` — `ServerConfig` from CLI args:

```rust
pub struct ServerConfig {
    pub listen: SocketAddr,           // --listen (default: 0.0.0.0:8080)
    pub metrics_addr: SocketAddr,     // --metrics-addr (default: 0.0.0.0:9090)
    pub max_conns: usize,             // --max-conns (default: 10000)
    pub max_conns_ip: usize,          // --max-conns-ip (default: 10)
    pub msg_rate: u32,                // --msg-rate (default: 120)
    pub bw_rate: u64,                 // --bw-rate (default: 1048576)
    pub max_payload: usize,           // --max-payload (default: 65535)
    pub admit_timeout: u64,           // --admit-timeout (default: 5)
    pub ping_interval: u64,           // --ping-interval (default: 30)
    pub idle_timeout: u64,            // --idle-timeout (default: 120)
    pub pow_difficulty: u8,           // --pow-difficulty (default: 16)
}
```

## arpc — Client Daemon

Persistent WebSocket client with local JSON API.

### Daemon Startup Flow

1. Load config (TOML file → env `ARPC_*` → CLI overrides)
2. Load or generate Ed25519 keypair (`~/.config/arpc/key`)
3. Start local API listener (TCP or Unix socket)
4. Spawn relay connection pool (coordinator + N workers)
5. Block on local API accept loop

### Relay Connection

`relay.rs` — `spawn_relay_pool()`: Creates a multi-relay connection pool with a coordinator and N workers.

**Coordinator Task** (`relay_coordinator`):
- Receives `OutboundMsg` via channel from local API
- Seals HPKE payload once ( Auth mode encryption)
- Builds ROUTE frame with encrypted payload
- Fans out to all worker channels via `try_send()` (non-blocking)
- Collects STATUS responses from workers with 5s timeout
- Aggregates status: `DELIVERED > RATE_LIMITED > OVERSIZE > OFFLINE > timeout`
- Returns first successful result to caller

**N Worker Tasks** (`relay_worker` + `relay_worker_connection`):
- Each worker manages one persistent WebSocket to a single relay
- Independent exponential backoff with jitter per relay
- Independent keepalive/ping handling per connection
- Receives pre-built ROUTE commands from coordinator via channel
- Sends STATUS reports back to coordinator via reply channel
- Handles incoming DELIVER frames, uses shared deduplicator

**`RelayPool` Struct**: Returned by `spawn_relay_pool()`, holds:
- Coordinator handle (mpsc channel for outgoing messages)
- Worker join handles (for graceful shutdown)
- Per-relay status receivers (watch channels for connection state)

**Send Strategies**:
- **Fan-out mode** (default): Non-blocking `try_send()` to all relay channels simultaneously. First `DELIVERED` resolves immediately.
- **Sequential mode**: Tries relays one by one until `DELIVERED` or all exhausted.

**Deduplication**: Shared `Arc<Mutex<Deduplicator>>` across all workers for receiver-side dedup:
- Fast-path check before HPKE decrypt (rejects duplicates early)
- Insert after successful decrypt (prevents cache poisoning from malicious payloads)

**Aggregate Connection Status**:
- `Connected`: If ANY relay is connected
- `Connecting`: If any relay is connecting (and none connected)
- `Disconnected`: If ALL relays are disconnected

`perform_relay_handshake()` handles admission per relay:
1. Receive Challenge frame
2. Sign `challenge ‖ timestamp`
3. Solve PoW if difficulty > 0
4. Send Response frame
5. Wait for Admitted/Rejected

### HPKE Encryption

`hpke_seal.rs` — `HpkeAuthEncryption`:

Algorithm: X25519-HKDF-SHA256 / ChaCha20Poly1305 (RFC 9180 Auth mode)

Key conversion: Ed25519 → X25519 via birational map (uses `to_scalar_bytes()`, `to_montgomery()`)

Stateless per-message encryption (no sessions, no handshake state):
 Each message encrypted independently with fresh ephemeral key
 Authenticated sender identity via Auth mode (sender's static X25519 key)
 No LRU cache, no session table, no eviction logic
Message prefixes (protocol-defined; receiver dispatches via `encryption.enabled` config flag, not prefix inspection):
 `0x00` — plaintext (raw bytes; no prefix prepended when encryption disabled)
 `0x04` — HPKE Auth encrypted (X25519 ephemeral | encrypted payload | auth tag)

### Local JSON API

`local_api.rs` — line-delimited JSON over TCP or Unix socket.

Protocol: each line is a JSON command. Response written as single line.

Max command length: 1,048,576 bytes (`MAX_CMD_LEN`).

Commands (see full reference below).

### Contact Management

`contacts.rs` — `ContactStore`:

- Persistent TOML storage (`~/.config/arpc/contacts.toml`)
- Filter modes: `ContactsOnly` (default) or `AcceptAll`
- Inbound messages from unknown senders dropped unless `AcceptAll`

### Webhook Push

`webhook.rs` — `WebhookClient`:

- Fire-and-forget HTTP POST for each inbound message
- JSON payload includes sender (base58), message (base64), timestamp
- Configurable URL, Bearer token, channel identifier

### Bridge (OpenClaw Gateway)

`bridge.rs` — WebSocket connection to OpenClaw gateway:

- Injects inbound ARP messages as `chat.send` protocol v3
- Authenticates with gateway token
- Targets specific session via session key

### Configuration

`config.rs` — `ClientConfig` (TOML format):

```toml
relay = "wss://arps.offgrid.ing"      # WebSocket relay URL (deprecated, use [[relays]])
listen = "tcp://127.0.0.1:7700"       # Local API bind address

# Multi-relay (recommended for cross-relay communication)
# relay = "wss://arps.offgrid.ing"     # legacy single-relay (still works)
[[relays]]
url = "wss://relay1.example.com"
# pubkey = "optional-base58-pubkey"     # pin relay identity

[[relays]]
url = "wss://relay2.example.com"

send_strategy = "fan_out"               # or "sequential"


[reconnect]
initial_delay_ms = 100                # First reconnect delay
max_delay_ms = 30000                  # Cap at 30s
backoff_factor = 2.0                  # Exponential multiplier

[keepalive]
interval_s = 30                       # WebSocket ping interval

[encryption]
enabled = true                        # Enable HPKE Auth encryption

[webhook]
enabled = false                       # HTTP push for inbound messages
url = "http://127.0.0.1:18789/hooks/agent"
token = ""                            # Bearer token
channel = "discord"

[bridge]
enabled = false                       # OpenClaw gateway integration
gateway_url = "ws://127.0.0.1:18789"
gateway_token = ""                    # Gateway auth token
session_key = ""                      # Target session identifier
```

Config resolution order: defaults → TOML file → env vars (`ARPC_*`) → CLI flags.

## Local API Reference

All commands are JSON objects with `"cmd"` field. Responses are single-line JSON.

| Command | Request | Response |
|---------|---------|----------|
| **send** | `{"cmd":"send","to":"<base58-pubkey>","payload":"<base64>"}` | `{"status":"sent","error":null}` or `{"status":"error","error":"..."}` |
| **recv** | `{"cmd":"recv","timeout_ms":5000}` (optional) | `{"from":"<base58>","payload":"<base64>","received_at":"<RFC3339>"}` or `{"error":"..."}` |
| **identity** | `{"cmd":"identity"}` | `{"identity":"<base58-pubkey>","connected":true/false}` |
| **status** | `{"cmd":"status"}` | `{"status":"connected","uptime_secs":N,"messages_sent":N,"messages_received":N,"relays":[{"url":"...","status":"connected"},...]}`  |
| **subscribe** | `{"cmd":"subscribe"}` | Stream of messages, starting with `{"subscribed":true}` |
| **contact_add** | `{"cmd":"contact_add","name":"Alice","pubkey":"<base58>","notes":"..."}` | `{"status":"added","name":"...","pubkey":"..."}` or `{"error":"..."}` |
| **contact_remove** | `{"cmd":"contact_remove","name":"Alice"}` or `{"pubkey":"<base58>"}` | `{"status":"removed","name":"...","pubkey":"..."}` or `{"error":"..."}` |
| **contact_list** | `{"cmd":"contact_list"}` | `{"contacts":[...],"filter_mode":"contacts_only"}` |
| **contact_lookup** | `{"cmd":"contact_lookup","name":"Alice"}` or `{"pubkey":"<base58>"}` | Contact object or `{"error":"not found"}` |
| **filter_mode** | `{"cmd":"filter_mode","mode":"accept_all"}` (or null to query) | `{"filter_mode":"accept_all"}` or error |

Status codes for send:
- `0x00` DELIVERED → "sent"
- `0x01` OFFLINE → "recipient is offline"
- `0x02` RATE_LIMITED → "rate limited by relay"
- `0x03` OVERSIZE → "payload too large"
- Timeout → "sent" (backwards compatibility)

## Configuration Reference (arpc)

Full TOML schema with defaults:

```toml
# Required fields (have defaults)
relay = "wss://arps.offgrid.ing"           # deprecated, use [[relays]] below
listen = "tcp://127.0.0.1:7700"

# Multi-relay configuration (recommended)
[[relays]]
url = "wss://relay1.example.com"
# pubkey = "optional-base58-pubkey"        # pin relay identity

[[relays]]
url = "wss://relay2.example.com"

send_strategy = "fan_out"                  # "fan_out" or "sequential"


[reconnect]
initial_delay_ms = 100
max_delay_ms = 30000
backoff_factor = 2.0

[keepalive]
interval_s = 30

[encryption]
enabled = true

[webhook]
enabled = false
url = "http://127.0.0.1:18789/hooks/agent"
token = ""
channel = "discord"

[bridge]
enabled = false
gateway_url = "ws://127.0.0.1:18789"
gateway_token = ""
session_key = ""
```

Validation rules:
- `relay` (deprecated) or `relays[].url` must start with `ws://` or `wss://`
- At least one relay must be configured (via `relay` or `relays`)
- If both `relay` and `relays` are set, `relays` takes precedence
- `listen` must start with `tcp://` or `unix://`
- `reconnect.initial_delay_ms` must be > 0
- `reconnect.max_delay_ms` must be >= `initial_delay_ms`
- `reconnect.backoff_factor` must be > 0.0
- `keepalive.interval_s` must be > 0
- If `webhook.enabled = true`, `webhook.token` must be non-empty
- If `bridge.enabled = true`, `bridge.gateway_token` and `bridge.session_key` must be non-empty, `gateway_url` must use ws/wss scheme

Config directory resolution (in order):
1. `$XDG_CONFIG_HOME/arpc`
2. `~/.config/arpc` if it exists
3. Platform config dir + `/arpc`

## Server Configuration Reference (arps)

CLI arguments with defaults:

```
arps [OPTIONS]

Options:
  -l, --listen <ADDR>          Bind address for WebSocket server [default: 0.0.0.0:8080]
      --metrics-addr <ADDR>    Prometheus metrics endpoint [default: 0.0.0.0:9090]
      --max-conns <N>          Maximum concurrent connections [default: 10000]
      --max-conns-ip <N>       Maximum connections per IP [default: 10]
      --msg-rate <N>           Messages per minute per agent [default: 120]
      --bw-rate <BYTES>        Bytes per minute per agent [default: 1048576]
      --max-payload <BYTES>    Maximum payload size [default: 65535]
      --admit-timeout <SECS>   Admission handshake timeout [default: 5]
      --ping-interval <SECS>   Keepalive ping interval [default: 30]
      --idle-timeout <SECS>    Disconnect after idle [default: 120]
      --pow-difficulty <BITS>  PoW difficulty (0 to disable) [default: 16]
  -h, --help                   Print help
  -V, --version                Print version
```

## Data Flow Diagrams

### Send Path (with HPKE Encryption)

```
┌─────────────┐     JSON      ┌─────────────┐   No encryption?   ┌─────────────────┐
│ Local Agent │───send cmd───►│  Local API  │────────────────────►│ HpkeAuthEncrypt │
└─────────────┘               └──────┬──────┘                     │    .seal()      │
                                     │                            └────────┬────────┘
                                     │                                     │
                                     │ ◄─────────encrypted payload───────────────┘
                                     │
                                     │ Route frame
                                     ▼
┌─────────────┐     WSS      ┌──────────────┐     WSS      ┌──────────────┐
│    arpc     │◄────────────►│  Relay (arps)│◄────────────►│   Recipient  │
│  relay.rs   │   (encrypted)│   router.rs  │            │    arpc      │
└─────────────┘              └──────────────┘            └──────────────┘
                                     │
                                     │ Deliver frame
                                     ▼
                              ┌──────────────┐
                              │   Recipient  │
                              │  hpke_seal.rs
                              │  decrypt_open │
                              └──────────────┘
```

### Receive Path

```
┌─────────────┐     Deliver frame     ┌─────────────┐
│Relay (arps) │──────────────────────►│    arpc     │
│ (router.rs) │                       │  relay.rs   │
└─────────────┘                       └──────┬──────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
             ┌────────────┐          ┌────────────┐           ┌────────────┐
             │    HPKE      │
             │ decrypt    │          │  filter    │           │   POST     │
             └─────┬──────┘          └─────┬──────┘           └─────┬──────┘
                   │                       │                        │
                   ▼                       ▼                        ▼
            ┌────────────┐          ┌────────────┐           ┌────────────┐
            │ Broadcast  │          │  Drop or   │           │  HTTP to   │
            │  channel   │          │  deliver   │           │  endpoint  │
            └─────┬──────┘          └────────────┘           └────────────┘
                  │
        ┌─────────┴──────────┐
        │                    │
        ▼                    ▼
 ┌────────────┐      ┌────────────┐
 │  recv cmd  │      │ subscribe  │
 │  response  │      │  stream    │
 └────────────┘      └────────────┘
```

### Admission Flow

```
Client (arpc)                                    Server (arps)
     │                                                  │
     │─────── WebSocket upgrade (Sec-WebSocket-Protocol: arp.v2) ─────►│
     │                                                  │
     │◄──────────────── Challenge(32B, server_pk, difficulty) ────────│
     │                                                  │
     │  1. Verify timestamp within ±30s                 │
     │  2. Sign: Ed25519(challenge ‖ timestamp)         │
     │  3. If difficulty > 0: solve PoW                 │
     │                                                  │
     │──── Response(pubkey, timestamp, signature, nonce?) ─────────────►│
     │                                                  │
     │                                          (admission.rs)
     │                                          1. Verify timestamp
     │                                          2. Verify signature
     │                                          3. Verify PoW
     │                                                  │
     │◄──────────────── Admitted or Rejected(code) ────────────────────│
     │                                                  │
     │                                         Insert into Router
     │                                         Spawn message loop
```

## Module Dependencies

```
arp-common
    └─▶ ed25519-dalek, sha2, hpke, thiserror

arps
    ├─▶ arp-common
    ├─▶ tokio (full), tokio-tungstenite, dashmap
    ├─▶ axum, metrics-exporter-prometheus
    └─▶ tracing, clap

arpc
    ├─▶ arp-common
    ├─▶ tokio (full), tokio-tungstenite, hpke
    ├─▶ reqwest
    └─▶ tracing, clap, config, toml
```

All crates compile with `#![forbid(unsafe_code)]`.

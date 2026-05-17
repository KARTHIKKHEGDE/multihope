# ARCHITECTURE.md
> Responsibility boundaries for every layer of the system.
> Last updated: 2026-05-16

---

## Folder Structure

```text
multihop_project/
|-- backend/
|   |-- app.py              # Flask server: API routes and static frontend serving only
|   |-- config.py           # All ports, IPs, thresholds, and demo constants
|   |-- bb84.py             # BB84 key exchange simulation and safe teaching previews
|   |-- crypto_utils.py     # AES encrypt/decrypt helpers
|   |-- attack_detector.py  # Error checks, nonce replay detection, MITM flagging
|   |-- router.py           # Routing table and reroute decisions
|   |-- logger.py           # Structured in-memory event store
|   |-- sender.py           # Entry point: plaintext into hop chain
|   |-- node.py             # Generic hop: BB84 rekey, decrypt, encrypt, forward
|   `-- receiver.py         # Final endpoint and TCP receiver server
|-- frontend/
|   |-- src/
|   |   |-- App.jsx         # Root polling loop
|   |   |-- api/
|   |   |   `-- client.js   # All fetch() calls to /api/*
|   |   |-- components/
|   |   |   |-- HopFlow.jsx
|   |   |   |-- MetricCards.jsx
|   |   |   |-- LiveLog.jsx
|   |   |   |-- ErrorRateBar.jsx
|   |   |   |-- AttackControls.jsx
|   |   |   `-- NodeSimulation.jsx # Step-mode BB84/AES teaching trace
|   |   `-- main.jsx
|   |-- index.html
|   |-- package.json
|   `-- vite.config.mjs
|-- tests/
|   |-- test_app.py
|   |-- test_attack_detector.py
|   |-- test_bb84.py
|   |-- test_config.py
|   |-- test_crypto_utils.py
|   |-- test_integration.py
|   |-- test_logger.py
|   |-- test_node.py
|   |-- test_receiver.py
|   |-- test_router.py
|   `-- test_sender.py
|-- AI_CONTRACT.md
|-- ARCHITECTURE.md
`-- DECISIONS.md
```

---

## Layer Responsibilities

### Backend Domain Layer

Backend modules own all security, routing, attack detection, and simulation behavior. They do not know how React renders the result.

| Module | Owns | Does not own |
|---|---|---|
| `bb84.py` | Bit generation, basis selection, measurement, sifting, error rate, safe preview metadata | AES, sockets, routing, UI rendering |
| `crypto_utils.py` | AES-256-CBC encrypt/decrypt and key derivation helper | BB84, sockets, routing, UI rendering |
| `attack_detector.py` | Error threshold decisions, nonce replay store, MITM flag detection, attack mode | Rerouting, UI rendering |
| `router.py` | Active route table, block/unblock nodes, next-hop calculation | Crypto, BB84, detection logic |
| `logger.py` | Structured `{time, source, message, status, ...metadata}` event store | HTTP, rendering, crypto |
| `sender.py` | Initial packet creation, first BB84 key, first AES encrypt, sender logs | Flask routes, React rendering |
| `node.py` | Generic hop processing: BB84 rekey, detection, AES decrypt/encrypt, forward, TCP delivery to receiver | Per-node duplicated files, UI rendering |
| `receiver.py` | Final AES decrypt, receive event, `run_receiver_server()` socket listener | Routing, UI rendering |
| `config.py` | `HOST`, `API_PORT`, `NODE_PORTS`, thresholds, TTLs, demo constants | Everything else |

### Flask API Layer

`backend/app.py` is a thin shell. Routes should call backend modules and return JSON.

```text
GET  /api/events   -> logger.get_events()
POST /api/send     -> sender.send_message(message)
POST /api/attack   -> attack_detector.set_attack_mode(mode)
POST /api/reset    -> reset detector, router, and logs
GET  /api/status   -> router.get_node_statuses()
GET  /             -> serve built React dashboard
```

Routes must not contain crypto, BB84, attack detection, or routing logic.

### Frontend UI Layer

React renders state from `/api/*`. It does not perform security decisions.

| Component | Renders | Does not do |
|---|---|---|
| `HopFlow.jsx` | Node boxes colored by `/api/status` | Decide if a node is attacked |
| `MetricCards.jsx` | Counts from events aggregated in `client.js` | Crypto, BB84, routing |
| `LiveLog.jsx` | Raw event feed | Modify backend events |
| `ErrorRateBar.jsx` | Latest emitted error rate | Calculate BB84 error rate |
| `AttackControls.jsx` | Attack mode buttons | Know attack internals |
| `NodeSimulation.jsx` | Per-node BB84/AES logs, BB84 basis table, step mode | Generate keys, encrypt/decrypt, detect attacks |
| `client.js` | Fetch calls and minor event aggregation | Domain logic |

`App.jsx` owns the single polling loop. It polls `/api/events` and `/api/status` every 1000ms and passes data down as props.

---

## Teaching Event Metadata

The dashboard displays explanatory metadata emitted by backend modules. These fields are for visualization only.

BB84 event metadata:

- `phase: "bb84"`
- `generatedBits`
- `matchingBases`
- `siftedBits`
- `comparedBits`
- `errorRate`
- `aliceBitPreview`
- `bobBitPreview`
- `aliceBasisPreview`
- `bobBasisPreview`
- `keepPreview`
- `siftedPreview`
- `keyFingerprint`

AES event metadata:

- `phase: "aes-encrypt"` or `phase: "aes-decrypt"`
- `plaintextLength`
- `ivPreview`
- `ciphertextPreview`
- `keyFingerprint`

Only previews and fingerprints are emitted. Full AES keys and full sensitive internals must not be exposed to the frontend.

---

## Data Flow: Normal Message

```text
User clicks Send in React
  -> POST /api/send {message}
    -> app.py calls sender.py
      -> sender establishes BB84 key through bb84.py
      -> sender emits BB84 teaching metadata through logger.py
      -> sender encrypts through crypto_utils.py
      -> sender emits AES encrypt metadata through logger.py
      -> sender forwards packet into the route
        -> node.py node1: BB84 rekey -> detect -> AES decrypt -> AES encrypt -> log -> forward
          -> node.py node2: BB84 rekey -> detect -> AES decrypt -> AES encrypt -> log -> forward
            -> node.py node3: BB84 rekey -> detect -> AES decrypt -> AES encrypt -> log
              -> node.py sends packet over TCP to config.RECEIVER_IP:config.NODE_PORTS["receiver"]
                -> receiver.py run_receiver_server(): accept packet -> AES decrypt -> log -> return plaintext
React polls /api/events
  -> LiveLog shows chronological events
  -> MetricCards and ErrorRateBar update
  -> NodeSimulation shows per-node BB84/AES logs and optional Step Mode
```

## Data Flow: Attack Detected

```text
attack_detector.py checks nonce, MITM flag, and BB84 error rate
  -> if attack detected:
      -> logger.py emits event with status="attack"
      -> router.py blocks the offending node
      -> router.py updates active route
React polls /api/status -> HopFlow marks blocked node
React polls /api/events -> LiveLog and NodeSimulation show where detection occurred
```

---

## Two-Laptop Receiver Setup

Laptop A can run the dashboard, sender, and nodes. Laptop B can run the receiver server.

Laptop B:

```powershell
python -m backend.receiver
```

Laptop A:

```powershell
python -m backend.app
```

Configuration lives only in `backend/config.py`.

For a two-laptop Wi-Fi demo:

```python
HOST = "0.0.0.0"              # on Laptop B, bind receiver to all interfaces
RECEIVER_IP = "192.168.1.23"  # on Laptop A, set this to Laptop B's Wi-Fi IPv4
```

`NODE_PORTS["receiver"]` controls the receiver port. Windows Firewall must allow Python inbound traffic on that port on Laptop B.

Tests do not require a real second laptop. They inject a local receiver transport or mock the TCP connection, so no external sockets are opened during the test suite.

---

## What Lives Where

- New crypto algorithm -> `backend/crypto_utils.py`
- New BB84 behavior or preview field -> `backend/bb84.py` plus tests
- New attack type -> `backend/attack_detector.py` plus tests
- New route/reroute behavior -> `backend/router.py` plus tests
- New API endpoint -> thin route in `backend/app.py`
- New receiver socket behavior -> `backend/receiver.py` plus tests
- New final-hop delivery behavior -> `backend/node.py` plus tests
- New dashboard panel -> `frontend/src/components/`
- New fetch call -> `frontend/src/api/client.js`
- New teaching metadata for AES -> emit safe previews from `sender.py`, `node.py`, or `receiver.py`; AES itself stays in `crypto_utils.py`
- New step-through UI behavior -> React component state only; do not add backend `time.sleep()` synchronization
- New config value -> `backend/config.py`

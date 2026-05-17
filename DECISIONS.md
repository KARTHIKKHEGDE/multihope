# DECISIONS.md
> Short records of non-obvious design choices.
> Format: Date - Decision - Why - Alternatives rejected

---

## 001 - Generic `node.py` Instead Of `node1.py`, `node2.py`, `node3.py`
**Date:** project start
**Decision:** A single `node.py` is instantiated for generic hop behavior rather than creating three separate node files.
**Why:** All hops do identical work: BB84 rekey, decrypt, encrypt, forward. One implementation prevents duplicated logic from drifting.
**Alternatives rejected:** Three separate files; a class hierarchy.

---

## 002 - Flask Polling (`/api/events`) Instead Of WebSockets
**Date:** project start
**Decision:** React polls `/api/events` every 1 second via `setInterval`.
**Why:** Polling is simple to implement, debug, and demo. One-second latency is acceptable for this teaching project.
**Alternatives rejected:** WebSockets; Server-Sent Events.
**Revisit if:** The demo needs sub-second updates.

---

## 003 - BB84 Error Threshold Set To 0.15
**Date:** project start
**Decision:** Keys with error rate greater than `0.15` are treated as attack/suspicious.
**Why:** The theoretical BB84 eavesdropping threshold is around 11 percent QBER. `0.15` gives a small simulation buffer while still detecting injected attacks.
**Alternatives rejected:** `0.11` as too tight for demo noise; `0.25` as too permissive.

---

## 004 - Python Backend + React Frontend
**Date:** project start
**Decision:** Flask serves the REST API and React renders the dashboard.
**Why:** A browser dashboard is easier to demo and gives more control over the hop-flow, logs, and teaching panels.
**Alternatives rejected:** Tkinter; terminal-only output; Streamlit.

---

## 005 - Attack Modes Toggled Via API
**Date:** project start
**Decision:** `POST /api/attack {"mode": "mitm"}` changes the attack mode.
**Why:** This allows live demo toggling without editing source files or restarting node scripts.
**Alternatives rejected:** Separate attack node scripts; command-line flags only.

---

## 006 - Nonce-Based Replay Detection With TTL
**Date:** project start
**Decision:** Packets include a nonce and timestamp; `attack_detector.py` rejects repeated nonces within `NONCE_TTL_SECONDS`.
**Why:** It is a simple replay prevention model and the TTL prevents unbounded nonce-store growth.
**Alternatives rejected:** Sequence numbers; no replay detection.

---

## 007 - All Config In `config.py`
**Date:** project start
**Decision:** `backend/config.py` holds host, ports, thresholds, TTLs, and demo constants.
**Why:** One source of truth keeps source files free of scattered IPs/ports and follows the AI contract.
**Alternatives rejected:** `.env` parsing; hardcoded values in each module.

---

## 008 - Safe Teaching Metadata In Events
**Date:** 2026-05-16
**Decision:** Backend modules emit BB84/AES preview metadata through `logger.py` for the dashboard.
**Why:** The simulator needs to explain how BB84 and AES work at each node, but React must not implement crypto or BB84 logic. Event metadata lets the frontend render the explanation while backend modules remain the source of truth.
**Alternatives rejected:** Recomputing BB84 tables in React; exposing full keys/ciphertexts; adding separate teaching-only APIs.

---

## 009 - Show Key Fingerprints, Not Full Keys
**Date:** 2026-05-16
**Decision:** Logs display short `keyFingerprint` values instead of full AES keys.
**Why:** Fingerprints let users see that each hop has a distinct key without leaking full secret material into the UI.
**Alternatives rejected:** Showing full keys; hiding all key identity.

---

## 010 - Step Mode Is Frontend-Only
**Date:** 2026-05-16
**Decision:** `NodeSimulation.jsx` reveals already-emitted events one step at a time.
**Why:** Step mode is a teaching view, not a network synchronization mechanism. Keeping it in React avoids backend sleeps and keeps tests fast/deterministic.
**Alternatives rejected:** Adding `time.sleep()` between backend stages; creating separate step-mode backend endpoints.

---

## 011 - Deterministic Eavesdrop Demo
**Date:** 2026-05-16
**Decision:** Eavesdrop mode uses `EAVESDROP_BIT_FLIP_RATE = 1.0` from `config.py`.
**Why:** The viva/demo should reliably show BB84 error detection instead of depending on random chance.
**Alternatives rejected:** Random 0.3 flip rate; manually editing node behavior during demo.

---

## 012 - TCP Only For Final Receiver Hop
**Date:** 2026-05-16
**Decision:** `node3` sends the final packet over TCP to `config.RECEIVER_IP:config.NODE_PORTS["receiver"]`, and `receiver.py` exposes `run_receiver_server()`.
**Why:** This supports the two-laptop demo where Laptop A runs the sender/nodes/dashboard and Laptop B runs the receiver, without turning every internal hop into a distributed deployment problem.
**Alternatives rejected:** Keeping receiver in-process only; making all hops remote sockets immediately; adding hardcoded receiver addresses in node code.

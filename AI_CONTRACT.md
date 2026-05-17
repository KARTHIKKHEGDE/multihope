# AI_CONTRACT.md

> Non-negotiable rules for this project. Every contributor (human or AI) must follow these.
> Last updated: project start

---

## 1. No one-off hacks

- No inline crypto logic inside node files. All encryption, decryption, and key generation must go through `backend/crypto_utils.py` and `backend/bb84.py`. If you are tempted to write `AES.new(...)` inside `node1.py`, stop — add a function to `crypto_utils.py` instead.
- No hardcoded IP addresses or port numbers anywhere in source files. All network config lives in `backend/config.py`. Nodes read from there.
- No `time.sleep()` used as a synchronisation mechanism. Use proper socket blocking or threading events.
- No `except: pass` anywhere. Every exception must be logged at minimum. Silent failures make attack detection impossible.

## 2. Where domain logic must live

| Concern                         | Must live in                        | Must NOT live in                                          |
| ------------------------------- | ----------------------------------- | --------------------------------------------------------- |
| AES encrypt / decrypt           | `backend/crypto_utils.py`           | Any node file, dashboard, React component                 |
| BB84 key generation + sifting   | `backend/bb84.py`                   | Any node file, tests (call the module, don't reimplement) |
| Attack detection logic          | `backend/attack_detector.py`        | Node files inline, frontend                               |
| Port / IP config                | `backend/config.py`                 | Hardcoded anywhere                                        |
| Log event emission to dashboard | `backend/logger.py`                 | Scattered POST calls in each node                         |
| UI state / rendering            | React components in `frontend/src/` | Flask routes, node files                                  |
| Flask API routes                | `backend/app.py`                    | Separate files per route (keep it simple)                 |

## 3. Testing requirements

- **No module is merged without a passing test file.** Every `backend/*.py` module must have a corresponding `tests/test_<module>.py`.
- Minimum coverage per module:
  - `bb84.py` — test normal sifting, error rate below threshold, error rate above threshold, eavesdropper bit-flip scenario
  - `crypto_utils.py` — test encrypt→decrypt roundtrip, wrong key fails, empty message
  - `attack_detector.py` — MITM flag triggers, replay nonce detection, clean pass-through
  - Node integration — send a message through all hops, verify receiver gets correct plaintext
- Tests run with `pytest` from the project root. No custom runners.
- Tests must not open real sockets to external IPs. Use `localhost` and ephemeral ports only.

## 4. Frontend rules

- React components must not contain business logic. A component computing an error rate is wrong.
- All data comes from the Flask API via `/api/*` endpoints. No component fetches from a hardcoded port directly.
- Dashboard polls `/api/events` every 1 second. No WebSockets unless recorded in `DECISIONS.md`.
- No `console.log` in committed code.

## 5. Attack simulation rules

- Attack modes are toggled via the Flask API (`POST /api/attack`), not by editing node source files.
- Simulated attacks must be labelled in log events with `"status": "attack"` so the dashboard can colour them.
- Rerouting logic lives in `backend/router.py`. Nodes do not make routing decisions themselves.

## 6. What AI assistants may do

- Generate new functions inside the correct module files listed in rule 2.
- Write test files following the conventions in rule 3.
- Suggest additions to `DECISIONS.md` when a non-obvious choice is made.
- Refactor within a module boundary.

## 7. What AI assistants must NOT do

- Create a new file that duplicates logic already owned by an existing module.
- Modify `AI_CONTRACT.md`, `ARCHITECTURE.md`, or `DECISIONS.md` without explicit instruction.
- Skip writing a test because "it's a simple function."
- Never guess implementation ask the user for inputs in such case

import { Shield, RadioTower, Repeat, UserRoundX, AlertTriangle, Info } from "lucide-react";
import { setAttackMode } from "../api/client.js";

const modes = [
  {
    id: "normal",
    label: "Normal",
    Icon: Shield,
    description: "Secure transmission - BB84 keys are exchanged honestly, no interference.",
    color: "teal",
  },
  {
    id: "mitm",
    label: "MITM",
    Icon: UserRoundX,
    description: "Man-in-the-Middle - attacker tampers with ciphertext; receiver blocks it when AES integrity verification fails.",
    color: "red",
  },
  {
    id: "eavesdrop",
    label: "Eavesdrop",
    Icon: RadioTower,
    description: "Eve measures qubits in random bases, introducing detectable bit errors (~25%).",
    color: "orange",
  },
  {
    id: "replay",
    label: "Replay",
    Icon: Repeat,
    description: "Attacker re-sends a previously captured packet - detected by nonce duplication.",
    color: "purple",
  },
];

const nodes = [
  { id: "node1", label: "Node 1" },
  { id: "node2", label: "Node 2" },
  { id: "node3", label: "Node 3" },
];

export default function AttackControls({ currentMode, targetNode, onChange }) {
  async function chooseMode(mode) {
    await setAttackMode(mode, targetNode);
    await onChange();
  }

  async function chooseTarget(event) {
    const newTarget = event.target.value;
    await setAttackMode(currentMode, newTarget);
    await onChange();
  }

  const activeMode = modes.find((m) => m.id === currentMode) || modes[0];
  const isAttack = currentMode !== "normal";

  return (
    <section className="panel">
      <div className="panelHeader">
        <h2>Attack Controls</h2>
        {isAttack && (
          <span className="attackBadge">
            <AlertTriangle size={14} />
            {activeMode.label} Active
          </span>
        )}
      </div>

      <div className="targetNodeSelector">
        <label htmlFor="targetNode">Target Node:</label>
        <select id="targetNode" value={targetNode} onChange={chooseTarget} disabled={!isAttack}>
          {nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.label}
            </option>
          ))}
        </select>
      </div>

      <div className="controlGrid">
        {modes.map((mode) => (
          <button
            key={mode.id}
            type="button"
            className={`attackBtn ${mode.id} ${currentMode === mode.id ? "active" : ""}`}
            onClick={() => chooseMode(mode.id)}
          >
            <mode.Icon size={18} />
            {mode.label}
          </button>
        ))}
      </div>
      <div className={`attackDescription ${isAttack ? "warning" : ""}`}>
        <Info size={14} />
        <p>{activeMode.description}</p>
      </div>
    </section>
  );
}

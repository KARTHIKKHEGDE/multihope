import { useState } from "react";
import { Shield, RadioTower, Repeat, UserRoundX, AlertTriangle, Info, Terminal, KeyRound } from "lucide-react";
import { setAttackMode, submitMitmGuess } from "../api/client.js";

const modes = [
  {
    id: "normal",
    label: "Normal",
    Icon: Shield,
    description: "Secure transmission — BB84 keys are exchanged honestly, no interference.",
    color: "teal",
  },
  {
    id: "mitm",
    label: "MITM",
    Icon: UserRoundX,
    description: "Man-in-the-Middle — attacker intercepts and re-encrypts, flagged by BB84 mismatch.",
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
    description: "Attacker re-sends a previously captured packet — detected by nonce duplication.",
    color: "purple",
  },
];

const nodes = [
  { id: "node1", label: "Node 1" },
  { id: "node2", label: "Node 2" },
  { id: "node3", label: "Node 3" },
];

export default function AttackControls({ currentMode, targetNode, intercepted, onChange }) {
  const [guess, setGuess] = useState("");
  const [mitmResult, setMitmResult] = useState(null);

  async function chooseMode(mode) {
    await setAttackMode(mode, targetNode);
    await onChange();
  }

  async function chooseTarget(event) {
    const newTarget = event.target.value;
    await setAttackMode(currentMode, newTarget);
    await onChange();
  }

  async function handleGuess(e) {
    e.preventDefault();
    if (!guess.trim()) return;
    const result = await submitMitmGuess(guess.trim());
    setMitmResult(result);
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

      {currentMode === "mitm" && (
        <div className="mitmChallenge">
          <div style={{ padding: "16px" }}>
            <div className="mitmChallengeHeader">
              <Terminal size={18} /> MITM Interception Challenge
            </div>
            
            {intercepted ? (
              <>
                <div className="mitmData">
                  <p><strong>Intercepted at:</strong> {intercepted.node}</p>
                  <p><strong>Ciphertext:</strong> <code>{intercepted.ciphertextPreview}...</code></p>
                  <p><strong>IV:</strong> <code>{intercepted.ivPreview}...</code></p>
                </div>
                
                <form className="mitmGuessForm" onSubmit={handleGuess}>
                  <input 
                    placeholder="Enter 256-bit hex key guess..." 
                    value={guess}
                    onChange={(e) => setGuess(e.target.value)}
                  />
                  <button type="submit"><KeyRound size={16} /> Decrypt</button>
                </form>

                {mitmResult && (
                  <div className={`mitmResult ${mitmResult.success ? "success" : "fail"}`}>
                    {mitmResult.success ? "✅ " : "❌ "}
                    {mitmResult.message}
                  </div>
                )}
              </>
            ) : (
              <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
                Waiting to intercept a packet... Send a message to capture data.
              </p>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

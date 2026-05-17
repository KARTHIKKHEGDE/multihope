import React, { useEffect, useMemo, useState } from "react";
import { RotateCcw, Send, Shield, Wifi, Monitor, Radio, ShieldAlert, UserRoundX, RadioTower, Repeat } from "lucide-react";
import {
  fetchEvents, fetchStatus, fetchPeers, fetchInbox,
  resetDemo, sendToPeer, clearInbox, summarizeEvents,
} from "./api/client.js";
import PeerList from "./components/PeerList.jsx";
import InboxPanel from "./components/InboxPanel.jsx";
import MetricCards from "./components/MetricCards.jsx";
import HopFlow from "./components/HopFlow.jsx";
import ErrorRateBar from "./components/ErrorRateBar.jsx";
import LiveLog from "./components/LiveLog.jsx";
import PacketJourney from "./components/PacketJourney.jsx";
import AttackControls from "./components/AttackControls.jsx";

const attackModes = [
  { id: "normal", label: "Normal send", Icon: Shield, color: "teal", desc: "All 3 hops forward the encrypted packet safely. Receiver decrypts it." },
  { id: "mitm", label: "Random MITM", Icon: UserRoundX, color: "red", desc: "One hop tampers with ciphertext. Receiver blocks when AES HMAC integrity verification fails." },
  { id: "eavesdrop", label: "Eavesdrop", Icon: RadioTower, color: "orange", desc: "An eavesdropper disturbs BB84 measurements. Receiver blocks when QBER exceeds the threshold." },
  { id: "replay", label: "Replay", Icon: Repeat, color: "purple", desc: "The same encrypted packet is resent. Receiver blocks when the nonce is already in the replay cache." },
];

function getReceiverResult(sendResult) {
  return sendResult?.result?.result || sendResult?.result || sendResult;
}

function NodeCrypto({ step, crypto }) {
  const nodeCrypto = step.crypto || {};
  const bb84 = nodeCrypto.bb84 || {};
  if (nodeCrypto.action) {
    return (
      <div className="nodeCrypto">
        {nodeCrypto.decryptedPreview && <p><span>Decrypted</span><code>{nodeCrypto.decryptedPreview}</code></p>}
        {nodeCrypto.plaintextPreview && <p><span>Plaintext</span><code>{nodeCrypto.plaintextPreview}</code></p>}
        {nodeCrypto.aesKeyFingerprint && <p><span>New AES key</span><code>{nodeCrypto.aesKeyFingerprint}... ({nodeCrypto.aesKeyLengthBits} bits)</code></p>}
        {nodeCrypto.ivPreview && <p><span>New IV</span><code>{nodeCrypto.ivPreview}...</code></p>}
        {nodeCrypto.ciphertextPreview && <p><span>New ciphertext</span><code>{nodeCrypto.ciphertextPreview}...</code></p>}
        {nodeCrypto.tagPreview && <p><span>AES HMAC tag</span><code>{nodeCrypto.tagPreview}...</code></p>}
        {nodeCrypto.payload?.ciphertext && <p><span>Incoming ciphertext</span><code>{nodeCrypto.payload.ciphertext.slice(0, 40)}...</code></p>}
        {bb84.aliceBasisPreview && <p><span>BB84 bases</span><code>Alice {bb84.aliceBasisPreview} | Bob {bb84.bobBasisPreview}</code></p>}
        {bb84.aliceBitPreview && <p><span>Bits</span><code>Alice {bb84.aliceBitPreview} | Bob {bb84.bobBitPreview}</code></p>}
        {bb84.keepPreview && <p><span>Keep / sifted</span><code>{bb84.keepPreview} / {bb84.siftedPreview}</code></p>}
        {bb84.matchingBases && <p><span>BB84 counts</span><code>{bb84.matchingBases} matching, {bb84.siftedBits} sifted, {bb84.comparedBits} compared</code></p>}
        {bb84.errorRate !== undefined && <p><span>Error rate</span><code>{Math.round((bb84.errorRate || 0) * 100)}% / {Math.round((bb84.errorThreshold || 0.15) * 100)}%</code></p>}
        {nodeCrypto.nonce && <p><span>Nonce</span><code>{nodeCrypto.nonce.slice(0, 24)}...</code></p>}
        {nodeCrypto.mode && <p><span>Mode seen</span><code>{nodeCrypto.mode}</code></p>}
        {nodeCrypto.blockedReason && <p><span>Blocked reason</span><code>{nodeCrypto.blockedReason}</code></p>}
        {nodeCrypto.note && <p><span>What happened</span><code>{nodeCrypto.note}</code></p>}
      </div>
    );
  }

  if (!crypto?.nonce) return null;
  const sender = crypto.senderBB84 || {};
  const receiver = crypto.receiverBB84 || {};
  const node = (step.node || "").toLowerCase();

  if (node.includes("sender")) {
    return (
      <div className="nodeCrypto">
        <p><span>Plaintext</span><code>{crypto.senderPlaintextPreview || crypto.plaintextPreview || "message typed by sender"}</code></p>
        <p><span>AES key</span><code>{crypto.aesKeyFingerprint}... ({crypto.aesKeyLengthBits} bits)</code></p>
        <p><span>IV</span><code>{crypto.ivPreview}...</code></p>
        <p><span>Ciphertext</span><code>{crypto.ciphertextPreview}...</code></p>
        {crypto.tagPreview && <p><span>AES HMAC tag</span><code>{crypto.tagPreview}...</code></p>}
        <p><span>BB84 bases</span><code>Alice {sender.aliceBasisPreview} | Bob {sender.bobBasisPreview}</code></p>
        <p><span>Bits</span><code>Alice {sender.aliceBitPreview} | Bob {sender.bobBitPreview}</code></p>
        <p><span>Keep / sifted</span><code>{sender.keepPreview} / {sender.siftedPreview}</code></p>
      </div>
    );
  }

  if (node.includes("hop")) {
    return (
      <div className="nodeCrypto">
        <p><span>Packet state</span><code>Encrypted only; hop cannot read plaintext</code></p>
        <p><span>Carrying</span><code>nonce {crypto.nonce.slice(0, 16)}... + ciphertext {crypto.ciphertextPreview}...</code></p>
      </div>
    );
  }

  if (node.includes("receiver check")) {
    return (
      <div className="nodeCrypto">
        <p><span>Nonce check</span><code>{crypto.nonce.slice(0, 24)}...</code></p>
        <p><span>Mode seen</span><code>{crypto.attackMode || "normal"}</code></p>
      </div>
    );
  }

  if (node.includes("receiver")) {
    return (
      <div className="nodeCrypto">
        <p><span>Receiver BB84 bases</span><code>Alice {receiver.aliceBasisPreview} | Bob {receiver.bobBasisPreview}</code></p>
        <p><span>Receiver bits</span><code>Alice {receiver.aliceBitPreview} | Bob {receiver.bobBitPreview}</code></p>
        <p><span>Keep / sifted</span><code>{receiver.keepPreview} / {receiver.siftedPreview}</code></p>
        <p><span>BB84 counts</span><code>{receiver.matchingBases} matching, {receiver.siftedBits} sifted, {receiver.comparedBits} compared</code></p>
        <p><span>Error rate</span><code>{Math.round((receiver.errorRate || 0) * 100)}% / {Math.round((receiver.errorThreshold || 0.15) * 100)}%</code></p>
        <p><span>Decryption</span><code>{crypto.decrypted ? `Plaintext: ${crypto.plaintextPreview}` : `Blocked: ${crypto.blockedReason}`}</code></p>
      </div>
    );
  }

  return null;
}

function SendExplanation({ sendResult }) {
  if (!sendResult) return null;
  const receiverResult = getReceiverResult(sendResult);
  const steps = receiverResult?.routeSteps || [];
  const crypto = receiverResult?.cryptoDetails || {};
  const blocked = receiverResult?.attackDetected || receiverResult?.ok === false;

  return (
    <div className={`sendExplanation ${blocked ? "blocked" : "delivered"}`}>
      <strong>{blocked ? "Receiver blocked the message" : "Receiver accepted the message"}</strong>
      {receiverResult?.attackType && <p>{receiverResult.attackType}</p>}
      {steps.length > 0 && (
        <ol>
          {steps.map((step, index) => (
            <li key={`${step.node}-${index}`}>
              <span>{index + 1}. {step.node}</span>
              <p>{step.detail}</p>
              <NodeCrypto step={step} crypto={crypto} />
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

export default function App() {
  // Peer state
  const [selfInfo, setSelfInfo] = useState(null);
  const [peers, setPeers] = useState([]);
  const [inboxMessages, setInboxMessages] = useState([]);

  // Send form
  const [message, setMessage] = useState("");
  const [targetIp, setTargetIp] = useState("");
  const [attackMode, setAttackMode] = useState("normal");
  const [busy, setBusy] = useState(false);
  const [sendResult, setSendResult] = useState(null);

  // Existing simulation state
  const [events, setEvents] = useState([]);
  const [statuses, setStatuses] = useState({});
  const [simAttackMode, setSimAttackMode] = useState("normal");
  const [targetNode, setTargetNode] = useState("node1");

  // Tab state
  const [activeTab, setActiveTab] = useState("network");

  async function refreshAll() {
    try {
      const [evts, statusData, peerData, inboxData] = await Promise.all([
        fetchEvents(),
        fetchStatus(),
        fetchPeers(),
        fetchInbox(),
      ]);
      setEvents(evts);
      if (statusData?.nodes) {
        setStatuses(statusData.nodes);
        setSimAttackMode(statusData.attackMode || "normal");
        setTargetNode(statusData.targetNode || "node1");
      }
      if (statusData?.self) setSelfInfo(statusData.self);
      if (peerData?.self) setSelfInfo(peerData.self);
      setPeers(peerData?.peers || []);
      setInboxMessages(inboxData || []);
    } catch {
      /* offline */
    }
  }

  useEffect(() => {
    refreshAll();
    const iv = setInterval(refreshAll, 2000);
    return () => clearInterval(iv);
  }, []);

  const metrics = useMemo(() => summarizeEvents(events), [events]);

  // Auto-select first peer as target
  useEffect(() => {
    if (!targetIp && peers.length > 0) setTargetIp(peers[0].ip);
  }, [peers, targetIp]);

  async function handleSend(e) {
    e.preventDefault();
    if (!message.trim() || !targetIp) return;
    setBusy(true);
    setSendResult(null);

    const targetPeerObj = peers.find((p) => p.ip === targetIp);
    const targetSocketPort = targetPeerObj?.socketPort || 5010;

    try {
      const result = await sendToPeer(
        message.trim(), targetIp, targetSocketPort,
        attackMode, "", 5010
      );
      setSendResult(result);
      setMessage("");
      setTimeout(refreshAll, 500);
    } catch (err) {
      setSendResult({ ok: false, error: err.message });
    }
    setBusy(false);
  }

  async function handleReset() {
    setBusy(true);
    await resetDemo();
    setSendResult(null);
    await refreshAll();
    setBusy(false);
  }

  const activeAttack = attackModes.find((m) => m.id === attackMode) || attackModes[0];
  const targetPeer = peers.find((p) => p.ip === targetIp);
  const pathText = `Path: You -> Hop 1 -> Hop 2 -> Hop 3 -> ${targetPeer?.name || "receiver"}`;

  return (
    <main className="shell">
      {/* ─── Top Bar ─── */}
      <section className="topbar">
        <div>
          <p className="eyebrow">BB84 Quantum Key Distribution</p>
          <h1>QuantumHop Secure Network</h1>
        </div>
        <div className="topbarRight">
          {selfInfo && (
            <div className="selfBadge">
              <Monitor size={14} />
              <span>{selfInfo.name}</span>
              <code>{selfInfo.ip}</code>
            </div>
          )}
          <button className="iconButton" type="button" onClick={handleReset} aria-label="Reset demo">
            <RotateCcw size={18} />
          </button>
        </div>
      </section>

      {/* ─── Tabs ─── */}
      <div className="tabBar">
        <button
          className={`tab ${activeTab === "network" ? "active" : ""}`}
          onClick={() => setActiveTab("network")}
        >
          <Wifi size={15} />
          Real Network
          {peers.length > 0 && <span className="tabBadge">{peers.length}</span>}
        </button>
        <button
          className={`tab ${activeTab === "simulation" ? "active" : ""}`}
          onClick={() => setActiveTab("simulation")}
        >
          <Radio size={15} />
          Local Simulation
        </button>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* REAL NETWORK TAB                                                   */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {activeTab === "network" && (
        <>
          {/* ─── Send Panel ─── */}
          <section className="panel sendPanel">
            <div className="panelHeader">
              <h2>Send Secure Message</h2>
              {attackMode !== "normal" && (
                <span className="attackBadge">
                  <ShieldAlert size={14} />
                  {activeAttack.label}
                </span>
              )}
            </div>

            <form className="sendForm" onSubmit={handleSend}>
              <div className="sendRow2">
                <input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Type a message to send securely…"
                  aria-label="Message"
                  className="sendInput"
                />
              </div>

              <div className="sendOptions">
                <div className="sendOption">
                  <label>To:</label>
                  <select value={targetIp} onChange={(e) => setTargetIp(e.target.value)}>
                    {peers.length === 0 && <option value="">No peers online</option>}
                    {peers.map((p) => (
                      <option key={p.ip} value={p.ip}>
                        {p.name} ({p.ip})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="sendOption">
                  <label>Mode:</label>
                  <select value={attackMode} onChange={(e) => setAttackMode(e.target.value)}>
                    {attackModes.map((m) => (
                      <option key={m.id} value={m.id}>{m.label}</option>
                    ))}
                  </select>
                </div>

                <button type="submit" className="sendBtn" disabled={busy || !targetIp || !message.trim()}>
                  <Send size={16} />
                  {busy ? "Sending…" : "Send Securely"}
                </button>
              </div>

              <div className={`attackDesc ${attackMode !== "normal" ? "warning" : ""}`}>
                <activeAttack.Icon size={14} />
                <p><strong>{pathText}</strong> {activeAttack.desc}</p>
              </div>
            </form>

            {sendResult && (
              <>
                <div className={`sendResult ${getReceiverResult(sendResult)?.attackDetected || !sendResult.ok ? "error" : "success"}`}>
                  {sendResult.ok
                    ? getReceiverResult(sendResult)?.attackDetected
                      ? "Message reached receiver, but attack detection blocked it."
                      : "Message delivered through 3 hops."
                    : `${sendResult.error || "Send failed"}`
                  }
                </div>
                <SendExplanation sendResult={sendResult} />
              </>
            )}
          </section>

          {/* ─── Network Grid ─── */}
          <div className="networkGrid">
            <PeerList selfInfo={selfInfo} peers={peers} onRefresh={refreshAll} />
            <InboxPanel messages={inboxMessages} onClear={async () => { await clearInbox(); await refreshAll(); }} />
          </div>

          {/* ─── Metrics + Log ─── */}
          <div className="split">
            <section>
              <ErrorRateBar value={metrics.latestErrorRate} />
            </section>
            <LiveLog events={events} />
          </div>
        </>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* LOCAL SIMULATION TAB                                               */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {activeTab === "simulation" && (
        <>
          <form className="sendRow" onSubmit={async (e) => {
            e.preventDefault();
            if (!message.trim()) return;
            setBusy(true);
            const { sendMessage } = await import("./api/client.js");
            await sendMessage(message.trim());
            await refreshAll();
            setBusy(false);
          }}>
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type a message to send through local simulation…"
              aria-label="Message"
            />
            <button type="submit" disabled={busy}>
              <Send size={18} />
              {busy ? "Sending…" : "Send Securely"}
            </button>
          </form>

          <MetricCards metrics={metrics} statuses={statuses} attackMode={simAttackMode} />
          <HopFlow statuses={statuses} attackMode={simAttackMode} targetNode={targetNode} />

          <div className="split">
            <section>
              <ErrorRateBar value={metrics.latestErrorRate} />
              <AttackControls
                currentMode={simAttackMode}
                targetNode={targetNode}
                onChange={refreshAll}
              />
            </section>
            <LiveLog events={events} />
          </div>
          <PacketJourney events={events} attackMode={simAttackMode} />
        </>
      )}
    </main>
  );
}

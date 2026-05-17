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

const attackModes = [
  { id: "normal", label: "Direct (Secure)", Icon: Shield, color: "teal", desc: "Send directly — BB84 key exchange is honest, no interference." },
  { id: "mitm", label: "MITM Relay", Icon: UserRoundX, color: "red", desc: "Route through an attacker machine — receiver detects high BB84 error rate." },
  { id: "eavesdrop", label: "Eavesdrop", Icon: RadioTower, color: "orange", desc: "Attacker passively monitors — quantum disturbance still detected." },
  { id: "replay", label: "Replay", Icon: Repeat, color: "purple", desc: "Resend a captured packet — duplicate nonce detected." },
];

export default function App() {
  // Peer state
  const [selfInfo, setSelfInfo] = useState(null);
  const [peers, setPeers] = useState([]);
  const [inboxMessages, setInboxMessages] = useState([]);

  // Send form
  const [message, setMessage] = useState("");
  const [targetIp, setTargetIp] = useState("");
  const [attackMode, setAttackMode] = useState("normal");
  const [relayIp, setRelayIp] = useState("");
  const [busy, setBusy] = useState(false);
  const [sendResult, setSendResult] = useState(null);

  // Existing simulation state
  const [events, setEvents] = useState([]);
  const [statuses, setStatuses] = useState({});
  const [simAttackMode, setSimAttackMode] = useState("normal");
  const [targetNode, setTargetNode] = useState("node1");
  const [intercepted, setIntercepted] = useState(null);

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
        setIntercepted(statusData.intercepted || null);
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

    let relaySocketPort = 5010;
    if (relayIp) {
      if (selfInfo && relayIp === selfInfo.ip) {
        relaySocketPort = selfInfo.socketPort || 5010;
      } else {
        const relayPeerObj = peers.find((p) => p.ip === relayIp);
        relaySocketPort = relayPeerObj?.socketPort || 5010;
      }
    }

    try {
      const result = await sendToPeer(
        message.trim(), targetIp, targetSocketPort,
        attackMode, relayIp || "", relaySocketPort
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

  const needsRelay = attackMode === "mitm" || attackMode === "eavesdrop";
  const activeAttack = attackModes.find((m) => m.id === attackMode) || attackModes[0];
  const targetPeer = peers.find((p) => p.ip === targetIp);

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

                {needsRelay && (
                  <div className="sendOption">
                    <label>Relay via:</label>
                    <select value={relayIp} onChange={(e) => setRelayIp(e.target.value)}>
                      <option value="">Select attacker machine…</option>
                      {selfInfo && (
                        <option value={selfInfo.ip}>Self (Simulate Attacker on this machine)</option>
                      )}
                      {peers.filter((p) => p.ip !== targetIp).map((p) => (
                        <option key={p.ip} value={p.ip}>
                          {p.name} ({p.ip})
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <button type="submit" className="sendBtn" disabled={busy || !targetIp || !message.trim()}>
                  <Send size={16} />
                  {busy ? "Sending…" : "Send Securely"}
                </button>
              </div>

              <div className={`attackDesc ${attackMode !== "normal" ? "warning" : ""}`}>
                <activeAttack.Icon size={14} />
                <p>{activeAttack.desc}</p>
              </div>
            </form>

            {sendResult && (
              <div className={`sendResult ${sendResult.ok ? "success" : "error"}`}>
                {sendResult.ok
                  ? `✅ Message delivered${sendResult.relay ? " via relay" : " directly"}!`
                  : `❌ ${sendResult.error || "Send failed"}`
                }
              </div>
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
              {/* AttackControls kept for simulation mode */}
              {(() => {
                const AttackControls = React.lazy(() => import("./components/AttackControls.jsx"));
                return (
                  <React.Suspense fallback={null}>
                    <AttackControls
                      currentMode={simAttackMode}
                      targetNode={targetNode}
                      intercepted={intercepted}
                      onChange={refreshAll}
                    />
                  </React.Suspense>
                );
              })()}
            </section>
            <LiveLog events={events} />
          </div>
          <PacketJourney events={events} attackMode={simAttackMode} />
        </>
      )}
    </main>
  );
}

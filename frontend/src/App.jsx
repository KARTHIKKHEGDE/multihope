import React, { useEffect, useMemo, useState } from "react";
import { RotateCcw, Send } from "lucide-react";
import { fetchEvents, fetchStatus, resetDemo, sendMessage, summarizeEvents } from "./api/client.js";
import AttackControls from "./components/AttackControls.jsx";
import ErrorRateBar from "./components/ErrorRateBar.jsx";
import HopFlow from "./components/HopFlow.jsx";
import LiveLog from "./components/LiveLog.jsx";
import MetricCards from "./components/MetricCards.jsx";
import PacketJourney from "./components/PacketJourney.jsx";

export default function App() {
  const [events, setEvents] = useState([]);
  const [statuses, setStatuses] = useState({});
  const [attackMode, setAttackMode] = useState("normal");
  const [targetNode, setTargetNode] = useState("node1");
  const [intercepted, setIntercepted] = useState(null);
  const [message, setMessage] = useState("HELLO QKD");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const [nextEvents, statusData] = await Promise.all([fetchEvents(), fetchStatus()]);
    setEvents(nextEvents);
    if (statusData && statusData.nodes) {
      setStatuses(statusData.nodes);
      setAttackMode(statusData.attackMode || "normal");
      setTargetNode(statusData.targetNode || "node1");
      setIntercepted(statusData.intercepted || null);
    } else {
      setStatuses(statusData || {});
      setAttackMode("normal");
      setTargetNode("node1");
      setIntercepted(null);
    }
  }

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 1000);
    return () => clearInterval(interval);
  }, []);

  const metrics = useMemo(() => summarizeEvents(events), [events]);

  async function handleSend(event) {
    event.preventDefault();
    if (!message.trim()) return;
    setBusy(true);
    await sendMessage(message.trim());
    await refresh();
    setBusy(false);
  }

  async function handleReset() {
    setBusy(true);
    await resetDemo();
    await refresh();
    setBusy(false);
  }

  return (
    <main className="shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">BB84 Quantum Key Distribution</p>
          <h1>Multihop Secure Network</h1>
        </div>
        <button className="iconButton" type="button" onClick={handleReset} aria-label="Reset demo">
          <RotateCcw size={18} />
        </button>
      </section>

      <form className="sendRow" onSubmit={handleSend}>
        <input
          value={message}
          onChange={(event) => setMessage(event.target.value)}
          placeholder="Type a message to send securely…"
          aria-label="Message"
        />
        <button type="submit" disabled={busy}>
          <Send size={18} />
          {busy ? "Sending…" : "Send Securely"}
        </button>
      </form>

      <MetricCards metrics={metrics} statuses={statuses} attackMode={attackMode} />
      <HopFlow statuses={statuses} attackMode={attackMode} targetNode={targetNode} />

      <div className="split">
        <section>
          <ErrorRateBar value={metrics.latestErrorRate} />
          <AttackControls 
            currentMode={attackMode} 
            targetNode={targetNode}
            intercepted={intercepted}
            onChange={refresh} 
          />
        </section>
        <LiveLog events={events} />
      </div>

      <PacketJourney events={events} attackMode={attackMode} />
    </main>
  );
}

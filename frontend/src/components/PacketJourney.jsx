import { useMemo, useState } from "react";
import {
  CheckCircle2,
  XCircle,
  Key,
  Lock,
  Unlock,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Zap,
  Send as SendIcon,
  ArrowDownToLine,
} from "lucide-react";

const phaseConfig = {
  bb84: { label: "Key Exchange (BB84)", Icon: Key, color: "teal" },
  "aes-encrypt": { label: "Encrypt (AES-CBC)", Icon: Lock, color: "amber" },
  "aes-decrypt": { label: "Decrypt (AES-CBC)", Icon: Unlock, color: "blue" },
  "attack-detected": { label: "Attack Detected!", Icon: ShieldAlert, color: "red" },
};

const nodeNames = {
  sender: "Sender",
  node1: "Node 1",
  node2: "Node 2",
  node3: "Node 3",
  receiver: "Receiver",
};

function previewCells(value = "") {
  return String(value).split("").slice(0, 8);
}

function BB84MiniTable({ event }) {
  if (!event.aliceBitPreview) return null;
  const rows = [
    ["Alice bit", previewCells(event.aliceBitPreview)],
    ["Bob bit", previewCells(event.bobBitPreview)],
    ["Alice basis", previewCells(event.aliceBasisPreview)],
    ["Bob basis", previewCells(event.bobBasisPreview)],
    ["Keep", previewCells(event.keepPreview)],
  ];

  return (
    <div className="bb84Table" aria-label="BB84 basis table">
      <p>QKD Sifted Key (matching bases kept):</p>
      {rows.map(([label, cells]) => (
        <div className="bb84Row" key={label}>
          <span>{label}</span>
          <div>
            {cells.map((cell, index) => (
              <b
                className={`${label === "Keep" && cell === "Y" ? "kept" : ""} ${label === "Keep" && cell === "N" ? "dropped" : ""}`}
                key={`${label}-${index}`}
              >
                {cell}
              </b>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function StepDetail({ event }) {
  const [expanded, setExpanded] = useState(false);
  const phase = phaseConfig[event.phase] || phaseConfig["attack-detected"];

  const summaryLines = [];
  if (event.phase === "bb84") {
    const errPct = Math.round((event.errorRate || 0) * 100);
    const thrPct = Math.round((event.errorThreshold || 0.15) * 100);
    summaryLines.push(`${event.matchingBases || "?"} bases matched → ${event.siftedBits || "?"} bits sifted`);
    summaryLines.push(`Error rate: ${errPct}% (limit: ${thrPct}%)`);
    if (event.errorRate > event.errorThreshold) {
      summaryLines.push("⚠️ Rejected — error rate exceeded threshold");
    } else {
      summaryLines.push("✓ Accepted — within error tolerance");
    }
  } else if (event.phase === "aes-encrypt" || event.phase === "aes-decrypt") {
    const action = event.phase === "aes-decrypt" ? "Decrypted" : "Encrypted";
    summaryLines.push(`${action} ${event.plaintextLength || "?"} characters with AES-256-CBC`);
    summaryLines.push(`Key fingerprint: ${event.keyFingerprint || "unknown"}`);
  } else if (event.phase === "attack-detected") {
    summaryLines.push(`Detection: ${event.detectionReason || event.message}`);
    if (event.blockedNode) summaryLines.push(`Node ${event.blockedNode} was blocked and routing will skip it`);
  }

  return (
    <div className={`journeyStepDetail ${phase.color}`}>
      <div className="journeyStepHeader" onClick={() => setExpanded(!expanded)}>
        <div className="journeyStepIcon">
          <phase.Icon size={16} />
        </div>
        <div className="journeyStepInfo">
          <span className="journeyStepLabel">{phase.label}</span>
          <p className="journeyStepMessage">{event.message}</p>
        </div>
        <button type="button" className="expandToggle" aria-label={expanded ? "Collapse" : "Expand"}>
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </button>
      </div>
      {summaryLines.length > 0 && (
        <ul className="journeyStepSummary">
          {summaryLines.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      )}
      {expanded && (
        <div className="journeyStepExpanded">
          {event.phase === "bb84" && <BB84MiniTable event={event} />}
          {(event.ivPreview || event.ciphertextPreview) && (
            <div className="technicalDetails">
              {event.ivPreview && <code>IV: {event.ivPreview}…</code>}
              {event.ciphertextPreview && <code>Cipher: {event.ciphertextPreview}…</code>}
            </div>
          )}
          {event.noncePreview && (
            <div className="technicalDetails">
              <code>Nonce: {event.noncePreview}…</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function OutcomeBanner({ events }) {
  const attackEvents = events.filter((e) => e.phase === "attack-detected" || e.status === "attack");
  const receiverSuccess = events.find((e) => e.source === "receiver" && e.status === "success");
  const isSuccess = receiverSuccess && attackEvents.length === 0;
  const isBlocked = attackEvents.length > 0;

  if (events.length === 0) return null;

  if (isSuccess) {
    return (
      <div className="outcomeBanner success">
        <CheckCircle2 size={22} />
        <div>
          <strong>Message Delivered Successfully</strong>
          <p>Packet traversed all hops securely via BB84 key exchange at each hop.</p>
        </div>
      </div>
    );
  }

  if (isBlocked) {
    const reason = attackEvents[0]?.detectionReason || attackEvents[0]?.message || "Attack detected";
    const blockedAt = attackEvents[0]?.source || "unknown node";
    return (
      <div className="outcomeBanner blocked">
        <XCircle size={22} />
        <div>
          <strong>Attack Detected & Blocked at {nodeNames[blockedAt] || blockedAt}</strong>
          <p>{reason} — The compromised node was removed from the routing table.</p>
        </div>
      </div>
    );
  }

  return null;
}

export default function PacketJourney({ events, attackMode }) {
  const stageEvents = useMemo(
    () => events.filter((e) => e.phase || e.status === "attack"),
    [events]
  );

  const nodeSteps = useMemo(() => {
    const nodeOrder = ["sender", "node1", "node2", "node3", "receiver"];
    return nodeOrder
      .map((node) => ({
        node,
        name: nodeNames[node],
        events: stageEvents.filter((e) => e.source === node),
      }))
      .filter((n) => n.events.length > 0);
  }, [stageEvents]);

  if (stageEvents.length === 0) {
    return (
      <section className="panel journeyPanel">
        <div className="panelHeader">
          <h2>Packet Journey</h2>
        </div>
        <div className="journeyEmpty">
          <Zap size={40} />
          <p>Send a message to see the step-by-step packet journey through the quantum network.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel journeyPanel">
      <div className="panelHeader">
        <h2>Packet Journey</h2>
        <span className="stepStatus">
          {stageEvents.length} steps across {nodeSteps.length} nodes
        </span>
      </div>

      <OutcomeBanner events={events} />

      <div className="journeyTimeline">
        {nodeSteps.map((nodeGroup, nodeIndex) => {
          const hasAttack = nodeGroup.events.some(
            (e) => e.phase === "attack-detected" || e.status === "attack"
          );
          const isFirst = nodeIndex === 0;
          const isLast = nodeIndex === nodeSteps.length - 1;
          const NodeIcon = isFirst ? SendIcon : isLast ? ArrowDownToLine : Key;

          return (
            <div
              className={`journeyNode ${hasAttack ? "attacked" : ""}`}
              key={nodeGroup.node}
            >
              <div className="journeyNodeHeader">
                <div className={`journeyNodeDot ${hasAttack ? "red" : "teal"}`}>
                  <NodeIcon size={16} />
                </div>
                <div className="journeyNodeLine" />
                <h3>{nodeGroup.name}</h3>
                {hasAttack && (
                  <span className="journeyAttackTag">
                    <ShieldAlert size={12} /> Blocked
                  </span>
                )}
              </div>
              <div className="journeyNodeSteps">
                {nodeGroup.events.map((event, index) => (
                  <StepDetail event={event} key={`${event.time}-${event.phase}-${index}`} />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

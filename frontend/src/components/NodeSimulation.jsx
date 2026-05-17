import { useEffect, useMemo, useState } from "react";
import { ChevronsRight, ListRestart, Pause, Play, StepForward } from "lucide-react";

const phaseLabels = {
  bb84: "BB84",
  "aes-decrypt": "AES decrypt",
  "aes-encrypt": "AES encrypt",
  "attack-detected": "Error check",
};

const nodeOrder = ["sender", "node1", "node2", "node3", "receiver"];

const nodeDisplayNames = {
  sender: "Sender (Node A)",
  node1: "Node 1",
  node2: "Node 2",
  node3: "Node 3",
  receiver: "Receiver (Node B)",
};

function bb84Details(event) {
  const errorPercent = Math.round(event.errorRate * 100);
  const thresholdPercent = Math.round(event.errorThreshold * 100);
  return [
    `Generated ${event.generatedBits} random qubit bits and random bases.`,
    `${event.matchingBases} bases matched, so ${event.siftedBits} bits were sifted.`,
    `${event.comparedBits} bits checked; error rate ${errorPercent}% against ${thresholdPercent}% limit.`,
    event.errorRate > event.errorThreshold
      ? "Result: rejected because too many checked bits disagreed."
      : "Result: accepted because the checked bits stayed within the error limit.",
    `Derived AES key fingerprint ${event.keyFingerprint} from sifted key material.`,
  ];
}

function aesDetails(event) {
  const action = event.phase === "aes-decrypt" ? "decrypted" : "encrypted";
  return [
    `AES-CBC ${action} ${event.plaintextLength} plaintext characters.`,
    `IV preview ${event.ivPreview}; ciphertext preview ${event.ciphertextPreview}.`,
    `Key fingerprint ${event.keyFingerprint} was used for this hop only.`,
  ];
}

function detailLines(event) {
  if (event.phase === "bb84") {
    return bb84Details(event);
  }
  if (event.phase === "aes-decrypt" || event.phase === "aes-encrypt") {
    return aesDetails(event);
  }
  if (event.phase === "attack-detected") {
    return [
      `Reason: ${event.detectionReason}.`,
      `Observed error ${Math.round(event.errorRate * 100)}%; allowed limit ${Math.round(event.errorThreshold * 100)}%.`,
      `Packet nonce preview ${event.noncePreview}.`,
      `${event.blockedNode} was blocked and routing will skip it.`,
    ];
  }
  return [];
}

function previewCells(value = "") {
  return String(value).split("").slice(0, 8);
}

function BB84Table({ event }) {
  const indexes = previewCells(event.aliceBitPreview).map((_cell, index) => String(index + 1));
  const rows = [
    ["#", indexes],
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

export default function NodeSimulation({ events }) {
  const stageEvents = useMemo(() => events.filter((event) => event.phase || event.status === "attack"), [events]);
  const [stepMode, setStepMode] = useState(false);
  const [visibleCount, setVisibleCount] = useState(stageEvents.length);

  useEffect(() => {
    setVisibleCount((current) => (stepMode ? Math.min(current || 1, stageEvents.length) : stageEvents.length));
  }, [stageEvents.length, stepMode]);

  const visibleEvents = stepMode ? stageEvents.slice(0, visibleCount) : stageEvents;
  const eventsByNode = nodeOrder.map((node) => ({
    node,
    events: visibleEvents.filter((event) => event.source === node),
  }));
  const canStep = visibleCount < stageEvents.length;

  function restartSteps() {
    setStepMode(true);
    setVisibleCount(stageEvents.length ? 1 : 0);
  }

  function nextStep() {
    setStepMode(true);
    setVisibleCount((current) => Math.min(current + 1, stageEvents.length));
  }

  function showAll() {
    setStepMode(false);
    setVisibleCount(stageEvents.length);
  }

  return (
    <section className="panel simulationPanel">
      <div className="panelHeader">
        <h2>Node Simulation</h2>
        <div className="stepControls">
          <button type="button" onClick={restartSteps} disabled={!stageEvents.length} aria-label="Restart step mode">
            <ListRestart size={16} />
          </button>
          <button type="button" onClick={() => setStepMode((enabled) => !enabled)} disabled={!stageEvents.length}>
            {stepMode ? <Pause size={16} /> : <Play size={16} />}
            {stepMode ? "Pause" : "Step mode"}
          </button>
          <button type="button" onClick={nextStep} disabled={!stageEvents.length || !canStep}>
            <StepForward size={16} />
            Next
          </button>
          <button type="button" onClick={showAll} disabled={!stageEvents.length}>
            <ChevronsRight size={16} />
            All
          </button>
        </div>
      </div>
      <div className="stepStatus">
        Showing {visibleEvents.length} of {stageEvents.length} simulation steps
      </div>
      <div className="nodeSimulationGrid">
        {eventsByNode.map(({ node, events: nodeEvents }) => (
          <article className="nodeLog" key={node}>
            <header>{nodeDisplayNames[node] || node}</header>
            <div className="nodeLogSteps">
              {nodeEvents.length === 0 && <p className="emptyNodeLog">Waiting for packet</p>}
              {nodeEvents.map((event, index) => (
                <section className={`simulationItem ${event.phase || event.status}`} key={`${event.time}-${event.phase}-${index}`}>
                  <div>
                    <span>{phaseLabels[event.phase] || "Error check"}</span>
                    <time>{new Date(event.time).toLocaleTimeString()}</time>
                  </div>
                  <p>{event.message}</p>
                  <ul>
                    {detailLines(event).map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                  {event.phase === "bb84" && <BB84Table event={event} />}
                </section>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

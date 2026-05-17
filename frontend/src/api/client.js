const jsonHeaders = { "Content-Type": "application/json" };

async function readJson(response) {
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`API ${response.status}: ${text.slice(0, 120)}`);
  }
  return response.json();
}

// ─── Simulation (local) ────────────────────────────────────────────────────

export async function fetchEvents() {
  return readJson(await fetch("/api/events"));
}

export async function fetchStatus() {
  return readJson(await fetch("/api/status"));
}

export async function sendMessage(message) {
  return readJson(
    await fetch("/api/send", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({ message }),
    })
  );
}

export async function setAttackMode(mode, targetNode) {
  return readJson(
    await fetch("/api/attack", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({ mode, targetNode }),
    })
  );
}

export async function resetDemo() {
  return readJson(await fetch("/api/reset", { method: "POST" }));
}

// ─── Real peer-to-peer ─────────────────────────────────────────────────────

export async function fetchPeers() {
  return readJson(await fetch("/api/peers"));
}

export async function fetchInbox() {
  return readJson(await fetch("/api/inbox"));
}

export async function clearInbox() {
  return readJson(await fetch("/api/inbox/clear", { method: "POST" }));
}

/**
 * Send a real encrypted message to a peer over the LAN.
 * @param {string} message
 * @param {string} targetIp
 * @param {number} targetPort
 * @param {string} attackMode  "normal" | "mitm" | "eavesdrop" | "replay"
 * @param {string} relayIp     IP of the attacker/relay machine (for MITM demo)
 * @param {number} relayPort
 */
export async function sendToPeer(message, targetIp, targetPort, attackMode = "normal", relayIp = "", relayPort = 5000) {
  return readJson(
    await fetch("/api/send-to-peer", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({ message, targetIp, targetPort, attackMode, relayIp, relayPort }),
    })
  );
}

// ─── Helpers ───────────────────────────────────────────────────────────────

export function summarizeEvents(events) {
  const latestErrorEvent = [...events].reverse().find((e) => typeof e.errorRate === "number");
  const received = events.filter((e) => e.source === "receiver" && e.status === "success").length;
  const attacksBlocked = events.filter((e) => e.status === "attack").length;
  return {
    messagesSent: events.filter((e) => e.source === "sender").length,
    messagesReceived: received,
    attacksBlocked,
    latestErrorRate: latestErrorEvent?.errorRate ?? 0,
  };
}

const jsonHeaders = { "Content-Type": "application/json" };

async function readJson(response) {
  if (!response.ok) {
    throw new Error(`API request failed with ${response.status}`);
  }
  return response.json();
}

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

export async function submitMitmGuess(keyGuess) {
  return readJson(
    await fetch("/api/mitm-attempt", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({ keyGuess }),
    })
  );
}

export async function resetDemo() {
  return readJson(await fetch("/api/reset", { method: "POST" }));
}

export function summarizeEvents(events) {
  const latestErrorEvent = [...events].reverse().find((event) => typeof event.errorRate === "number");
  const received = events.filter((event) => event.source === "receiver" && event.status === "success").length;
  const attacksBlocked = events.filter((event) => event.status === "attack").length;
  return {
    messagesSent: events.filter((event) => event.source === "sender").length,
    messagesReceived: received,
    attacksBlocked,
    latestErrorRate: latestErrorEvent?.errorRate ?? 0,
  };
}

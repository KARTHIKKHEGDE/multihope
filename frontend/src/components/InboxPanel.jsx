import { ShieldCheck, ShieldAlert, Inbox, Trash2, User, Clock, Zap, AlertTriangle } from "lucide-react";

function formatTime(iso) {
  if (!iso) return "";
  return new Date(iso + "Z").toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function AttackBanner({ msg }) {
  if (!msg.attackDetected) return null;
  return (
    <div className="inboxAttackBanner">
      <AlertTriangle size={14} />
      <div>
        <strong>⚠️ Security Alert: {msg.attackType}</strong>
        {msg.relayName && (
          <p>Relayed through: <code>{msg.relayName} ({msg.relayIp})</code></p>
        )}
        {msg.bb84Details?.errorRate !== undefined && (
          <p>BB84 error rate: <strong>{Math.round(msg.bb84Details.errorRate * 100)}%</strong> (threshold: {Math.round((msg.bb84Details.errorThreshold || 0.15) * 100)}%)</p>
        )}
      </div>
    </div>
  );
}

function BB84Badge({ details }) {
  if (!details?.errorRate === undefined) return null;
  const pct = Math.round((details.errorRate || 0) * 100);
  const threshold = Math.round((details.errorThreshold || 0.15) * 100);
  const safe = pct <= threshold;
  return (
    <div className={`bb84Badge ${safe ? "safe" : "danger"}`}>
      {safe ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
      BB84 error {pct}% / {threshold}%
      &nbsp;·&nbsp;
      Key: <code>{details.keyFingerprint}…</code>
    </div>
  );
}

export default function InboxPanel({ messages, onClear }) {
  return (
    <section className="panel inboxPanel">
      <div className="panelHeader">
        <div className="panelHeaderLeft">
          <Inbox size={16} className="panelHeaderIcon" />
          <h2>Inbox</h2>
          {messages.length > 0 && (
            <span className="inboxCount">{messages.length}</span>
          )}
        </div>
        {messages.length > 0 && (
          <button type="button" className="clearBtn" onClick={onClear} title="Clear inbox">
            <Trash2 size={14} />
            Clear
          </button>
        )}
      </div>

      {messages.length === 0 ? (
        <div className="inboxEmpty">
          <Zap size={32} />
          <p>No messages received yet.</p>
          <small>Messages sent from other laptops will appear here in real-time.</small>
        </div>
      ) : (
        <div className="inboxList">
          {[...messages].reverse().map((msg) => (
            <div
              key={msg.id}
              className={`inboxMessage ${msg.attackDetected ? "attacked" : "safe"}`}
            >
              <div className="inboxMessageHeader">
                <div className="inboxSender">
                  {msg.attackDetected
                    ? <ShieldAlert size={14} className="dangerIcon" />
                    : <ShieldCheck size={14} className="safeIcon" />
                  }
                  <User size={13} />
                  <strong>{msg.senderName}</strong>
                  <code className="senderIp">{msg.senderIp}</code>
                </div>
                <div className="inboxTime">
                  <Clock size={11} />
                  {formatTime(msg.receivedAtISO)}
                </div>
              </div>

              <AttackBanner msg={msg} />

              <div className={`inboxText ${msg.attackDetected ? "blocked" : ""}`}>
                {msg.attackDetected
                  ? "🚫 Message blocked — attack detected"
                  : `💬 ${msg.plaintext}`
                }
              </div>

              <BB84Badge details={msg.bb84Details} />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

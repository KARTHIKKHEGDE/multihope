import {
  ShieldCheck,
  ShieldAlert,
  Inbox,
  Trash2,
  User,
  Clock,
  Zap,
  AlertTriangle,
  Route,
  CheckCircle2,
  XCircle,
  CircleAlert,
} from "lucide-react";

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
  if (details?.errorRate === undefined) return null;
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

function stepIcon(status) {
  if (status === "attack") return <XCircle size={14} />;
  if (status === "warning") return <CircleAlert size={14} />;
  return <CheckCircle2 size={14} />;
}

function NodeSteps({ msg }) {
  const steps = msg.routeSteps || [];
  if (steps.length === 0) return null;

  return (
    <details className="nodeSteps">
      <summary>
        <Route size={14} />
        <span>Node steps</span>
      </summary>
      <ol className="nodeStepList">
        {steps.map((step, index) => (
          <li key={`${msg.id}-${step.node}-${index}`} className={`nodeStep ${step.status || "success"}`}>
            <div className="nodeStepIcon">{stepIcon(step.status)}</div>
            <div className="nodeStepBody">
              <div className="nodeStepTop">
                <strong>{index + 1}. {step.node}</strong>
                <span>{step.name}</span>
                {step.ip && <code>{step.ip}</code>}
              </div>
              <p>{step.title}</p>
              <small>{step.detail}</small>
            </div>
          </li>
        ))}
      </ol>
    </details>
  );
}

function CryptoDetails({ details }) {
  if (!details?.nonce) return null;
  const sender = details.senderBB84 || {};
  const receiver = details.receiverBB84 || {};
  return (
    <details className="cryptoPanel">
      <summary>Encryption / BB84 details</summary>
      <div className="cryptoDetails">
        <div><span>Nonce</span><code>{details.nonce.slice(0, 24)}...</code></div>
        <div><span>AES key</span><code>{details.aesKeyFingerprint}... ({details.aesKeyLengthBits} bits)</code></div>
        <div><span>IV</span><code>{details.ivPreview}...</code></div>
        <div><span>Ciphertext</span><code>{details.ciphertextPreview}...</code></div>
        <div><span>Decryption</span><code>{details.decrypted ? `Plaintext: ${details.plaintextPreview}` : `Blocked: ${details.blockedReason}`}</code></div>
        <div><span>Sender bases</span><code>Alice {sender.aliceBasisPreview} | Bob {sender.bobBasisPreview}</code></div>
        <div><span>Receiver bases</span><code>Alice {receiver.aliceBasisPreview} | Bob {receiver.bobBasisPreview}</code></div>
        <div><span>Receiver bits</span><code>Alice {receiver.aliceBitPreview} | Bob {receiver.bobBitPreview}</code></div>
        <div><span>Keep mask</span><code>{receiver.keepPreview}</code></div>
        <div><span>Sifted key bits</span><code>{receiver.siftedPreview}</code></div>
        <div><span>BB84 counts</span><code>{receiver.matchingBases} matching, {receiver.siftedBits} sifted, {receiver.comparedBits} compared, {receiver.generatedBits} generated</code></div>
        <div><span>Error rate</span><code>{Math.round((receiver.errorRate || 0) * 100)}% / {Math.round((receiver.errorThreshold || 0.15) * 100)}%</code></div>
      </div>
    </details>
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
              <CryptoDetails details={msg.cryptoDetails} />
              <NodeSteps msg={msg} />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

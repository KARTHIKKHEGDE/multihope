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
              <NodeCrypto step={step} crypto={msg.cryptoDetails} />
            </div>
          </li>
        ))}
      </ol>
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
              <NodeSteps msg={msg} />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

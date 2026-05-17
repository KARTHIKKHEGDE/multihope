import { ShieldCheck, ShieldAlert } from "lucide-react";

export default function MetricCards({ metrics, statuses, attackMode }) {
  const activeHops = Object.values(statuses).filter((node) => node.status === "active").length;
  const isAttack = attackMode && attackMode !== "normal";

  const items = [
    { label: "Sent", value: metrics.messagesSent, color: "default" },
    { label: "Received", value: metrics.messagesReceived, color: "teal" },
    { label: "Active Hops", value: activeHops, color: "blue" },
    { label: "Attacks Blocked", value: metrics.attacksBlocked, color: "red" },
  ];

  return (
    <section className="metrics">
      {items.map((item) => (
        <article className={`metric ${item.color}`} key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </article>
      ))}
      <article className={`metric mode ${isAttack ? "danger" : "safe"}`}>
        <span>Network Mode</span>
        <div className="modeIndicator">
          {isAttack ? <ShieldAlert size={22} /> : <ShieldCheck size={22} />}
          <strong>{(attackMode || "normal").toUpperCase()}</strong>
        </div>
      </article>
    </section>
  );
}

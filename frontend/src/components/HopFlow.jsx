import { ArrowRight, Lock, ShieldAlert, Target } from "lucide-react";

const route = ["sender", "node1", "node2", "node3", "receiver"];

const displayNames = {
  sender: "Sender",
  node1: "Node 1",
  node2: "Node 2",
  node3: "Node 3",
  receiver: "Receiver",
};

export default function HopFlow({ statuses, attackMode, targetNode }) {
  const isAttack = attackMode && attackMode !== "normal";

  return (
    <section className="panel">
      <div className="panelHeader">
        <h2>Network Topology</h2>
        {isAttack && (
          <span className="attackBadge">
            <Target size={14} />
            Target: {displayNames[targetNode]}
          </span>
        )}
      </div>
      <div className="hopFlow">
        {route.map((node, index) => {
          const status = statuses[node]?.status || "active";
          const isBlocked = status === "blocked";
          const isTargeted = isAttack && node === targetNode;

          return (
            <div className="hopGroup" key={node}>
              <div className={`hop ${status} ${isTargeted ? 'blocked' : ''}`}>
                <div className="hopIcon">
                  {isBlocked || isTargeted ? <ShieldAlert size={20} /> : <Lock size={18} />}
                </div>
                <span>{displayNames[node]}</span>
                <small>
                  {isBlocked
                    ? "Blocked"
                    : isTargeted
                      ? "Compromised"
                      : statuses[node]?.nextHop
                        ? `→ ${displayNames[statuses[node].nextHop] || statuses[node].nextHop}`
                        : "End"}
                </small>
              </div>
              {index < route.length - 1 && (
                <div className={`connector ${isBlocked ? "blocked" : ""}`}>
                  <ArrowRight size={18} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default function ErrorRateBar({ value }) {
  const percent = Math.round(value * 100);
  const isHigh = percent > 15;

  return (
    <section className="panel">
      <div className="panelHeader">
        <h2>BB84 Error Rate</h2>
        <strong style={{ color: isHigh ? "#ef4444" : "#0f766e" }}>{percent}%</strong>
      </div>
      <div className="barTrack">
        <div className="barFill" style={{ width: `${Math.min(percent, 100)}%` }} />
      </div>
      <p style={{ fontSize: "11px", color: "#94a3b8", marginTop: "8px" }}>
        {isHigh
          ? "⚠️ High error rate — possible eavesdropping detected"
          : percent === 0
            ? "No errors detected — quantum channel is secure"
            : "Within acceptable range — quantum channel appears clean"}
      </p>
    </section>
  );
}

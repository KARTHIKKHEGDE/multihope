import { Activity } from "lucide-react";

export default function LiveLog({ events }) {
  return (
    <section className="panel logPanel">
      <div className="panelHeader">
        <h2>Live Log</h2>
        <span className="stepStatus">{events.length} events</span>
      </div>
      {events.length === 0 ? (
        <div className="journeyEmpty" style={{ padding: "32px 16px" }}>
          <Activity size={28} />
          <p>No events yet — send a message to see the live log.</p>
        </div>
      ) : (
        <div className="logList">
          {[...events].reverse().map((event, index) => (
            <article className={`logItem ${event.status}`} key={`${event.time}-${index}`}>
              <span>{event.source}</span>
              <p>{event.message}</p>
              {event.detectionReason && <small>{event.detectionReason}</small>}
              {event.routeSteps?.length > 0 && (
                <details className="logDetails">
                  <summary>What happened?</summary>
                  <ol>
                    {event.routeSteps.map((step, stepIndex) => (
                      <li key={`${event.time}-${step.node}-${stepIndex}`}>
                        <strong>{step.node}</strong>
                        <p>{step.detail}</p>
                      </li>
                    ))}
                  </ol>
                </details>
              )}
              <time>{new Date(event.time).toLocaleTimeString()}</time>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

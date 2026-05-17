import { useState } from "react";
import { Wifi, WifiOff, Monitor, RefreshCw, Radio } from "lucide-react";

export default function PeerList({ selfInfo, peers, onRefresh }) {
  const [refreshing, setRefreshing] = useState(false);

  async function handleRefresh() {
    setRefreshing(true);
    await onRefresh();
    setTimeout(() => setRefreshing(false), 600);
  }

  return (
    <section className="panel peerPanel">
      <div className="panelHeader">
        <div className="panelHeaderLeft">
          <Radio size={16} className="panelHeaderIcon" />
          <h2>Network Peers</h2>
        </div>
        <button
          type="button"
          className="iconButton"
          onClick={handleRefresh}
          aria-label="Refresh peers"
          title="Refresh peer list"
        >
          <RefreshCw size={15} className={refreshing ? "spin" : ""} />
        </button>
      </div>

      {/* Self card */}
      {selfInfo && (
        <div className="peerSelf">
          <Monitor size={15} />
          <div className="peerInfo">
            <strong>{selfInfo.name} <span className="peerSelfBadge">You</span></strong>
            <code>{selfInfo.ip}:{selfInfo.port}</code>
          </div>
          <span className="peerDot online" title="Online" />
        </div>
      )}

      {/* Peer list */}
      <div className="peerList">
        {peers.length === 0 ? (
          <div className="peerEmpty">
            <WifiOff size={28} />
            <p>No peers found on this network.</p>
            <small>Run QuantumHop on other laptops connected to the same hotspot/Wi-Fi.</small>
          </div>
        ) : (
          peers.map((peer) => (
            <div className="peerCard" key={peer.ip}>
              <Wifi size={15} />
              <div className="peerInfo">
                <strong>{peer.name}</strong>
                <code>{peer.ip}:{peer.port}</code>
              </div>
              <span className="peerDot online" title="Online" />
            </div>
          ))
        )}
      </div>
    </section>
  );
}

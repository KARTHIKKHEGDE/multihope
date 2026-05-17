"""Flask API shell — serves the web UI and bridges browser to raw socket P2P layer."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from . import (
    attack_detector,
    config,
    inbox,
    logger,
    peer_discovery,
    peer_socket,
    router,
    sender,
)

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
app = Flask(__name__, static_folder=str(FRONTEND_DIST / "assets"), static_url_path="/assets")


# ─── Peer-to-peer: browser triggers a socket send ─────────────────────────────

@app.post("/api/send-to-peer")
def send_to_peer():
    """
    Browser sends JSON here; Flask uses peer_socket to deliver the message
    to the target laptop via raw TCP (port PEER_SOCKET_PORT).
    """
    body       = request.get_json(silent=True) or {}
    message    = body.get("message", "").strip()
    target_ip  = body.get("targetIp", "")
    target_port = int(body.get("targetPort", config.PEER_SOCKET_PORT))
    attack_mode = body.get("attackMode", "normal")
    relay_ip   = body.get("relayIp", "")
    relay_port = int(body.get("relayPort", config.PEER_SOCKET_PORT))

    if not message:
        return jsonify({"error": "Empty message"}), 400
    if not target_ip:
        return jsonify({"error": "No target IP"}), 400

    result = peer_socket.send_message_to_peer(
        message, target_ip, target_port,
        attack_mode, relay_ip, relay_port,
    )
    return jsonify(result)


# ─── Peer discovery ───────────────────────────────────────────────────────────

@app.get("/api/peers")
def get_peers():
    return jsonify({
        "self":  {"name": config.MACHINE_NAME, "ip": config.LOCAL_IP,
                  "port": config.API_PORT, "socketPort": config.PEER_SOCKET_PORT},
        "peers": peer_discovery.get_peers(),
    })


# ─── Inbox (written by peer_socket, read by browser) ─────────────────────────

@app.get("/api/inbox")
def get_inbox():
    return jsonify(inbox.get_messages())


@app.post("/api/inbox/clear")
def clear_inbox():
    inbox.clear()
    return jsonify({"ok": True})


# ─── Local simulation endpoints (unchanged) ───────────────────────────────────

@app.get("/api/events")
def events():
    return jsonify(logger.get_events())


@app.post("/api/send")
def send():
    payload = request.get_json(silent=True) or {}
    return jsonify({"received": sender.send_message(payload.get("message", ""))})


@app.post("/api/attack")
def attack():
    try:
        body   = request.get_json(silent=True) or {}
        mode   = body.get("mode", "normal")
        target = body.get("targetNode", None)
        result_mode   = attack_detector.set_attack_mode(mode)
        result_target = attack_detector.get_target_node()
        if target:
            result_target = attack_detector.set_target_node(target)
        return jsonify({"mode": result_mode, "targetNode": result_target})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/reset")
def reset():
    logger.clear_events()
    router.reset_routes()
    attack_detector.reset_detector()
    inbox.clear()
    return jsonify({"ok": True})


@app.get("/api/status")
def status():
    return jsonify({
        "nodes":      router.get_node_statuses(),
        "attackMode": attack_detector.get_attack_mode(),
        "targetNode": attack_detector.get_target_node(),
        "intercepted": attack_detector.get_intercepted(),
        "self": {
            "name": config.MACHINE_NAME,
            "ip":   config.LOCAL_IP,
            "port": config.API_PORT,
            "socketPort": config.PEER_SOCKET_PORT,
        },
    })


# ─── Frontend serving ─────────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIST, "index.html")


@app.get("/<path:path>")
def frontend(path):
    target = FRONTEND_DIST / path
    return send_from_directory(FRONTEND_DIST, path if target.exists() else "index.html")


# ─── Startup ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    peer_discovery.start_discovery()
    peer_socket.start_peer_server()
    print(f"[QH] QuantumHop | IP={config.LOCAL_IP} | Flask={config.API_PORT} | Socket={config.PEER_SOCKET_PORT}")
    app.run(host=config.HOST, port=config.API_PORT, debug=False, use_reloader=False)

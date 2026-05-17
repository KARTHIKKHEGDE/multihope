"""Thin Flask API shell."""

from __future__ import annotations

import hashlib
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from . import attack_detector, config, crypto_utils, logger, router, sender

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
app = Flask(__name__, static_folder=str(FRONTEND_DIST / "assets"), static_url_path="/assets")


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
        body = request.get_json(silent=True) or {}
        mode = body.get("mode", "normal")
        target = body.get("targetNode", None)
        result_mode = attack_detector.set_attack_mode(mode)
        result_target = attack_detector.get_target_node()
        if target:
            result_target = attack_detector.set_target_node(target)
        return jsonify({"mode": result_mode, "targetNode": result_target})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/reset")
def reset():
    logger.clear_events(); router.reset_routes(); attack_detector.reset_detector()
    return jsonify({"ok": True})


@app.get("/api/status")
def status():
    return jsonify({
        "nodes": router.get_node_statuses(),
        "attackMode": attack_detector.get_attack_mode(),
        "targetNode": attack_detector.get_target_node(),
        "intercepted": attack_detector.get_intercepted(),
    })


@app.post("/api/mitm-attempt")
def mitm_attempt():
    """User submits a hex key guess to try to decrypt the intercepted packet."""
    body = request.get_json(silent=True) or {}
    guess = body.get("keyGuess", "")
    intercepted = attack_detector.get_intercepted()

    if not intercepted:
        return jsonify({"success": False, "message": "No intercepted packet available. Send a message first with MITM mode active."})

    real_fingerprint = intercepted.get("realKeyFingerprint", "")

    # Hash the user's guess the same way we derive AES keys
    try:
        guess_bytes = bytes.fromhex(guess) if len(guess) >= 2 else guess.encode("utf-8")
    except ValueError:
        guess_bytes = guess.encode("utf-8")

    guess_key = hashlib.sha256(guess_bytes).digest()
    guess_fingerprint = guess_key.hex()[:12]

    matched = guess_fingerprint == real_fingerprint

    return jsonify({
        "success": matched,
        "guessFingerprint": guess_fingerprint,
        "realFingerprint": real_fingerprint,
        "message": "Key matched! You cracked the encryption (in theory)."
                   if matched
                   else f"Wrong key. Your fingerprint {guess_fingerprint} ≠ real {real_fingerprint}. BB84 quantum key exchange makes this nearly impossible!",
    })


@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIST, "index.html")


@app.get("/<path:path>")
def frontend(path):
    target = FRONTEND_DIST / path
    return send_from_directory(FRONTEND_DIST, path if target.exists() else "index.html")


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.API_PORT, debug=False, use_reloader=False)

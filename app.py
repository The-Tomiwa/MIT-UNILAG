"""GPON Malware Framework Generator - thin Flask backend.

Routes
  GET  /                      single-page UI
  GET  /api/samples           list bundled sample analyses
  GET  /api/samples/<id>      raw inputs for one bundled sample
  POST /api/generate          analysis text/files  -> framework JSON
  POST /api/export/markdown   framework JSON       -> .md download
  GET  /api/campaign          correlate all bundled samples

The backend never executes or unpacks samples: it only parses analysis output.
"""

import hmac
import json
import os
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request

from engine import correlate, generate
from engine.ingest import file_to_text
from engine.render import to_markdown

BASE = Path(__file__).resolve().parent
SAMPLES = BASE / "samples"
MAX_UPLOAD = 20 * 1024 * 1024
ALLOWED = {".txt", ".log", ".md", ".csv", ".json", ".pdf", ".yar", ".yara", ".rules"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD


# Optional HTTP Basic auth: enabled when APP_PASSWORD is set (e.g. on Render).
# Left unset for local use, the app stays open on 127.0.0.1.
APP_USER = os.environ.get("APP_USERNAME", "admin")
APP_PASS = os.environ.get("APP_PASSWORD", "")


@app.before_request
def _require_login():
    if not APP_PASS or request.path == "/healthz":
        return None
    auth = request.authorization
    if auth and auth.type == "basic"             and hmac.compare_digest(auth.username or "", APP_USER)             and hmac.compare_digest(auth.password or "", APP_PASS):
        return None
    return Response("Login required.", 401, {"WWW-Authenticate": 'Basic realm="GPON Framework"'})


@app.get("/healthz")
def healthz():
    return "ok"


def _load_sample(sid):
    d = SAMPLES / sid
    if not d.is_dir() or d.parent != SAMPLES:
        return None
    read = lambda n: (d / n).read_text(encoding="utf-8") if (d / n).exists() else ""
    meta = json.loads(read("meta.json") or "{}")
    return {"id": sid, "meta": meta, "static": read("static.txt"), "dynamic": read("dynamic.txt")}


def _sample_ids():
    # bundled samples are optional - the app works with pasted/uploaded input alone
    if not SAMPLES.is_dir():
        return []
    return sorted(p.name for p in SAMPLES.iterdir() if p.is_dir())


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/samples")
def list_samples():
    out = []
    for sid in _sample_ids():
        s = _load_sample(sid)
        out.append({"id": sid, "name": s["meta"].get("name", sid), "sha256": s["meta"].get("sha256")})
    return jsonify(out)


@app.get("/api/samples/<sid>")
def get_sample(sid):
    s = _load_sample(sid)
    if not s:
        abort(404)
    return jsonify(s)


@app.post("/api/generate")
def api_generate():
    warnings = []
    if request.is_json:
        body = request.get_json(silent=True) or {}
        static, dynamic, meta = body.get("static", ""), body.get("dynamic", ""), body.get("meta", {})
    else:
        f = request.form
        static, dynamic = f.get("static", ""), f.get("dynamic", "")
        meta = {k: f.get(k, "") for k in ("name", "sha256", "family", "arch", "c2", "exploit_url")}
        for field in ("static_files", "dynamic_files"):
            for up in request.files.getlist(field):
                if not up.filename:
                    continue
                ext = Path(up.filename).suffix.lower()
                if ext not in ALLOWED:
                    warnings.append(f"{up.filename}: unsupported type {ext} (only analysis text/JSON/PDF is accepted)")
                    continue
                text, warn = file_to_text(up.filename, up.read())
                if warn:
                    warnings.append(f"{up.filename}: {warn}")
                block = f"\n# --- from {up.filename} ---\n{text}\n"
                if field == "static_files":
                    static += block
                else:
                    dynamic += block
    if not (static.strip() or dynamic.strip()):
        return jsonify({"error": "Provide static and/or dynamic analysis text or files.", "warnings": warnings}), 400
    fw = generate(static, dynamic, meta)
    fw["warnings"] = warnings
    return jsonify(fw)


@app.post("/api/export/markdown")
def export_md():
    fw = request.get_json(silent=True)
    if not fw or "identity" not in fw:
        abort(400)
    name = "".join(c if c.isalnum() else "_" for c in fw["identity"]["name"]).strip("_") or "framework"
    return Response(to_markdown(fw), mimetype="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="{name}_framework.md"'})


@app.get("/api/campaign")
def campaign():
    fws = []
    for sid in _sample_ids():
        s = _load_sample(sid)
        fws.append((sid, generate(s["static"], s["dynamic"], s["meta"])))
    return jsonify(correlate(fws))


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": f"Upload exceeds {MAX_UPLOAD // (1024 * 1024)} MB"}), 413


if __name__ == "__main__":
    # local use; in production gunicorn imports `app` instead (see render.yaml)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5057)), debug=False)

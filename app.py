#!/usr/bin/env python3
"""
QEMU Web Frontend
A browser-based QEMU launcher with WebSocket terminal support.
"""

import os
import re
import json
import uuid
import shlex
import subprocess
import threading
import signal
import ssl
import logging
import time
import shutil
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
import werkzeug
from werkzeug.utils import secure_filename

# ─── Configuration ────────────────────────────────────────────────────────────

UPLOAD_FOLDER   = Path("uploads")
SESSION_FOLDER  = Path("sessions")
CERT_FILE       = Path("certs/server.crt")
KEY_FILE        = Path("certs/server.key")

MAX_MEMORY_MB   = 16384   # 16 GB
MAX_STORAGE_GB  = 512     # 512 GB
ALLOWED_EXT     = {".iso", ".img", ".qcow2", ".raw", ".vmdk"}
MAX_ISO_SIZE_GB = 50

SESSION_TTL_MINUTES      = 60
UPLOAD_TTL_MINUTES       = 60
UPLOAD_MAX_SIZE_GB       = 4
CLEANUP_INTERVAL_SECONDS = 30

QEMU_BINS = {
    "x86":    "qemu-system-i386",
    "x86_64": "qemu-system-x86_64",
    "arm32":  "qemu-system-arm",
    "arm64":  "qemu-system-aarch64",
    "riscv":  "qemu-system-riscv64",
}

QEMU_MACHINES = {
    "x86":    "pc",
    "x86_64": "q35",
    "arm32":  "virt",
    "arm64":  "virt",
    "riscv":  "virt",
}

# ─── Security: Flag injection patterns ────────────────────────────────────────

INJECTION_PATTERNS = [
    r"[;&|`$]",
    r"\.\./",
    r"rm\s+-",
    r"mkfs",
    r"dd\s+if=",
    r"chmod\s+777",
    r">/dev/",
    r"curl\s+.*\s*\|",
    r"wget\s+.*\s*\|",
    r"bash\s+-c",
    r"python.*-c",
    r"exec\s+",
    r"eval\s+",
    r"\$\(",
    r"`.*`",
    r"nc\s+-",
    r"ncat\s+",
    r"/etc/passwd",
    r"/etc/shadow",
    r"--daemonize",
    r"-monitor\s+stdio",
]


def sanitize_extra_flags(flags_str: str) -> tuple:
    if not flags_str or not flags_str.strip():
        return True, "", ""

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, flags_str, re.IGNORECASE):
            return False, "", f"Potentially malicious pattern detected: {pattern}"

    try:
        parts = shlex.split(flags_str)
    except ValueError as e:
        return False, "", f"Invalid flag syntax: {e}"

    clean_flags = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if part.startswith("-"):
            clean_flags.append(part)
            if i + 1 < len(parts) and not parts[i+1].startswith("-"):
                val = parts[i+1]
                if not re.match(r'^[\w,=./:\-@]+$', val):
                    return False, "", f"Unsafe value in flag: {val}"
                clean_flags.append(val)
                i += 1
        i += 1

    return True, " ".join(clean_flags), ""


# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_ISO_SIZE_GB * 1024 * 1024 * 1024

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("qemu-frontend")

UPLOAD_FOLDER.mkdir(exist_ok=True)
SESSION_FOLDER.mkdir(exist_ok=True)

active_sessions: dict = {}
sessions_lock = threading.Lock()

allocated_vnc_ports: set = set()
allocated_ws_ports: set = set()
ports_lock = threading.Lock()

# ─── Helper functions ─────────────────────────────────────────────────────────

def find_free_port(start=5900, end=5999) -> int:
    import socket
    with ports_lock:
        for port in range(start, end):
            if port in allocated_vnc_ports:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("0.0.0.0", port))
                    allocated_vnc_ports.add(port)
                    return port
                except OSError:
                    continue
    raise RuntimeError("No free VNC ports available (5900-5999)")


def release_vnc_port(port: int):
    with ports_lock:
        allocated_vnc_ports.discard(port)


def find_free_websockify_port(start=6900, end=6999) -> int:
    import socket
    with ports_lock:
        for port in range(start, end):
            if port in allocated_ws_ports:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("0.0.0.0", port))
                    allocated_ws_ports.add(port)
                    return port
                except OSError:
                    continue
    raise RuntimeError("No free websockify ports available (6900-6999)")


def release_ws_port(port: int):
    with ports_lock:
        allocated_ws_ports.discard(port)


def is_kvm_available() -> bool:
    kvm_path = "/dev/kvm"
    return os.path.exists(kvm_path) and os.access(kvm_path, os.R_OK | os.W_OK)


def shutil_which(name):
    return shutil.which(name)


def build_qemu_command(config: dict, iso_path: str, disk_path: str, vnc_port_offset: int) -> list:
    arch      = config["arch"]
    memory    = int(config["memory"])
    extra     = config.get("extra_flags", "")

    qemu_bin  = QEMU_BINS[arch]
    machine   = QEMU_MACHINES[arch]

    cmd = [
        qemu_bin,
        "-machine", machine,
        "-m", str(memory),
        "-cdrom", iso_path,
        "-drive", f"file={disk_path},format=qcow2,if=virtio",
        "-boot", "d",
        "-vnc", f":{vnc_port_offset}",
        "-no-reboot",
    ]

    if arch == "arm64":
        cmd += ["-cpu", "cortex-a57"]
        for bios_path in [
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        ]:
            if os.path.exists(bios_path):
                cmd += ["-bios", bios_path]
                break
    elif arch == "riscv":
        for fw_path in [
            "/usr/lib/riscv64-linux-gnu/opensbi/generic/fw_jump.elf",
            "/usr/share/opensbi/lp64/generic/firmware/fw_jump.elf",
        ]:
            if os.path.exists(fw_path):
                cmd += ["-kernel", fw_path]
                break

    if arch in ("x86", "x86_64") and is_kvm_available():
        cmd += ["-enable-kvm", "-cpu", "host"]
    elif arch in ("x86", "x86_64"):
        cmd += ["-cpu", "qemu64"]

    if extra.strip():
        cmd += shlex.split(extra)

    return cmd


# ─── noVNC static file proxy ─────────────────────────────────────────────────
# Serving noVNC files through Flask means the browser only needs to trust ONE
# SSL certificate (Flask's on port 8444). No second "trust this site" popup.

NOVNC_PATH = None
for _p in ["/usr/share/novnc", "/usr/share/novnc/web", "/opt/novnc"]:
    if os.path.isdir(_p):
        NOVNC_PATH = _p
        break


@app.route("/novnc/<path:filename>")
def novnc_static(filename):
    """Proxy noVNC static files through Flask so the browser trusts one cert."""
    if not NOVNC_PATH:
        return "noVNC not installed — run setup.sh", 503
    safe = os.path.realpath(os.path.join(NOVNC_PATH, filename))
    if not safe.startswith(os.path.realpath(NOVNC_PATH)):
        return "Forbidden", 403
    return send_from_directory(NOVNC_PATH, filename)


@app.route("/novnc/")
def novnc_index():
    if not NOVNC_PATH:
        return "noVNC not installed — run setup.sh", 503
    return send_from_directory(NOVNC_PATH, "vnc.html")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           max_memory=MAX_MEMORY_MB,
                           max_storage=MAX_STORAGE_GB)


@app.route("/upload", methods=["POST"])
def upload_iso():
    if "iso" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["iso"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"error": f"File type '{ext}' not allowed. Use: {', '.join(ALLOWED_EXT)}"}), 400

    uid = uuid.uuid4().hex[:8]
    safe_name = f"{uid}_{filename}"
    dest = UPLOAD_FOLDER / safe_name
    file.save(str(dest))

    logger.info(f"ISO uploaded: {safe_name} ({dest.stat().st_size // (1024*1024)} MB)")
    return jsonify({"filename": safe_name, "display_name": filename})


@app.route("/launch", methods=["POST"])
def launch_vm():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    iso_name = data.get("iso")
    arch     = data.get("arch", "x86_64")
    memory   = int(data.get("memory", 1024))
    storage  = int(data.get("storage", 20))
    extra    = data.get("extra_flags", "").strip()

    if arch not in QEMU_BINS:
        return jsonify({"error": f"Unknown arch: {arch}"}), 400

    memory = max(128, min(memory, MAX_MEMORY_MB))
    storage = max(1, min(storage, MAX_STORAGE_GB))

    iso_path = UPLOAD_FOLDER / secure_filename(iso_name)
    if not iso_path.exists():
        return jsonify({"error": "ISO not found — please upload it first"}), 400

    qemu_bin = QEMU_BINS[arch]
    if not shutil_which(qemu_bin):
        return jsonify({"error": f"QEMU binary '{qemu_bin}' not found. Run setup.sh to install it."}), 500

    is_safe, clean_flags, reason = sanitize_extra_flags(extra)
    if not is_safe:
        return jsonify({"error": f"Unsafe extra flags: {reason}"}), 400

    session_id = uuid.uuid4().hex
    session_dir = SESSION_FOLDER / session_id
    session_dir.mkdir()

    disk_path = str(session_dir / "disk.qcow2")
    result = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", disk_path, f"{storage}G"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return jsonify({"error": f"Failed to create disk image: {result.stderr}"}), 500

    try:
        vnc_port = find_free_port()
        vnc_offset = vnc_port - 5900
        ws_port = find_free_websockify_port()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    config = {"arch": arch, "memory": memory, "extra_flags": clean_flags}
    cmd = build_qemu_command(config, str(iso_path), disk_path, vnc_offset)

    logger.info(f"[{session_id}] Launching: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
    except Exception as e:
        release_vnc_port(vnc_port)
        release_ws_port(ws_port)
        return jsonify({"error": f"Failed to start QEMU: {e}"}), 500

    time.sleep(0.5)
    if proc.poll() is not None:
        stderr_out = proc.stderr.read().decode(errors="replace")
        release_vnc_port(vnc_port)
        release_ws_port(ws_port)
        logger.error(f"[{session_id}] QEMU failed immediately: {stderr_out}")
        return jsonify({"error": f"QEMU exited immediately: {stderr_out[:400]}"}), 500

    # Launch websockify — plain ws:// (no SSL) because Flask owns the SSL layer.
    # The browser connects to Flask over HTTPS/WSS and Flask's cert is already
    # trusted, so websockify only needs to bridge localhost VNC → localhost WS.
    ws_proc = None
    websockify_bin = shutil_which("websockify")
    if websockify_bin:
        try:
            ws_cmd = [
                websockify_bin,
                # NO --cert / --key: plain (unencrypted) websockify on localhost only
                "--web", NOVNC_PATH or "/usr/share/novnc",
                str(ws_port),
                f"127.0.0.1:{vnc_port}"
            ]
            ws_proc = subprocess.Popen(ws_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"[{session_id}] websockify (plain) started on port {ws_port} → VNC {vnc_port}")
        except Exception as e:
            logger.warning(f"websockify failed to start: {e}")
    else:
        logger.warning("websockify not found — in-browser VNC unavailable. Run setup.sh.")

    with sessions_lock:
        active_sessions[session_id] = {
            "process":    proc,
            "ws_process": ws_proc,
            "vnc_port":   vnc_port,
            "ws_port":    ws_port,
            "arch":       arch,
            "memory":     memory,
            "storage":    storage,
            "iso":        iso_name,
            "started":    datetime.now().isoformat(),
            "session_dir": str(session_dir),
        }

    threading.Thread(target=_watch_process, args=(session_id,), daemon=True).start()

    return jsonify({
        "session_id": session_id,
        "vnc_port":   vnc_port,
        "ws_port":    ws_port,
    })


def _watch_process(session_id: str):
    with sessions_lock:
        info = active_sessions.get(session_id)
    if not info:
        return
    proc = info["process"]
    proc.wait()
    try:
        stderr_out = proc.stderr.read().decode(errors="replace")
        if stderr_out:
            logger.warning(f"[{session_id}] QEMU stderr: {stderr_out[:500]}")
    except Exception:
        pass
    logger.info(f"[{session_id}] QEMU process exited (code {proc.returncode})")

    vnc_port = info.get("vnc_port")
    ws_port  = info.get("ws_port")
    if vnc_port:
        release_vnc_port(vnc_port)
    if ws_port:
        release_ws_port(ws_port)

    socketio.emit("vm_stopped", {"session_id": session_id}, room=session_id)


@app.route("/session/<session_id>")
def session_view(session_id: str):
    with sessions_lock:
        info = active_sessions.get(session_id)
    if not info:
        return render_template("error.html", message="Session not found or already terminated"), 404
    return render_template("session.html", session=info, session_id=session_id)


@app.route("/api/sessions")
def list_sessions():
    with sessions_lock:
        result = {}
        for sid, info in active_sessions.items():
            proc = info["process"]
            result[sid] = {
                "arch":    info["arch"],
                "memory":  info["memory"],
                "storage": info["storage"],
                "iso":     info["iso"],
                "started": info["started"],
                "running": proc.poll() is None,
                "vnc_port": info["vnc_port"],
                "ws_port":  info["ws_port"],
            }
    return jsonify(result)


@app.route("/api/session/<session_id>/stop", methods=["POST"])
def stop_session(session_id: str):
    with sessions_lock:
        info = active_sessions.get(session_id)
    if not info:
        return jsonify({"error": "Session not found"}), 404

    proc = info["process"]
    ws_proc = info.get("ws_process")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        proc.terminate()
    if ws_proc:
        try:
            ws_proc.terminate()
        except Exception:
            pass

    vnc_port = info.get("vnc_port")
    ws_port  = info.get("ws_port")
    if vnc_port:
        release_vnc_port(vnc_port)
    if ws_port:
        release_ws_port(ws_port)

    with sessions_lock:
        active_sessions.pop(session_id, None)

    return jsonify({"status": "stopped"})


@app.route("/api/validate_flags", methods=["POST"])
def validate_flags():
    data = request.get_json()
    flags = data.get("flags", "")
    is_safe, clean, reason = sanitize_extra_flags(flags)
    return jsonify({"safe": is_safe, "cleaned": clean, "reason": reason})


@app.route("/api/system_info")
def system_info():
    info = {}
    for arch, binary in QEMU_BINS.items():
        info[arch] = {
            "available": bool(shutil_which(binary)),
            "binary": binary,
        }
    return jsonify({
        "qemu": info,
        "kvm": is_kvm_available(),
        "websockify": bool(shutil_which("websockify")),
        "novnc": NOVNC_PATH is not None,
    })


# ─── SocketIO events ──────────────────────────────────────────────────────────

@socketio.on("join_session")
def on_join(data):
    session_id = data.get("session_id")
    join_room(session_id)
    with sessions_lock:
        info = active_sessions.get(session_id)
    if info:
        proc = info["process"]
        emit("session_status", {"running": proc.poll() is None})


@socketio.on("leave_session")
def on_leave(data):
    leave_room(data.get("session_id"))


# ─── Cleanup helpers ──────────────────────────────────────────────────────────

def parse_iso(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.utcnow()


def safe_unlink(path: Path):
    try:
        path.unlink()
    except Exception:
        pass


def safe_rmtree(path: Path):
    try:
        shutil.rmtree(str(path))
    except Exception:
        pass


def folder_size_bytes(folder: Path) -> int:
    total = 0
    for f in folder.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except Exception:
                pass
    return total


def terminate_session(sid: str, info: dict):
    proc = info["process"]
    ws_proc = info.get("ws_process")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        proc.terminate()
    if ws_proc:
        try:
            ws_proc.terminate()
        except Exception:
            pass
    vnc_port = info.get("vnc_port")
    ws_port  = info.get("ws_port")
    if vnc_port:
        release_vnc_port(vnc_port)
    if ws_port:
        release_ws_port(ws_port)


def cleanup_sessions():
    now = datetime.utcnow()
    expired = []
    with sessions_lock:
        for sid, info in list(active_sessions.items()):
            started = parse_iso(info.get("started", now.isoformat()))
            age = now - started
            proc = info["process"]
            if proc.poll() is not None:
                expired.append(sid)
                continue
            if age > timedelta(minutes=SESSION_TTL_MINUTES):
                logger.info(f"[cleanup] Session expired: {sid}")
                terminate_session(sid, info)
                expired.append(sid)
        for sid in expired:
            active_sessions.pop(sid, None)


def cleanup_uploads():
    now = datetime.utcnow()
    if not UPLOAD_FOLDER.exists():
        return
    for file in UPLOAD_FOLDER.iterdir():
        if not file.is_file():
            continue
        try:
            mtime = datetime.utcfromtimestamp(file.stat().st_mtime)
            if (now - mtime) > timedelta(minutes=UPLOAD_TTL_MINUTES):
                logger.info(f"[cleanup] Removing expired upload: {file.name}")
                safe_unlink(file)
        except Exception:
            pass


def enforce_upload_quota():
    max_bytes = UPLOAD_MAX_SIZE_GB * 1024 * 1024 * 1024
    if folder_size_bytes(UPLOAD_FOLDER) > max_bytes:
        logger.warning("[cleanup] Upload folder exceeded quota. Wiping uploads.")
        for f in UPLOAD_FOLDER.iterdir():
            if f.is_file():
                safe_unlink(f)
            elif f.is_dir():
                safe_rmtree(f)


def cleanup_orphan_session_dirs():
    if not SESSION_FOLDER.exists():
        return
    with sessions_lock:
        live = set(active_sessions.keys())
    for folder in SESSION_FOLDER.iterdir():
        if folder.is_dir() and folder.name not in live:
            logger.info(f"[cleanup] Removing orphaned session dir: {folder.name}")
            safe_rmtree(folder)


def cleanup_loop():
    while True:
        try:
            cleanup_sessions()
            cleanup_uploads()
            enforce_upload_quota()
            cleanup_orphan_session_dirs()
        except Exception as e:
            logger.error(f"[cleanup] {e}")
        time.sleep(CLEANUP_INTERVAL_SECONDS)


def start_cleanup_thread():
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        logger.info("Generating self-signed certificate...")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
            "-days", "3650", "-nodes",
            "-subj", "/CN=qemu-frontend/O=Local/C=US"
        ], check=True)

    start_cleanup_thread()

    logger.info("Starting QEMU Frontend on https://0.0.0.0:8444")
    socketio.run(
        app,
        host="0.0.0.0",
        port=8444,
        ssl_context=(str(CERT_FILE), str(KEY_FILE)),
        debug=False,
        allow_unsafe_werkzeug=True
    )

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
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
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

# QEMU binary map per architecture
QEMU_BINS = {
    "x86":    "qemu-system-i386",
    "x86_64": "qemu-system-x86_64",
    "arm32":  "qemu-system-arm",
    "arm64":  "qemu-system-aarch64",
    "riscv":  "qemu-system-riscv64",
}

# Default machine types per arch
QEMU_MACHINES = {
    "x86":    "pc",
    "x86_64": "q35",
    "arm32":  "virt",
    "arm64":  "virt",
    "riscv":  "virt",
}

# ─── Security: Flag injection patterns ────────────────────────────────────────

INJECTION_PATTERNS = [
    r"[;&|`$]",            # shell metacharacters
    r"\.\./",              # path traversal
    r"rm\s+-",             # rm commands
    r"mkfs",               # format commands
    r"dd\s+if=",           # dd overwrite
    r"chmod\s+777",        # dangerous permission
    r">/dev/",             # device writes
    r"curl\s+.*\s*\|",     # curl pipe
    r"wget\s+.*\s*\|",     # wget pipe
    r"bash\s+-c",          # bash exec
    r"python.*-c",         # python exec
    r"exec\s+",            # exec calls
    r"eval\s+",            # eval calls
    r"\$\(",               # command substitution
    r"`.*`",               # backtick execution
    r"nc\s+-",             # netcat
    r"ncat\s+",            # ncat
    r"/etc/passwd",        # sensitive files
    r"/etc/shadow",
    r"--daemonize",        # prevent QEMU daemonize (we manage that)
    r"-monitor\s+stdio",   # don't allow stdio monitor (we use our own)
]

ALLOWED_EXTRA_FLAGS_PATTERN = re.compile(
    r"^(-device\s+[\w,=.\-]+|-netdev\s+[\w,=.\-]+|-drive\s+[\w,=./\-]+"
    r"|-usb|-usbdevice\s+\w+|-boot\s+[a-z,=]+"
    r"|-vga\s+\w+|-display\s+\w+|-cpu\s+[\w,.\-]+"
    r"|-smp\s+[\d,=]+"
    r"|-rtc\s+[\w,=]+"
    r")*$",
    re.IGNORECASE
)


def sanitize_extra_flags(flags_str: str) -> tuple[bool, str, str]:
    """
    Returns (is_safe, sanitized_flags, reason_if_unsafe)
    """
    if not flags_str or not flags_str.strip():
        return True, "", ""

    # Check injection patterns
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, flags_str, re.IGNORECASE):
            return False, "", f"Potentially malicious pattern detected: {pattern}"

    # Split into individual flags for validation
    try:
        parts = shlex.split(flags_str)
    except ValueError as e:
        return False, "", f"Invalid flag syntax: {e}"

    # Rebuild cleaned flags
    clean_flags = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if part.startswith("-"):
            clean_flags.append(part)
            # consume the value if next part doesn't start with -
            if i + 1 < len(parts) and not parts[i+1].startswith("-"):
                val = parts[i+1]
                # validate value: only safe chars
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

# Active QEMU sessions: session_id -> {process, vnc_port, ...}
active_sessions: dict = {}
sessions_lock = threading.Lock()

# ─── Helper functions ─────────────────────────────────────────────────────────

def find_free_port(start=5900, end=5999) -> int:
    import socket
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free VNC ports available")


def find_free_websockify_port(start=6900, end=6999) -> int:
    import socket
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free websockify ports available")


def build_qemu_command(config: dict, iso_path: str, disk_path: str, vnc_port_offset: int) -> list[str]:
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

    # Architecture-specific tweaks
    if arch in ("arm64",):
        cmd += ["-cpu", "cortex-a57"]
        cmd += ["-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"]
    elif arch == "riscv":
        cmd += ["-kernel", "/usr/lib/riscv64-linux-gnu/opensbi/generic/fw_jump.elf"]

    # KVM acceleration (x86 only, if available)
    if arch in ("x86", "x86_64"):
        kvm_path = "/dev/kvm"
        if os.path.exists(kvm_path) and os.access(kvm_path, os.R_OK | os.W_OK):
            cmd += ["-enable-kvm", "-cpu", "host"]

    # Extra flags
    if extra.strip():
        cmd += shlex.split(extra)

    return cmd


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

    # Give it a unique name to avoid collisions
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

    # Validate arch
    if arch not in QEMU_BINS:
        return jsonify({"error": f"Unknown arch: {arch}"}), 400

    # Validate memory
    memory = max(128, min(memory, MAX_MEMORY_MB))

    # Validate storage
    storage = max(1, min(storage, MAX_STORAGE_GB))

    # Validate ISO
    iso_path = UPLOAD_FOLDER / secure_filename(iso_name)
    if not iso_path.exists():
        return jsonify({"error": "ISO not found — please upload it first"}), 400

    # Check QEMU binary exists
    qemu_bin = QEMU_BINS[arch]
    if not shutil_which(qemu_bin):
        return jsonify({"error": f"QEMU binary '{qemu_bin}' not found on this system"}), 500

    # Sanitize extra flags
    is_safe, clean_flags, reason = sanitize_extra_flags(extra)
    if not is_safe:
        return jsonify({"error": f"Unsafe extra flags: {reason}"}), 400

    # Create session
    session_id = uuid.uuid4().hex
    session_dir = SESSION_FOLDER / session_id
    session_dir.mkdir()

    # Create disk image
    disk_path = str(session_dir / "disk.qcow2")
    result = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", disk_path, f"{storage}G"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return jsonify({"error": f"Failed to create disk image: {result.stderr}"}), 500

    # Find free VNC port
    try:
        vnc_port = find_free_port()
        vnc_offset = vnc_port - 5900
        ws_port = find_free_websockify_port()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    # Build command
    config = {"arch": arch, "memory": memory, "extra_flags": clean_flags}
    cmd = build_qemu_command(config, str(iso_path), disk_path, vnc_offset)

    logger.info(f"[{session_id}] Launching: {' '.join(cmd)}")

    # Launch QEMU
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
    except Exception as e:
        return jsonify({"error": f"Failed to start QEMU: {e}"}), 500

    # Launch websockify (VNC → WebSocket bridge)
    ws_proc = None
    try:
        ws_proc = subprocess.Popen(
            ["websockify", "--web", "/usr/share/novnc/", str(ws_port), f"localhost:{vnc_port}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        logger.warning("websockify not found — VNC direct only")

    # Store session
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

    # Background thread to reap process
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
    logger.info(f"[{session_id}] QEMU process exited")
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

    with sessions_lock:
        active_sessions.pop(session_id, None)

    return jsonify({"status": "stopped"})


@app.route("/api/validate_flags", methods=["POST"])
def validate_flags():
    data = request.get_json()
    flags = data.get("flags", "")
    is_safe, clean, reason = sanitize_extra_flags(flags)
    return jsonify({"safe": is_safe, "cleaned": clean, "reason": reason})


def shutil_which(name):
    import shutil
    return shutil.which(name)


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


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Generate self-signed cert if needed
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

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(str(CERT_FILE), str(KEY_FILE))

    logger.info("Starting QEMU Frontend on https://0.0.0.0:8444")
    socketio.run(
        app,
        host="0.0.0.0",
        port=8444,
        ssl_context=(str(CERT_FILE), str(KEY_FILE)),
        debug=False,
        allow_unsafe_werkzeug=True
    )

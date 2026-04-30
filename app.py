#!/usr/bin/env python3
"""
QEMU Web Frontend
Browser-based QEMU launcher. VNC is proxied through Socket.IO (WSS) so the
browser only needs to trust one certificate — Flask's on port 8444.
No websockify required.
"""

import os
import re
import uuid
import shlex
import subprocess
import threading
import signal
import logging
import time
import shutil
import select
import socket as _socket
import base64
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename

# ─── Configuration ────────────────────────────────────────────────────────────

UPLOAD_FOLDER   = Path("uploads")
SESSION_FOLDER  = Path("sessions")
CERT_FILE       = Path("certs/server.crt")
KEY_FILE        = Path("certs/server.key")

MAX_MEMORY_MB   = 16384
MAX_STORAGE_GB  = 512
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

# ─── Security ─────────────────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    r"[;&|`$]", r"\.\./", r"rm\s+-", r"mkfs", r"dd\s+if=",
    r"chmod\s+777", r">/dev/", r"curl\s+.*\s*\|", r"wget\s+.*\s*\|",
    r"bash\s+-c", r"python.*-c", r"exec\s+", r"eval\s+",
    r"\$\(", r"`.*`", r"nc\s+-", r"ncat\s+",
    r"/etc/passwd", r"/etc/shadow",
    r"--daemonize", r"-monitor\s+stdio",
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
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                val = parts[i + 1]
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
ports_lock = threading.Lock()

# noVNC static files
NOVNC_PATH = None
for _p in ["/usr/share/novnc", "/usr/share/novnc/web", "/opt/novnc"]:
    if os.path.isdir(_p):
        NOVNC_PATH = _p
        break

# ─── Port helpers ─────────────────────────────────────────────────────────────

def find_free_port(start=5900, end=5999) -> int:
    with ports_lock:
        for port in range(start, end):
            if port in allocated_vnc_ports:
                continue
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
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


# ─── System helpers ───────────────────────────────────────────────────────────

def is_kvm_available() -> bool:
    return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)


def shutil_which(name):
    return shutil.which(name)


def build_qemu_command(config: dict, iso_path: str, disk_path: str, vnc_port_offset: int) -> list:
    arch         = config["arch"]
    memory       = int(config["memory"])
    extra        = config.get("extra_flags", "")
    kvm_override = config.get("kvm_override", "auto")  # "auto" | "force_on" | "force_off"

    cmd = [
        QEMU_BINS[arch],
        "-machine", QEMU_MACHINES[arch],
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

    # KVM decision
    if arch in ("x86", "x86_64"):
        if kvm_override == "force_on":
            use_kvm = True
        elif kvm_override == "force_off":
            use_kvm = False
        else:
            use_kvm = is_kvm_available()

        if use_kvm:
            cmd += ["-enable-kvm", "-cpu", "host"]
        else:
            cmd += ["-cpu", "qemu64"]

    if extra.strip():
        cmd += shlex.split(extra)

    return cmd


# ─── VNC Proxy via Socket.IO ─────────────────────────────────────────────────
#
# Architecture:
#   Browser  ←—WSS/Socket.IO—→  Flask (port 8444, already trusted)
#                                    ↕ TCP
#                               QEMU VNC (127.0.0.1:590x)
#
# No websockify needed. The browser never opens a second connection to a
# different port, so there is no mixed-content block and no second cert popup.
#
# Protocol: raw VNC bytes are base64-encoded over Socket.IO events:
#   vnc_start   →  server opens TCP to QEMU VNC
#   vnc_data    ←  server pushes VNC→browser bytes
#   vnc_send    →  browser pushes browser→VNC bytes
#   vnc_connected / vnc_disconnected / vnc_error  — lifecycle events

class VNCProxyThread(threading.Thread):
    def __init__(self, session_id: str, vnc_port: int):
        super().__init__(daemon=True)
        self.session_id = session_id
        self.vnc_port   = vnc_port
        self._stop_evt  = threading.Event()
        self._sock      = None

    def run(self):
        # Wait a moment for QEMU VNC to be ready
        for attempt in range(20):
            if self._stop_evt.is_set():
                return
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(("127.0.0.1", self.vnc_port))
                s.settimeout(None)
                self._sock = s
                break
            except Exception:
                time.sleep(1)
        else:
            logger.warning(f"[{self.session_id}] VNC proxy: could not connect after 20s")
            socketio.emit("vnc_error", {"reason": "VNC server not ready after 20s"},
                          room=self.session_id)
            return

        logger.info(f"[{self.session_id}] VNC proxy connected → 127.0.0.1:{self.vnc_port}")
        socketio.emit("vnc_connected", {}, room=self.session_id)

        while not self._stop_evt.is_set():
            try:
                ready, _, _ = select.select([self._sock], [], [], 0.5)
                if ready:
                    data = self._sock.recv(65536)
                    if not data:
                        break
                    socketio.emit(
                        "vnc_data",
                        {"b64": base64.b64encode(data).decode()},
                        room=self.session_id,
                    )
            except Exception as e:
                if not self._stop_evt.is_set():
                    logger.warning(f"[{self.session_id}] VNC read error: {e}")
                break

        self._close()
        socketio.emit("vnc_disconnected", {}, room=self.session_id)
        logger.info(f"[{self.session_id}] VNC proxy stopped")

    def send(self, data: bytes):
        if self._sock:
            try:
                self._sock.sendall(data)
            except Exception as e:
                logger.warning(f"[{self.session_id}] VNC write error: {e}")
                self._stop_evt.set()

    def stop(self):
        self._stop_evt.set()
        self._close()

    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


vnc_proxies: dict = {}
vnc_proxies_lock = threading.Lock()


# ─── noVNC static proxy ───────────────────────────────────────────────────────

@app.route("/novnc/")
def novnc_index():
    if not NOVNC_PATH:
        return "noVNC not installed — run setup.sh", 503
    return send_from_directory(NOVNC_PATH, "vnc.html")


@app.route("/novnc/<path:filename>")
def novnc_static(filename):
    if not NOVNC_PATH:
        return "noVNC not installed — run setup.sh", 503
    safe = os.path.realpath(os.path.join(NOVNC_PATH, filename))
    if not safe.startswith(os.path.realpath(NOVNC_PATH)):
        return "Forbidden", 403
    return send_from_directory(NOVNC_PATH, filename)


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
        return jsonify({"error": f"File type '{ext}' not allowed."}), 400
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

    iso_name     = data.get("iso")
    arch         = data.get("arch", "x86_64")
    memory       = int(data.get("memory", 1024))
    storage      = int(data.get("storage", 20))
    extra        = data.get("extra_flags", "").strip()
    kvm_override = data.get("kvm_override", "auto")

    if arch not in QEMU_BINS:
        return jsonify({"error": f"Unknown arch: {arch}"}), 400
    if kvm_override not in ("auto", "force_on", "force_off"):
        kvm_override = "auto"

    memory  = max(128, min(memory, MAX_MEMORY_MB))
    storage = max(1, min(storage, MAX_STORAGE_GB))

    iso_path = UPLOAD_FOLDER / secure_filename(iso_name)
    if not iso_path.exists():
        return jsonify({"error": "ISO not found — please upload it first"}), 400

    qemu_bin = QEMU_BINS[arch]
    if not shutil_which(qemu_bin):
        return jsonify({"error": f"QEMU binary '{qemu_bin}' not found. Run setup.sh."}), 500

    is_safe, clean_flags, reason = sanitize_extra_flags(extra)
    if not is_safe:
        return jsonify({"error": f"Unsafe extra flags: {reason}"}), 400

    session_id  = uuid.uuid4().hex
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
        vnc_port   = find_free_port()
        vnc_offset = vnc_port - 5900
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    config = {
        "arch": arch, "memory": memory,
        "extra_flags": clean_flags, "kvm_override": kvm_override,
    }
    cmd = build_qemu_command(config, str(iso_path), disk_path, vnc_offset)
    logger.info(f"[{session_id}] Launching: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
    except Exception as e:
        release_vnc_port(vnc_port)
        return jsonify({"error": f"Failed to start QEMU: {e}"}), 500

    time.sleep(0.5)
    if proc.poll() is not None:
        stderr_out = proc.stderr.read().decode(errors="replace")
        release_vnc_port(vnc_port)
        logger.error(f"[{session_id}] QEMU failed immediately: {stderr_out}")
        return jsonify({"error": f"QEMU exited immediately: {stderr_out[:400]}"}), 500

    with sessions_lock:
        active_sessions[session_id] = {
            "process":      proc,
            "vnc_port":     vnc_port,
            "arch":         arch,
            "memory":       memory,
            "storage":      storage,
            "iso":          iso_name,
            "started":      datetime.now().isoformat(),
            "session_dir":  str(session_dir),
            "kvm_override": kvm_override,
        }

    threading.Thread(target=_watch_process, args=(session_id,), daemon=True).start()
    return jsonify({"session_id": session_id, "vnc_port": vnc_port})


def _watch_process(session_id: str):
    with sessions_lock:
        info = active_sessions.get(session_id)
    if not info:
        return
    info["process"].wait()
    try:
        stderr_out = info["process"].stderr.read().decode(errors="replace")
        if stderr_out:
            logger.warning(f"[{session_id}] QEMU stderr: {stderr_out[:500]}")
    except Exception:
        pass
    logger.info(f"[{session_id}] QEMU exited (code {info['process'].returncode})")
    release_vnc_port(info.get("vnc_port", 0))
    with vnc_proxies_lock:
        proxy = vnc_proxies.pop(session_id, None)
    if proxy:
        proxy.stop()
    socketio.emit("vm_stopped", {"session_id": session_id}, room=session_id)


@app.route("/session/<session_id>")
def session_view(session_id: str):
    with sessions_lock:
        info = active_sessions.get(session_id)
    if not info:
        return render_template("error.html", message="Session not found or already terminated"), 404
    return render_template("session.html", session=info, session_id=session_id,
                           novnc_available=NOVNC_PATH is not None)


@app.route("/api/sessions")
def list_sessions():
    with sessions_lock:
        result = {
            sid: {
                "arch": i["arch"], "memory": i["memory"], "storage": i["storage"],
                "iso": i["iso"], "started": i["started"],
                "running": i["process"].poll() is None,
                "vnc_port": i["vnc_port"],
            }
            for sid, i in active_sessions.items()
        }
    return jsonify(result)


@app.route("/api/session/<session_id>/stop", methods=["POST"])
def stop_session(session_id: str):
    with sessions_lock:
        info = active_sessions.pop(session_id, None)
    if not info:
        return jsonify({"error": "Session not found"}), 404
    proc = info["process"]
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        proc.terminate()
    release_vnc_port(info.get("vnc_port", 0))
    with vnc_proxies_lock:
        proxy = vnc_proxies.pop(session_id, None)
    if proxy:
        proxy.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/validate_flags", methods=["POST"])
def validate_flags():
    data  = request.get_json()
    flags = data.get("flags", "")
    is_safe, clean, reason = sanitize_extra_flags(flags)
    return jsonify({"safe": is_safe, "cleaned": clean, "reason": reason})


@app.route("/api/system_info")
def system_info():
    return jsonify({
        "qemu": {
            arch: {"available": bool(shutil_which(binary)), "binary": binary}
            for arch, binary in QEMU_BINS.items()
        },
        "kvm":        is_kvm_available(),
        "novnc":      NOVNC_PATH is not None,
        "websockify": bool(shutil_which("websockify")),
    })


# ─── Socket.IO events ────────────────────────────────────────────────────────

@socketio.on("join_session")
def on_join(data):
    session_id = data.get("session_id")
    join_room(session_id)
    with sessions_lock:
        info = active_sessions.get(session_id)
    if info:
        emit("session_status", {"running": info["process"].poll() is None})


@socketio.on("leave_session")
def on_leave(data):
    leave_room(data.get("session_id"))


@socketio.on("vnc_start")
def on_vnc_start(data):
    session_id = data.get("session_id")
    with sessions_lock:
        info = active_sessions.get(session_id)
    if not info:
        emit("vnc_error", {"reason": "Session not found"})
        return
    with vnc_proxies_lock:
        old = vnc_proxies.pop(session_id, None)
        if old:
            old.stop()
        proxy = VNCProxyThread(session_id, info["vnc_port"])
        vnc_proxies[session_id] = proxy
    proxy.start()


@socketio.on("vnc_send")
def on_vnc_send(data):
    session_id = data.get("session_id")
    with vnc_proxies_lock:
        proxy = vnc_proxies.get(session_id)
    if proxy:
        proxy.send(base64.b64decode(data.get("b64", "")))


@socketio.on("vnc_stop")
def on_vnc_stop(data):
    session_id = data.get("session_id")
    with vnc_proxies_lock:
        proxy = vnc_proxies.pop(session_id, None)
    if proxy:
        proxy.stop()


# ─── Cleanup ──────────────────────────────────────────────────────────────────

def parse_iso(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.utcnow()


def safe_unlink(p: Path):
    try: p.unlink()
    except Exception: pass


def safe_rmtree(p: Path):
    try: shutil.rmtree(str(p))
    except Exception: pass


def folder_size_bytes(folder: Path) -> int:
    return sum(f.stat().st_size for f in folder.rglob("*") if f.is_file())


def cleanup_loop():
    while True:
        try:
            now = datetime.utcnow()
            # sessions
            expired = []
            with sessions_lock:
                for sid, info in list(active_sessions.items()):
                    if info["process"].poll() is not None:
                        expired.append(sid)
                        continue
                    if (now - parse_iso(info.get("started", ""))) > timedelta(minutes=SESSION_TTL_MINUTES):
                        try: os.killpg(os.getpgid(info["process"].pid), signal.SIGTERM)
                        except Exception: info["process"].terminate()
                        release_vnc_port(info.get("vnc_port", 0))
                        expired.append(sid)
                for sid in expired:
                    active_sessions.pop(sid, None)
            # uploads
            for f in UPLOAD_FOLDER.iterdir():
                if f.is_file():
                    try:
                        mtime = datetime.utcfromtimestamp(f.stat().st_mtime)
                        if (now - mtime) > timedelta(minutes=UPLOAD_TTL_MINUTES):
                            safe_unlink(f)
                    except Exception:
                        pass
            # quota
            if folder_size_bytes(UPLOAD_FOLDER) > UPLOAD_MAX_SIZE_GB * 1024**3:
                for f in UPLOAD_FOLDER.iterdir():
                    safe_unlink(f) if f.is_file() else safe_rmtree(f)
            # orphan dirs
            with sessions_lock:
                live = set(active_sessions.keys())
            for folder in SESSION_FOLDER.iterdir():
                if folder.is_dir() and folder.name not in live:
                    safe_rmtree(folder)
        except Exception as e:
            logger.error(f"[cleanup] {e}")
        time.sleep(CLEANUP_INTERVAL_SECONDS)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess as _sp
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        logger.info("Generating self-signed certificate...")
        _sp.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
            "-days", "3650", "-nodes",
            "-subj", "/CN=qemu-frontend/O=Local/C=US"
        ], check=True)

    threading.Thread(target=cleanup_loop, daemon=True).start()

    logger.info("Starting QEMU Frontend on https://0.0.0.0:8444")
    socketio.run(
        app,
        host="0.0.0.0",
        port=8444,
        ssl_context=(str(CERT_FILE), str(KEY_FILE)),
        debug=False,
        allow_unsafe_werkzeug=True
    )

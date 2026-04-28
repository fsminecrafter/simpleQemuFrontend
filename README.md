# QEMU Web Frontend

A browser-based QEMU launcher with drag-and-drop ISO upload, in-browser VNC, and a clean dark/light UI.

## Quick Start

```bash
sudo bash setup.sh
```

Then open: **https://localhost:8444**

> **Note:** Your browser will warn about the self-signed certificate. Click **Advanced → Proceed** to continue.

---

## Troubleshooting

If you cannot start a session, maybe KVM is disabled on your device. And if KVM is not installed then run

```
nano app.py
```

And edit the is_kvm_available() function and change the 

return, to

```
return False
```

---

If the session wont ever connect then your browser is propably just declining the connection

try connecting to https://your-ip-address:6900/ with your web browser

and click thrust website, now your vnc should work.

## Features

- **Drag & Drop ISO** — upload `.iso`, `.img`, `.qcow2`, `.raw`, `.vmdk`
- **Architecture selection** — x86, x86_64, arm32, arm64, riscv
- **Memory slider** — configurable max (default 16 GB)
- **Storage slider** — configurable max (default 512 GB), with import existing disk
- **Extra flags** — validated against injection patterns before passing to QEMU
- **In-browser VNC** — via noVNC + websockify (auto-detected)
- **Session management** — list, connect, stop active VMs
- **Dark / Light mode** — toggle with a switch, persisted in localStorage
- **HTTPS** — self-signed certificate auto-generated on first run
- **systemd service** — optional autoboot setup via `setup.sh`

---

## Manual Setup

### Requirements

```bash
# Debian/Ubuntu
sudo apt install python3 python3-pip python3-venv \
  qemu-system-x86 qemu-system-arm qemu-system-misc \
  qemu-utils websockify novnc openssl

# Fedora/RHEL
sudo dnf install python3 python3-pip qemu qemu-img openssl

# Arch
sudo pacman -S python python-pip qemu websockify
```

### Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate SSL certificate (or let app.py do it automatically)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -days 3650 -nodes -subj "/CN=localhost"
```

### Run

```bash
python3 app.py
# or
venv/bin/python app.py
```

---

## Configuration

Edit `app.py` top section:

```python
MAX_MEMORY_MB   = 16384   # Max RAM slider value (MB)
MAX_STORAGE_GB  = 512     # Max storage slider value (GB)
MAX_ISO_SIZE_GB = 50      # Max upload size
PORT            = 8444    # HTTPS port
```

---

## Security

- Extra QEMU flags are validated against a list of injection patterns (shell metacharacters, rm, dd, curl|pipe, etc.)
- Only allow-listed flag prefixes pass through (`-device`, `-netdev`, `-drive`, `-vga`, `-cpu`, `-smp`, etc.)
- Uploaded filenames are sanitized with `werkzeug.secure_filename`
- File type and extension validation on upload
- KVM is only enabled when `/dev/kvm` is accessible

---

## Architecture Notes

| Arch   | QEMU Binary          | Default Machine | Notes                  |
|--------|----------------------|-----------------|------------------------|
| x86    | qemu-system-i386     | pc              | KVM if available       |
| x86_64 | qemu-system-x86_64   | q35             | KVM if available       |
| arm32  | qemu-system-arm      | virt            |                        |
| arm64  | qemu-system-aarch64  | virt            | Needs UEFI firmware    |
| riscv  | qemu-system-riscv64  | virt            | Needs OpenSBI firmware |

---

## Systemd Service

```bash
# Status
sudo systemctl status qemu-frontend

# Logs
sudo journalctl -u qemu-frontend -f

# Restart
sudo systemctl restart qemu-frontend
```

---

## VNC Access

VMs expose VNC on ports **5900–5999**. If `websockify` and `novnc` are installed, the session page connects automatically in-browser. Otherwise, use any VNC client:

```
vncviewer localhost:5900
```

---

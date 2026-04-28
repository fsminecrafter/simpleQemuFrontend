#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║          QEMU Web Frontend — Setup Script                   ║
# ║  Installs dependencies, configures firewall, SSL, systemd   ║
# ╚══════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✓${RESET} $*"; }
info() { echo -e "${CYAN}  ▶${RESET} $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET} $*"; }
err()  { echo -e "${RED}  ✗${RESET} $*"; exit 1; }
head() { echo -e "\n${BOLD}${CYAN}══ $* ${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR"
APP_FILE="$APP_DIR/app.py"
SERVICE_NAME="qemu-frontend"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PORT=8444

banner() {
  echo -e "${CYAN}"
  echo '   ██████╗ ███████╗███╗   ███╗██╗   ██╗'
  echo '  ██╔═══██╗██╔════╝████╗ ████║██║   ██║'
  echo '  ██║   ██║█████╗  ██╔████╔██║██║   ██║'
  echo '  ██║▄▄ ██║██╔══╝  ██║╚██╔╝██║██║   ██║'
  echo '  ╚██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝'
  echo '   ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ '
  echo -e "${RESET}"
  echo -e "  ${BOLD}QEMU Web Frontend — Setup Script${RESET}"
  echo -e "  ${CYAN}https://0.0.0.0:${PORT}${RESET}\n"
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some steps (firewall, systemd) require sudo."
    warn "Re-run with: sudo bash setup.sh"
    echo ""
  fi
}

detect_os() {
  if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update -qq"
  elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_INSTALL="dnf install -y"
    PKG_UPDATE="dnf check-update || true"
  elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_INSTALL="yum install -y"
    PKG_UPDATE="yum check-update || true"
  elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
    PKG_INSTALL="pacman -S --noconfirm"
    PKG_UPDATE="pacman -Sy"
  else
    err "No supported package manager found (apt/dnf/yum/pacman)"
  fi
  ok "Detected package manager: $PKG_MANAGER"
}

ask_yn() {
  local prompt="$1" default="${2:-y}"
  local yn_str
  [[ "$default" == "y" ]] && yn_str="[Y/n]" || yn_str="[y/N]"
  read -rp "  ${YELLOW}?${RESET} $prompt $yn_str " reply
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ── Install system packages ──────────────────────────────────────
install_system_deps() {
  head "Installing System Dependencies"
  info "Updating package lists…"
  $PKG_UPDATE 2>/dev/null || true

  local pkgs=()

  # ── Python ──
  if ! command -v python3 &>/dev/null; then
    pkgs+=(python3)
    warn "python3 not found — will install"
  else
    ok "python3 $(python3 --version 2>&1 | awk '{print $2}')"
  fi

  if ! command -v pip3 &>/dev/null; then
    pkgs+=(python3-pip)
  else
    ok "pip3 present"
  fi

  # python3-venv for Debian/Ubuntu
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    if ! python3 -c "import venv" &>/dev/null 2>&1; then
      pkgs+=(python3-venv)
    fi
  fi

  # ── OpenSSL ──
  if ! command -v openssl &>/dev/null; then
    pkgs+=(openssl)
  else
    ok "openssl present"
  fi

  # ── QEMU — install ALL emulators ──
  head "Installing QEMU Emulators"
  info "Installing all QEMU system emulators (x86, ARM, RISC-V, etc.)…"

  if [[ "$PKG_MANAGER" == "apt" ]]; then
    local qemu_pkgs=(
      qemu-system          # meta-package: all architectures
      qemu-system-x86      # x86 + x86_64 (qemu-system-i386, qemu-system-x86_64)
      qemu-system-arm      # arm32 + arm64 (qemu-system-arm, qemu-system-aarch64)
      qemu-system-misc     # riscv64, s390x, and others
      qemu-utils           # qemu-img
    )
    for pkg in "${qemu_pkgs[@]}"; do
      if ! dpkg -l "$pkg" &>/dev/null 2>&1; then
        pkgs+=("$pkg")
      else
        ok "$pkg already installed"
      fi
    done

  elif [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
    local qemu_pkgs=(
      qemu-system-x86
      qemu-system-arm
      qemu-system-aarch64
      qemu-system-riscv
      qemu-img
      qemu-common
    )
    for pkg in "${qemu_pkgs[@]}"; do
      pkgs+=("$pkg")
    done

  elif [[ "$PKG_MANAGER" == "pacman" ]]; then
    local qemu_pkgs=(qemu-full qemu-img)
    for pkg in "${qemu_pkgs[@]}"; do
      if ! pacman -Qi "$pkg" &>/dev/null 2>&1; then
        pkgs+=("$pkg")
      else
        ok "$pkg already installed"
      fi
    done
  fi

  # ── ARM64 UEFI firmware ──
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    if ! dpkg -l qemu-efi-aarch64 &>/dev/null 2>&1; then
      pkgs+=(qemu-efi-aarch64)
      info "Adding ARM64 UEFI firmware (qemu-efi-aarch64)"
    else
      ok "qemu-efi-aarch64 already installed"
    fi
  fi

  # ── noVNC + websockify ──
  head "Installing noVNC and websockify"
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    local novnc_pkgs=()
    if ! dpkg -l novnc &>/dev/null 2>&1; then
      novnc_pkgs+=(novnc)
    else
      ok "novnc already installed"
    fi
    if ! dpkg -l websockify &>/dev/null 2>&1; then
      novnc_pkgs+=(websockify)
    else
      ok "websockify already installed"
    fi
    pkgs+=("${novnc_pkgs[@]}")

  elif [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
    # noVNC may not be in default repos — try pip fallback
    if ! command -v websockify &>/dev/null; then
      warn "websockify not in repos — will install via pip after"
    fi
    if ! rpm -q novnc &>/dev/null 2>&1; then
      pkgs+=(novnc) 2>/dev/null || true
    fi

  elif [[ "$PKG_MANAGER" == "pacman" ]]; then
    if ! pacman -Qi novnc &>/dev/null 2>&1; then
      pkgs+=(novnc)
    fi
  fi

  # ── Install collected packages ──
  if [[ ${#pkgs[@]} -gt 0 ]]; then
    info "Installing packages: ${pkgs[*]}"
    $PKG_INSTALL "${pkgs[@]}" || warn "Some packages may have failed — check output above"
  else
    ok "All system packages already present"
  fi

  # ── Verify QEMU binaries ──
  head "Verifying QEMU Binaries"
  local qemu_bins=(
    qemu-system-i386
    qemu-system-x86_64
    qemu-system-arm
    qemu-system-aarch64
    qemu-system-riscv64
    qemu-img
  )
  local missing_bins=()
  for bin in "${qemu_bins[@]}"; do
    if command -v "$bin" &>/dev/null; then
      ok "$bin → $(command -v "$bin")"
    else
      warn "$bin not found"
      missing_bins+=("$bin")
    fi
  done
  if [[ ${#missing_bins[@]} -gt 0 ]]; then
    warn "Some QEMU binaries are missing: ${missing_bins[*]}"
    warn "These architectures will be unavailable in the frontend."
  fi

  # ── Verify noVNC ──
  head "Verifying noVNC / websockify"
  local novnc_found=false
  for p in /usr/share/novnc /usr/share/novnc/web /opt/novnc; do
    if [[ -d "$p" ]]; then
      ok "noVNC found at: $p"
      novnc_found=true
      break
    fi
  done

  if ! $novnc_found; then
    warn "noVNC web directory not found. Trying pip install…"
    install_novnc_pip
  fi

  if command -v websockify &>/dev/null; then
    ok "websockify found: $(command -v websockify)"
  else
    warn "websockify not found. Trying pip install…"
    pip3 install websockify 2>/dev/null || \
      warn "pip install websockify failed — in-browser VNC will not work"
  fi

  ok "System packages done"
}

install_novnc_pip() {
  info "Installing noVNC via pip…"
  pip3 install novnc 2>/dev/null || true

  # Try downloading from GitHub as a last resort
  if ! [[ -d /usr/share/novnc ]]; then
    if command -v git &>/dev/null; then
      info "Cloning noVNC from GitHub to /opt/novnc…"
      git clone --depth=1 https://github.com/novnc/noVNC.git /opt/novnc 2>/dev/null || \
        warn "Could not clone noVNC. In-browser VNC will fall back to direct VNC info."
    else
      warn "git not found — cannot clone noVNC. Install git and re-run, or install novnc manually."
    fi
  fi
}

# ── Python deps ──────────────────────────────────────────────────
install_python_deps() {
  head "Installing Python Dependencies"

  VENV_DIR="$APP_DIR/venv"
  if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR"
    python3 -m venv "$VENV_DIR" || {
      warn "venv creation failed — installing to user site"
      VENV_DIR=""
    }
  fi

  if [[ -n "$VENV_DIR" ]]; then
    PIP="$VENV_DIR/bin/pip"
    PYTHON="$VENV_DIR/bin/python"
    ok "Using venv: $VENV_DIR"
  else
    PIP="pip3"
    PYTHON="python3"
  fi

  $PIP install --upgrade pip -q
  $PIP install -r "$APP_DIR/requirements.txt"
  ok "Python dependencies installed"
}

# ── SSL Certificate ──────────────────────────────────────────────
setup_ssl() {
  head "SSL Certificate"
  CERT_DIR="$APP_DIR/certs"
  mkdir -p "$CERT_DIR"

  if [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]]; then
    ok "Certificate already exists at $CERT_DIR/"
    return
  fi

  info "Generating self-signed certificate (10 years)…"
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 3650 -nodes \
    -subj "/CN=$(hostname -f 2>/dev/null || echo localhost)/O=QEMU-Frontend/C=US" \
    2>/dev/null
  chmod 600 "$CERT_DIR/server.key"
  ok "Certificate generated: $CERT_DIR/server.crt"
  warn "This is a self-signed cert — your browser will show a warning. Accept it to continue."
}

# ── Firewall ─────────────────────────────────────────────────────
setup_firewall() {
  head "Firewall Configuration"
  if ! ask_yn "Configure firewall to allow port $PORT?"; then
    info "Skipping firewall setup"
    return
  fi

  if command -v ufw &>/dev/null; then
    info "Using ufw…"
    ufw allow "$PORT/tcp" comment "QEMU Web Frontend" || warn "ufw rule failed"
    ok "ufw: port $PORT allowed"
  fi

  if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    info "Using firewalld…"
    firewall-cmd --permanent --add-port="$PORT/tcp" || warn "firewalld rule failed"
    firewall-cmd --reload || true
    ok "firewalld: port $PORT allowed"
  fi

  if ! command -v ufw &>/dev/null && ! command -v firewall-cmd &>/dev/null; then
    if command -v iptables &>/dev/null; then
      iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || warn "iptables rule failed"
      ok "iptables: port $PORT allowed"
    else
      warn "No firewall tool found — make sure port $PORT is accessible"
    fi
  fi

  if ask_yn "Also allow VNC port range 5900-5999 (for external VNC clients)?"; then
    if command -v ufw &>/dev/null; then
      ufw allow 5900:5999/tcp comment "QEMU VNC" || true
    fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
      firewall-cmd --permanent --add-port=5900-5999/tcp || true
      firewall-cmd --reload || true
    fi
    ok "VNC port range opened"
  fi
}

# ── KVM ──────────────────────────────────────────────────────────
setup_kvm() {
  head "KVM Acceleration"
  if [[ -e /dev/kvm ]]; then
    ok "/dev/kvm exists"
    local user="${SUDO_USER:-$(whoami)}"
    if groups "$user" 2>/dev/null | grep -q kvm; then
      ok "User '$user' already in kvm group"
    else
      if ask_yn "Add user '$user' to the kvm group (enables hardware acceleration)?"; then
        usermod -aG kvm "$user" || warn "Could not add to kvm group"
        ok "Added $user to kvm group (log out/in to take effect)"
      fi
    fi
  else
    warn "/dev/kvm not found — KVM acceleration unavailable"
    warn "This is normal in VMs or systems without VT-x/AMD-V enabled in BIOS"
    warn "Emulation will still work, just slower"
  fi
}

# ── Systemd service ──────────────────────────────────────────────
setup_service() {
  head "Systemd Service"
  if ! ask_yn "Install systemd service for autostart on boot?"; then
    info "Skipping systemd service"
    return
  fi

  [[ $EUID -ne 0 ]] && err "Root required to install systemd service. Run: sudo bash setup.sh"

  local run_user="${SUDO_USER:-root}"
  local python_bin
  if [[ -f "$APP_DIR/venv/bin/python" ]]; then
    python_bin="$APP_DIR/venv/bin/python"
  else
    python_bin="$(command -v python3)"
  fi

  cat > "$SERVICE_FILE" << EOF
[Unit]
Description=QEMU Web Frontend
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${run_user}
WorkingDirectory=${APP_DIR}
ExecStart=${python_bin} ${APP_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=${APP_DIR}/uploads ${APP_DIR}/sessions ${APP_DIR}/certs

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  ok "Service installed: $SERVICE_FILE"

  if ask_yn "Start the service now?"; then
    systemctl start "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      ok "Service started successfully"
    else
      warn "Service may have failed. Check: journalctl -u $SERVICE_NAME -n 30"
    fi
  fi

  info "Service management:"
  echo "    Start:   sudo systemctl start $SERVICE_NAME"
  echo "    Stop:    sudo systemctl stop $SERVICE_NAME"
  echo "    Status:  sudo systemctl status $SERVICE_NAME"
  echo "    Logs:    sudo journalctl -u $SERVICE_NAME -f"
}

# ── Directory setup ──────────────────────────────────────────────
setup_dirs() {
  head "Directory Setup"
  for d in uploads sessions certs; do
    mkdir -p "$APP_DIR/$d"
    ok "Created: $APP_DIR/$d"
  done
  chmod 750 "$APP_DIR/uploads" "$APP_DIR/sessions"
}

# ── Summary ──────────────────────────────────────────────────────
print_summary() {
  head "Setup Complete"
  echo ""
  echo -e "  ${BOLD}Access your QEMU Frontend at:${RESET}"
  echo -e "  ${GREEN}https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost):${PORT}${RESET}"
  echo -e "  ${GREEN}https://localhost:${PORT}${RESET}"
  echo ""
  echo -e "  ${BOLD}To start manually:${RESET}"
  if [[ -f "$APP_DIR/venv/bin/python" ]]; then
    echo -e "  ${CYAN}cd $APP_DIR && venv/bin/python app.py${RESET}"
  else
    echo -e "  ${CYAN}cd $APP_DIR && python3 app.py${RESET}"
  fi
  echo ""

  # Final status check
  echo -e "  ${BOLD}Component Status:${RESET}"
  for bin in qemu-system-i386 qemu-system-x86_64 qemu-system-arm qemu-system-aarch64 qemu-system-riscv64; do
    if command -v "$bin" &>/dev/null; then
      echo -e "  ${GREEN}✓${RESET} $bin"
    else
      echo -e "  ${RED}✗${RESET} $bin (unavailable)"
    fi
  done
  for tool in websockify qemu-img openssl; do
    if command -v "$tool" &>/dev/null; then
      echo -e "  ${GREEN}✓${RESET} $tool"
    else
      echo -e "  ${YELLOW}⚠${RESET} $tool (not found)"
    fi
  done
  for p in /usr/share/novnc /opt/novnc; do
    if [[ -d "$p" ]]; then
      echo -e "  ${GREEN}✓${RESET} noVNC at $p"
      break
    fi
  done
  echo ""

  warn "Browser will show a certificate warning — click 'Advanced' → 'Proceed'"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────
main() {
  clear
  banner
  check_root
  detect_os
  setup_dirs
  install_system_deps
  install_python_deps
  setup_ssl
  setup_kvm

  if [[ $EUID -eq 0 ]]; then
    setup_firewall
    setup_service
  else
    warn "Skipping firewall and systemd setup (not root)"
    warn "Re-run with sudo for full setup"
  fi

  print_summary
}

main "$@"

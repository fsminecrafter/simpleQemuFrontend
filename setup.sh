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

  # ── QEMU ──
  head "Installing QEMU Emulators"
  info "Installing all QEMU system emulators (x86, ARM, RISC-V, etc.)…"

  if [[ "$PKG_MANAGER" == "apt" ]]; then
    local qemu_pkgs=(
      qemu-system
      qemu-system-x86
      qemu-system-arm
      qemu-system-misc
      qemu-utils
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
      qemu-system-x86 qemu-system-arm qemu-system-aarch64
      qemu-system-riscv qemu-img qemu-common
    )
    for pkg in "${qemu_pkgs[@]}"; do pkgs+=("$pkg"); done

  elif [[ "$PKG_MANAGER" == "pacman" ]]; then
    local qemu_pkgs=(qemu-full qemu-img)
    for pkg in "${qemu_pkgs[@]}"; do
      if ! pacman -Qi "$pkg" &>/dev/null 2>&1; then pkgs+=("$pkg"); else ok "$pkg already installed"; fi
    done
  fi

  if [[ "$PKG_MANAGER" == "apt" ]]; then
    if ! dpkg -l qemu-efi-aarch64 &>/dev/null 2>&1; then
      pkgs+=(qemu-efi-aarch64)
    else
      ok "qemu-efi-aarch64 already installed"
    fi
  fi

  # ── noVNC + websockify ──
  head "Installing noVNC and websockify"
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    local novnc_pkgs=()
    ! dpkg -l novnc &>/dev/null 2>&1      && novnc_pkgs+=(novnc)      || ok "novnc already installed"
    ! dpkg -l websockify &>/dev/null 2>&1 && novnc_pkgs+=(websockify) || ok "websockify already installed"
    pkgs+=("${novnc_pkgs[@]}")
  elif [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
    if ! command -v websockify &>/dev/null; then
      warn "websockify not in repos — will install via pip after"
    fi
    rpm -q novnc &>/dev/null 2>&1 || pkgs+=(novnc) 2>/dev/null || true
  elif [[ "$PKG_MANAGER" == "pacman" ]]; then
    pacman -Qi novnc &>/dev/null 2>&1 || pkgs+=(novnc)
  fi

  if [[ ${#pkgs[@]} -gt 0 ]]; then
    info "Installing packages: ${pkgs[*]}"
    $PKG_INSTALL "${pkgs[@]}" || warn "Some packages may have failed — check output above"
  else
    ok "All system packages already present"
  fi

  # ── Verify QEMU binaries ──
  head "Verifying QEMU Binaries"
  local qemu_bins=(
    qemu-system-i386 qemu-system-x86_64 qemu-system-arm
    qemu-system-aarch64 qemu-system-riscv64 qemu-img
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
  [[ ${#missing_bins[@]} -gt 0 ]] && warn "Missing binaries: ${missing_bins[*]} — these archs will be unavailable"

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
  $novnc_found || install_novnc_pip

  if command -v websockify &>/dev/null; then
    ok "websockify found: $(command -v websockify)"
  else
    warn "websockify not found. Trying pip install…"
    pip3 install websockify 2>/dev/null || warn "pip install websockify failed"
  fi

  ok "System packages done"
}

install_novnc_pip() {
  info "Installing noVNC via pip…"
  pip3 install novnc 2>/dev/null || true
  if ! [[ -d /usr/share/novnc ]]; then
    if command -v git &>/dev/null; then
      info "Cloning noVNC from GitHub to /opt/novnc…"
      git clone --depth=1 https://github.com/novnc/noVNC.git /opt/novnc 2>/dev/null || \
        warn "Could not clone noVNC."
    else
      warn "git not found — cannot clone noVNC."
    fi
  fi
}

# ── Python deps ──────────────────────────────────────────────────
install_python_deps() {
  head "Installing Python Dependencies"

  if [[ "$PKG_MANAGER" == "apt" ]]; then
    info "Ensuring python3-venv is installed..."
    apt-get install -y python3-venv python3-pip -qq || warn "Could not install python3-venv via apt"
  elif [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
    $PKG_INSTALL python3-venv python3-pip 2>/dev/null || true
  fi

  VENV_DIR="$APP_DIR/venv"

  if [[ -d "$VENV_DIR" ]]; then
    info "Removing existing venv at $VENV_DIR..."
    rm -rf "$VENV_DIR"
  fi

  info "Creating fresh virtual environment at $VENV_DIR..."
  if python3 -m venv "$VENV_DIR"; then
    ok "Virtual environment created"
  else
    err "python3 -m venv failed. Try: sudo apt install python3-venv"
  fi

  PIP="$VENV_DIR/bin/pip"
  PYTHON="$VENV_DIR/bin/python"

  info "Upgrading pip..."
  "$PIP" install --upgrade pip -q

  info "Installing requirements..."
  "$PIP" install -r "$APP_DIR/requirements.txt"
  ok "Python dependencies installed into $VENV_DIR"
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
  warn "Self-signed cert — browser will warn once. Click Advanced → Proceed."
}

# ── Firewall ─────────────────────────────────────────────────────
setup_firewall() {
  head "Firewall Configuration"
  if ! ask_yn "Configure firewall to allow port $PORT?"; then
    info "Skipping firewall setup"
    return
  fi

  if command -v ufw &>/dev/null; then
    ufw allow "$PORT/tcp" comment "QEMU Web Frontend" || warn "ufw rule failed"
    ok "ufw: port $PORT allowed"
  fi

  if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
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
    command -v ufw &>/dev/null && ufw allow 5900:5999/tcp comment "QEMU VNC" || true
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
      if ask_yn "Add user '$user' to the kvm group?"; then
        usermod -aG kvm "$user" || warn "Could not add to kvm group"
        ok "Added $user to kvm group (log out/in to take effect)"
      fi
    fi
  else
    warn "/dev/kvm not found — KVM acceleration unavailable (emulation still works, just slower)"
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

  # Always run as root: QEMU needs /dev/kvm, websockify needs low ports, etc.
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
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${python_bin} ${APP_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  ok "Service installed: $SERVICE_FILE"
  ok "Runs as: root using ${python_bin}"

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
  echo -e "  ${BOLD}To start manually (must be root for KVM + port access):${RESET}"
  if [[ -f "$APP_DIR/venv/bin/python" ]]; then
    echo -e "  ${CYAN}cd $APP_DIR && sudo venv/bin/python app.py${RESET}"
  else
    echo -e "  ${CYAN}cd $APP_DIR && sudo python3 app.py${RESET}"
  fi
  echo ""
  echo -e "  ${BOLD}SSL trust:${RESET}"
  echo -e "  Open ${GREEN}https://YOUR-IP:${PORT}${RESET} and click ${YELLOW}Advanced → Proceed${RESET}"
  echo -e "  That's it — noVNC now loads through Flask so ${GREEN}no second popup${RESET}."
  echo ""

  echo -e "  ${BOLD}Component Status:${RESET}"
  for bin in qemu-system-i386 qemu-system-x86_64 qemu-system-arm qemu-system-aarch64 qemu-system-riscv64; do
    command -v "$bin" &>/dev/null \
      && echo -e "  ${GREEN}✓${RESET} $bin" \
      || echo -e "  ${RED}✗${RESET} $bin (unavailable)"
  done
  for tool in websockify qemu-img openssl; do
    command -v "$tool" &>/dev/null \
      && echo -e "  ${GREEN}✓${RESET} $tool" \
      || echo -e "  ${YELLOW}⚠${RESET} $tool (not found)"
  done
  for p in /usr/share/novnc /opt/novnc; do
    if [[ -d "$p" ]]; then
      echo -e "  ${GREEN}✓${RESET} noVNC at $p"
      break
    fi
  done
  echo ""

  warn "Browser will show a certificate warning — click 'Advanced' → 'Proceed' once."
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

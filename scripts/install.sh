#!/usr/bin/env bash
set -euo pipefail

# Jianlai user-level installer for Linux/macOS/WSL.
# One-line install after publishing:
#   curl -fsSL https://raw.githubusercontent.com/Lniosy/jianlai/master/scripts/install.sh | bash
#
# Optional environment variables:
#   JIANLAI_REPO_URL     Git repository URL. Default: https://github.com/Lniosy/jianlai.git
#   JIANLAI_BRANCH       Git branch/ref. Default: master
#   JIANLAI_INSTALL_DIR  Install root. Default: ~/.local/share/jianlai

REPO_URL="${JIANLAI_REPO_URL:-https://github.com/Lniosy/jianlai.git}"
BRANCH="${JIANLAI_BRANCH:-master}"
INSTALL_ROOT="${JIANLAI_INSTALL_DIR:-$HOME/.local/share/jianlai}"
APP_DIR="$INSTALL_ROOT/app"
VENV_DIR="$INSTALL_ROOT/.venv"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.jianlai"
CONFIG_FILE="$CONFIG_DIR/.env"

step() { printf '\033[36m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fail "Git not found. Install Git first, then rerun this installer."

find_python312() {
  if command -v python3.12 >/dev/null 2>&1; then
    printf '%s' "python3.12"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    if python3 - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)
PY
    then
      printf '%s' "python3"
      return 0
    fi
  fi
  return 1
}

PYTHON_BIN="$(find_python312 || true)"
[ -n "$PYTHON_BIN" ] || fail "Python 3.12 not found. Install Python 3.12 first, then rerun this installer."

step "Preparing directories"
mkdir -p "$INSTALL_ROOT" "$BIN_DIR" "$CONFIG_DIR"

step "Fetching Jianlai source"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch --all --prune
  git -C "$APP_DIR" checkout "$BRANCH"
  git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
else
  rm -rf "$APP_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

step "Using Python: $PYTHON_BIN"
if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

step "Installing Jianlai into isolated venv"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -e "$APP_DIR"

if [ ! -f "$CONFIG_FILE" ]; then
  step "Creating user config: $CONFIG_FILE"
  mkdir -p "$CONFIG_DIR/data"
  cat > "$CONFIG_FILE" <<EOF
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_PRO_MODEL=deepseek-v4-pro
DEEPSEEK_FLASH_MODEL=deepseek-v4-flash

DATABASE_PATH=$CONFIG_DIR/data/jianlai.db
MAX_CONCURRENT_TASKS=5
LOG_LEVEL=INFO
EOF
fi

step "Creating global jianlai launcher"
cat > "$BIN_DIR/jianlai" <<EOF
#!/usr/bin/env bash
export JIANLAI_HOME="$CONFIG_DIR"
exec "$VENV_DIR/bin/jianlai" "\$@"
EOF
chmod +x "$BIN_DIR/jianlai"

if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
  step "Adding $BIN_DIR to shell PATH"
  PROFILE_FILE="$HOME/.bashrc"
  [ -n "${ZSH_VERSION:-}" ] && PROFILE_FILE="$HOME/.zshrc"
  if ! grep -qs 'export PATH="$HOME/.local/bin:$PATH"' "$PROFILE_FILE"; then
    printf '\n# Jianlai\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$PROFILE_FILE"
  fi
fi

printf '\n\033[32mJianlai installed successfully.\033[0m\n'
printf 'Config file: %s\n' "$CONFIG_FILE"
printf 'Launcher:    %s\n\n' "$BIN_DIR/jianlai"
printf 'Next steps:\n'
printf '  1. Edit config and set DEEPSEEK_API_KEY: ${EDITOR:-nano} %s\n' "$CONFIG_FILE"
printf '  2. Open a new shell, then run: jianlai\n\n'

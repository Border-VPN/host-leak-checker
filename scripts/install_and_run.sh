#!/usr/bin/env bash
# install_and_run.sh
# Автоматически клонирует репозиторий в /opt, настраивает окружение, просит ссылку на подписку и запускает скрипт.

set -euo pipefail
IFS=$'\n\t'

REPO_URL="https://github.com/Border-VPN/host-leak-checker.git"
DEST_DIR="/opt/host-leak-checker"
VENV_DIR=".venv"

# Проверка команд
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

echo "Starting host-leak-checker installer/script runner..."

# Ensure /opt exists (may require sudo)
if [ ! -d "/opt" ]; then
  echo "/opt does not exist — creating (may require sudo)"
  sudo mkdir -p /opt
fi

# Clone or update repo
if [ -d "$DEST_DIR/.git" ]; then
  echo "Repository already exists at $DEST_DIR — performing git pull"
  sudo git -C "$DEST_DIR" pull --ff-only || { echo "Git pull failed"; exit 1; }
else
  echo "Cloning repository into $DEST_DIR (requires sudo)"
  sudo git clone --depth 1 "$REPO_URL" "$DEST_DIR" || { echo "Git clone failed"; exit 1; }
  # Make the current user the owner of the cloned files so venv & installs work without sudo
  sudo chown -R "$(id -u):$(id -g)" "$DEST_DIR"
fi

cd "$DEST_DIR"

# Check for Python
PYTHON=""
if cmd_exists python3; then
  PYTHON=python3
elif cmd_exists python; then
  PYTHON=python
else
  echo "Python not found on the system. Please install Python 3 and re-run this script." >&2
  echo "On Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip" >&2
  exit 2
fi

echo "Using python: $(command -v $PYTHON)"

# Ensure `venv` module is available; install python3-venv if necessary
if ! $PYTHON -c "import venv" >/dev/null 2>&1; then
  echo "python venv module not available — attempting to install package python3-venv (may require sudo)"
  if cmd_exists apt-get; then
    sudo apt-get update && sudo apt-get install -y python3-venv
  elif cmd_exists dnf; then
    sudo dnf install -y python3-venv || sudo dnf install -y python3
  elif cmd_exists yum; then
    sudo yum install -y python3-venv || sudo yum install -y python3
  elif cmd_exists zypper; then
    sudo zypper install -y python3-venv
  else
    echo "No known package manager found to install python3-venv. Please install \\`python3-venv\\` or ensure your Python has the venv module." >&2
    exit 2
  fi
  # Re-check
  if ! $PYTHON -c "import venv" >/dev/null 2>&1; then
    echo "Failed to enable venv module even after installing packages. Please install python3-venv manually." >&2
    exit 2
  fi
fi

# Create and activate virtualenv
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment in $VENV_DIR"
  $PYTHON -m venv "$VENV_DIR" || { echo "Failed to create virtualenv"; exit 1; }
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# Upgrade pip and install requirements
echo "Upgrading pip and installing requirements"
python -m pip install --upgrade pip setuptools wheel >/dev/null
if [ -f requirements.txt ]; then
  python -m pip install -r requirements.txt
else
  echo "requirements.txt not found — skipping dependency installation"
fi

# Ask user for subscription URL
read -rp "Введите URL подписки (например https://...): " SUBSCRIPTION_URL
if [ -z "$SUBSCRIPTION_URL" ]; then
  echo "Subscription URL is empty — aborting" >&2
  deactivate || true
  exit 3
fi

# Run the checker
echo "Running checker with subscription URL: $SUBSCRIPTION_URL"
python check_leaks.py "$SUBSCRIPTION_URL" list.txt || {
  echo "check_leaks.py failed" >&2
  deactivate || true
  exit 4
}

echo "Done. Reports (if any) are in the repository root: leak_report.json, leak_report.md"

deactivate || true

exit 0

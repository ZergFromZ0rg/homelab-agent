#!/usr/bin/env sh
# Write a .env for this host: guess what can be guessed, ask for the rest.
#
# Everything here is a default you can overwrite by editing .env afterwards.
# Re-running keeps the answers you already gave.

set -eu

cd "$(dirname "$0")"

ENV_FILE=.env
[ -f "$ENV_FILE" ] || : > "$ENV_FILE"

# Current value of a key in .env, if any.
current() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

# Set a key, replacing any existing line for it.
put() {
  key=$1
  value=$2
  tmp=$(mktemp)
  grep -v "^$key=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
}

# Ask, offering a default.
ask() {
  key=$1
  prompt=$2
  default=${3:-}
  existing=$(current "$key")
  [ -n "$existing" ] && default=$existing

  if [ -n "$default" ]; then
    printf '%s [%s]: ' "$prompt" "$default"
  else
    printf '%s: ' "$prompt"
  fi

  read -r answer || answer=""
  [ -z "$answer" ] && answer=$default
  put "$key" "$answer"
}

echo "homelab-agent setup"
echo

# ---- HOST_NAME -----------------------------------------------------------
# Must match this host's Prometheus job_name, or the dashboard can't line
# the agent's containers up with the host's metrics. The machine's own
# hostname is the usual answer but not always the right one.
ask HOST_NAME "Host name (must equal its Prometheus job_name)" "$(hostname -s 2>/dev/null || hostname)"

# ---- GPU -----------------------------------------------------------------
# NVIDIA needs the container runtime to see the card at all. AMD and Intel
# are read from /sys/class/drm, which every container already has, so
# there is nothing to configure for them.
runtime=$(current AGENT_RUNTIME)

if [ -z "$runtime" ]; then
  if [ -e /dev/nvidiactl ] || command -v nvidia-smi >/dev/null 2>&1; then
    if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
      runtime=nvidia
      count=$(nvidia-smi --list-gpus 2>/dev/null | wc -l | tr -d ' ')
      echo "NVIDIA detected (${count:-?} card(s)) and the container toolkit is installed."
      echo "  -> AGENT_RUNTIME=nvidia"
    else
      echo "NVIDIA card found, but Docker has no 'nvidia' runtime registered."
      echo "  Install the NVIDIA Container Toolkit, then re-run this script."
      echo "  Without it the agent still sees the card, but reports no"
      echo "  utilisation, VRAM, power or fan."
    fi
  elif [ -d /sys/class/drm ] && ls /sys/class/drm/card[0-9]* >/dev/null 2>&1; then
    echo "AMD/Intel GPU detected. Nothing to configure - it is read from"
    echo "  /sys, which every container already has."
  else
    echo "No GPU detected."
  fi
fi

[ -n "$runtime" ] && put AGENT_RUNTIME "$runtime"
echo

# ---- Dashboard -----------------------------------------------------------
ask DASHBOARD_URL "Dashboard API URL (blank to skip registration)" "$(current DASHBOARD_URL)"

if [ -n "$(current DASHBOARD_URL)" ]; then
  ask AGENT_URL "How the dashboard reaches THIS agent" \
    "http://$(current HOST_NAME):8123"
  ask REGISTER_TOKEN "Dashboard API_TOKEN (blank if unset)" "$(current REGISTER_TOKEN)"
fi
echo

# ---- Security ------------------------------------------------------------
ask AGENT_TOKEN "Shared token for mutating routes (blank = unprotected)" "$(current AGENT_TOKEN)"

if [ -z "$(current AGENT_TOKEN)" ]; then
  echo "  No token: anything that can reach port 8123 can start, stop and"
  echo "  deploy containers here. Fine behind Tailscale, not on a LAN."
fi
echo

ask REBUILD_ENABLED "Allow the dashboard to pull+rebuild projects here? (1/blank)" \
  "$(current REBUILD_ENABLED)"

if [ "$(current REBUILD_ENABLED)" = "1" ]; then
  echo "  This runs whatever the repo and its Dockerfile say, as root."
fi
echo

echo "Wrote $ENV_FILE:"
sed 's/\(TOKEN=\).*/\1***/' "$ENV_FILE" | sed 's/^/  /'
echo
echo "Next: docker compose up -d --build"

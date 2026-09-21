#!/usr/bin/env sh
# One-shot install for a new node. Meant to be run from the command the
# dashboard hands you:
#
#   curl -fsSL https://raw.githubusercontent.com/ZergFromZ0rg/homelab-agent/main/install.sh \
#     | sh -s -- --dashboard http://thinkpad:8081
#
# Clones the repo, writes a .env, detects the GPU, starts the agent. The
# agent then registers itself with the dashboard and appears there.
#
# Re-running is safe: an existing checkout is updated rather than replaced,
# and an existing .env keeps every value you don't override.

set -eu

REPO_URL=${REPO_URL:-https://github.com/ZergFromZ0rg/homelab-agent.git}
DIR=${DIR:-$HOME/homelab-agent}
DASHBOARD=""
TOKEN=""
NAME=""
AGENT_URL_OVERRIDE=""
REBUILD=""

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

  --dashboard URL   the dashboard this node should register with
  --token TOKEN     the dashboard's API_TOKEN, if it has one set
  --name NAME       this host's name (default: its hostname)
                    must match its Prometheus job_name
  --agent-url URL   how the dashboard should reach this agent
                    (default: http://<name>:8123)
  --rebuild         allow the dashboard to pull+rebuild projects here
  --dir PATH        where to put the checkout (default ~/homelab-agent)
USAGE
}

while [ $# -gt 0 ]; do
  case $1 in
    --dashboard) DASHBOARD=${2:?--dashboard needs a URL}; shift 2 ;;
    --token) TOKEN=${2:?--token needs a value}; shift 2 ;;
    --name) NAME=${2:?--name needs a value}; shift 2 ;;
    --agent-url) AGENT_URL_OVERRIDE=${2:?--agent-url needs a URL}; shift 2 ;;
    --dir) DIR=${2:?--dir needs a path}; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$1"; }

# ---- prerequisites --------------------------------------------------------

missing=""
for tool in git docker; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done

if [ -n "$missing" ]; then
  echo "Missing:$missing" >&2
  echo "Install them and re-run this." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker's compose plugin isn't available (try: docker compose version)." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Can't talk to Docker. Is it running, and are you in the docker group?" >&2
  exit 1
fi

# ---- the checkout ---------------------------------------------------------

if [ -d "$DIR/.git" ]; then
  say "Updating $DIR"
  # Non-fatal on purpose: a re-run with no network, or a checkout that has
  # diverged, shouldn't leave a working node stopped. Say so and carry on
  # with what's on disk.
  if ! git -C "$DIR" pull --ff-only; then
    echo "    Couldn't update the checkout — continuing with what's there." >&2
  fi
elif [ -e "$DIR" ]; then
  echo "$DIR exists and isn't a git checkout. Move it aside or pass --dir." >&2
  exit 1
else
  say "Cloning into $DIR"
  git clone --depth 1 "$REPO_URL" "$DIR"
fi

cd "$DIR"

# ---- .env -----------------------------------------------------------------

ENV_FILE=.env
[ -f "$ENV_FILE" ] || : > "$ENV_FILE"

current() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

put() {
  tmp=$(mktemp)
  grep -v "^$1=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
}

# Only overwrite what was passed; anything already there survives a re-run.
PREVIOUS_NAME=$(current HOST_NAME)
[ -z "$NAME" ] && NAME=$PREVIOUS_NAME
[ -z "$NAME" ] && NAME=$(hostname -s 2>/dev/null || hostname)
put HOST_NAME "$NAME"

[ -n "$DASHBOARD" ] && put DASHBOARD_URL "$DASHBOARD"
[ -n "$TOKEN" ] && put REGISTER_TOKEN "$TOKEN"
[ -n "$REBUILD" ] && put REBUILD_ENABLED 1

if [ -n "$AGENT_URL_OVERRIDE" ]; then
  put AGENT_URL "$AGENT_URL_OVERRIDE"
elif [ -z "$(current AGENT_URL)" ]; then
  put AGENT_URL "http://$NAME:8123"
elif [ "$(current AGENT_URL)" = "http://$PREVIOUS_NAME:8123" ]; then
  # It was only ever the default derived from the old name, so follow the
  # rename. A URL someone actually chose (a tailnet IP, a container name
  # on a shared network) doesn't match this and is left alone.
  put AGENT_URL "http://$NAME:8123"
fi

# ---- GPU ------------------------------------------------------------------
# NVIDIA needs the container runtime to see the card. AMD and Intel are read
# from /sys, which every container already has, so there's nothing to set.

if [ -z "$(current AGENT_RUNTIME)" ]; then
  if [ -e /dev/nvidiactl ] || command -v nvidia-smi >/dev/null 2>&1; then
    if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
      put AGENT_RUNTIME nvidia
      say "NVIDIA detected with the container toolkit — AGENT_RUNTIME=nvidia"
    else
      say "NVIDIA card found, but Docker has no 'nvidia' runtime registered."
      echo "    Install the NVIDIA Container Toolkit and re-run this to get"
      echo "    utilisation, VRAM, temperature, power and fan."
    fi
  fi
fi

# ---- go -------------------------------------------------------------------

say "Building and starting the agent"
docker compose up -d --build

say "Done"
echo "    host:      $(current HOST_NAME)"
echo "    dashboard: $(current DASHBOARD_URL || echo '(registration off)')"
echo "    checkout:  $DIR"
echo
echo "    Check it:  curl -s localhost:8123/ ; echo"

if [ -n "$(current DASHBOARD_URL)" ]; then
  echo "    It should appear on the dashboard within a minute."
else
  echo "    No --dashboard given, so it won't register itself."
fi

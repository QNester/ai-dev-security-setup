#!/usr/bin/env bash
# Start the local LiteLLM proxy used by the ai-dev sandbox.
# Run as your normal user, never as root.
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ENV_FILE=${LITELLM_ENV_FILE:-$SCRIPT_DIR/litellm.env}
CONFIG_FILE=${LITELLM_CONFIG_FILE:-$SCRIPT_DIR/litellm.config.yaml}
LITELLM_BIN=${LITELLM_BIN:-litellm}

die() {
    printf 'start-litellm: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'start-litellm: warning: %s\n' "$*" >&2
}

[[ $EUID -ne 0 ]] || die "run as your normal user, not root"

[[ -f $ENV_FILE ]] || die "missing $ENV_FILE (copy litellm.env.example)"
[[ -f $CONFIG_FILE ]] || die "missing $CONFIG_FILE (copy litellm.config.example.yaml)"

mode=$(stat -c %a -- "$ENV_FILE")
if (( (8#$mode & 077) != 0 )); then
    warn "$ENV_FILE is readable by group/other; run: chmod 600 $ENV_FILE"
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE" || { set +a; die "cannot load $ENV_FILE"; }
set +a

[[ -n ${LITELLM_MASTER_KEY:-} ]] \
    || die "LITELLM_MASTER_KEY is empty in $ENV_FILE"

if [[ $LITELLM_BIN == */* ]]; then
    [[ -x $LITELLM_BIN ]] || die "LiteLLM executable not found: $LITELLM_BIN"
else
    command -v "$LITELLM_BIN" >/dev/null 2>&1 \
        || die "LiteLLM is not installed or not in PATH (see README)"
fi

PROXY_HOST=${LITELLM_PROXY_HOST:-127.0.0.1}
PROXY_PORT=${LITELLM_PROXY_PORT:-4000}

case "$PROXY_HOST" in
    127.0.0.1|localhost|::1) ;;
    *) warn "LiteLLM will listen on $PROXY_HOST; the sandbox firewall only allows the configured loopback address" ;;
esac

printf 'start-litellm: http://%s:%s (config: %s)\n' \
    "$PROXY_HOST" "$PROXY_PORT" "$CONFIG_FILE"

exec "$LITELLM_BIN" --config "$CONFIG_FILE" \
    --host "$PROXY_HOST" --port "$PROXY_PORT"

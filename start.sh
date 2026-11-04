#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export PYTHONDONTWRITEBYTECODE=1
if ! command -v python3 >/dev/null 2>&1; then
    if [[ "${1:-demo}" == check || "${1:-demo}" == report || "${1:-demo}" == --help ]]; then
        printf 'Python 3 is missing. Run bash start.sh setup to install it.\n' >&2
        exit 2
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        printf 'Install Python 3 with your package manager, then rerun this script.\n' >&2
        exit 2
    fi
    PRIV=()
    if [[ $EUID -ne 0 ]]; then PRIV=(sudo); fi
    printf 'Installing Python 3 through apt-get...\n'
    "${PRIV[@]}" apt-get update
    "${PRIV[@]}" apt-get install -y python3
fi
exec python3 "$ROOT/scripts/easy.py" "$@"

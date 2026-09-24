set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/run.py local --mode sp-local "$@"

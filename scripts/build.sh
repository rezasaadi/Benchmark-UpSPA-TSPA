set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/upspa-tspa-bench-target}"
cargo build --workspace --release --locked
python3 scripts/environment.py --record-build --target "$CARGO_TARGET_DIR"

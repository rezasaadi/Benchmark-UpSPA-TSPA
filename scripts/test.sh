set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/upspa-tspa-bench-target}"
cargo test --workspace --release --locked
python3 -m unittest discover -s scripts/tests -v

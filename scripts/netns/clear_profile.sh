set -euo pipefail
exec python3 "$(dirname "$0")/netns.py" clear "$@"

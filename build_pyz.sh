#!/bin/sh
# Builds a single-file, cross-platform executable archive: dist/pqcheck.pyz
# Runs anywhere Python 3.9+ exists:  ./dist/pqcheck.pyz tls example.com
set -e
cd "$(dirname "$0")"
rm -rf build/pyz dist/pqcheck.pyz && mkdir -p build/pyz dist
cp -R pqcheck build/pyz/pqcheck
find build/pyz -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
cat > build/pyz/__main__.py <<'PY'
import sys
from pqcheck.cli import main
sys.exit(main())
PY
python3 -m zipapp build/pyz -p "/usr/bin/env python3" -c -o dist/pqcheck.pyz
echo "built dist/pqcheck.pyz ($(wc -c < dist/pqcheck.pyz) bytes)"

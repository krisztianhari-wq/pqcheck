#!/bin/sh
# Builds the double-clickable desktop app with PyInstaller.
#   macOS   -> dist/PQCheck.app  (also zipped as dist/PQCheck-macos.zip)
#   Windows -> dist/PQCheck.exe  (windowed, no console)
#   Linux   -> dist/PQCheck      (opens the browser)
# Needs: pip install pyinstaller
set -e
cd "$(dirname "$0")"
mkdir -p build dist
printf 'import sys\nfrom pqcheck.cli import main\nsys.exit(main())\n' > build/entry.py
case "$(uname -s)" in
  Darwin) ICON="$(pwd)/assets/pqcheck.icns" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) ICON="$(pwd)/assets/pqcheck.ico" ;;
  *) ICON="$(pwd)/assets/icon_256.png" ;;
esac
PYI=${PYINSTALLER:-pyinstaller}
MODE=--onefile
[ "$(uname -s)" = "Darwin" ] && MODE=--onedir   # a .app bundle cannot be a single file
$PYI $MODE --windowed --name PQCheck --icon "$ICON" --clean --noconfirm --paths . \
     --osx-bundle-identifier hu.yettel.pqcheck \
     --distpath dist/app --workpath build/pyi-app --specpath build build/entry.py
if [ "$(uname -s)" = "Darwin" ]; then
  # let Finder show the icon immediately and mark the bundle as a background-friendly agent
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(python3 -c 'import pqcheck;print(pqcheck.__version__)')" dist/app/PQCheck.app/Contents/Info.plist || true
  rm -f dist/PQCheck-macos.zip && (cd dist/app && ditto -c -k --keepParent PQCheck.app ../PQCheck-macos.zip)
  echo "built dist/app/PQCheck.app and dist/PQCheck-macos.zip"
else
  echo "built dist/app/PQCheck*"
fi

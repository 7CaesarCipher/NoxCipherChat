#!/bin/zsh
# NoxCipher Chat: macOS launcher (Apple Silicon/Rosetta and Intel)
set -e
cd "$(dirname "$0")"

# Prefer native Apple Silicon Python installed by Homebrew when available.
# This avoids the mismatch between Rosetta Terminal and /opt/homebrew.
if arch -arm64 /usr/bin/true >/dev/null 2>&1; then
  NATIVE_ARM=1
else
  NATIVE_ARM=0
fi

if [[ "$NATIVE_ARM" == "1" ]]; then
  VENV_PY=(arch -arm64 .venv/bin/python)
  if [[ -x /opt/homebrew/bin/python3.14 ]]; then
    BASE_PY=(arch -arm64 /opt/homebrew/bin/python3.14)
  else
    BASE_PY=(arch -arm64 python3)
  fi
else
  VENV_PY=(.venv/bin/python)
  BASE_PY=(python3)
fi

if [[ ! -x .venv/bin/python ]]; then
  echo "Creating virtual environment..."
  "${BASE_PY[@]}" -m venv .venv
fi

# Some Homebrew Python builds link against a newer Expat than macOS ships.
if ! "${VENV_PY[@]}" -c 'import pyexpat' >/dev/null 2>&1; then
  for EXPAT_LIB in /opt/homebrew/opt/expat/lib /usr/local/opt/expat/lib; do
    if [[ -f "$EXPAT_LIB/libexpat.1.dylib" ]]; then
      export DYLD_LIBRARY_PATH="$EXPAT_LIB${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
      if "${VENV_PY[@]}" -c 'import pyexpat' >/dev/null 2>&1; then
        break
      fi
    fi
  done
fi

# Some Homebrew Python builds require separately installed python-tk.
if ! "${VENV_PY[@]}" -c 'import tkinter, _tkinter' >/dev/null 2>&1; then
  echo "" >&2
  echo "ERROR: Tkinter is not available in your Python environment." >&2
  if [[ "$NATIVE_ARM" == "1" ]]; then
    echo 'Fix for Homebrew Python 3.14:' >&2
    echo '  arch -arm64 /opt/homebrew/bin/brew install python-tk@3.14' >&2
    echo '  arch -arm64 .venv/bin/python -m tkinter' >&2
  else
    echo 'Install a Python build with Tk support, then recreate .venv.' >&2
  fi
  exit 1
fi

# pip 24.2+ uses truststore by default. In some macOS environments,
# platform.mac_ver() returns an empty version and truststore crashes.
# legacy-certs uses certifi and still validates TLS certificates.
echo "Installing/checking Python dependencies..."
"${VENV_PY[@]}" mac_pip.py install \
  --use-deprecated=legacy-certs \
  --disable-pip-version-check \
  -r requirements.txt

echo "Starting NoxCipher Chat..."
"${VENV_PY[@]}" run_local.py

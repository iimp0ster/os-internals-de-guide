#!/usr/bin/env bash

set -euo pipefail

LAB_DIR="/tmp/mac-monitor-demo-$$"
FIRST_FILE="$LAB_DIR/esf-original.txt"
RENAMED_FILE="$LAB_DIR/esf-renamed.txt"
SYSTEM_FILE="$LAB_DIR/esf-system-info.txt"

cleanup() {
  rm -f "$FIRST_FILE" "$RENAMED_FILE" "$SYSTEM_FILE"
  rmdir "$LAB_DIR" 2>/dev/null || true
}

trap cleanup EXIT

echo "[+] Starting Mac Monitor ESF test"
echo "[+] Script PID: $$"
echo "[+] Parent PID: $PPID"

sleep 2
mkdir -m 700 "$LAB_DIR"
sleep 2
/usr/bin/touch "$FIRST_FILE"
sleep 2
/bin/echo "Mac Monitor ESF demonstration" > "$FIRST_FILE"
sleep 2
mv "$FIRST_FILE" "$RENAMED_FILE"
sleep 2
cat "$RENAMED_FILE"
sleep 2
uname -a > "$SYSTEM_FILE"
sleep 2
ls -la "$LAB_DIR"
sleep 2
rm -f "$RENAMED_FILE" "$SYSTEM_FILE"
sleep 2
rmdir "$LAB_DIR"
trap - EXIT

echo "[+] Test complete"

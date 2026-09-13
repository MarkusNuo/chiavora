#!/usr/bin/env bash
# Every `tap` and `screencap` first checks that one of our apps has focus and
# refuses otherwise, so it can never touch or capture another app.
# Usage:
#   device-drive.sh focus                 -- print the focused activity
#   device-drive.sh launch <package>      -- start and wait for focus
#   device-drive.sh tap <x> <y>           -- tap, only if ours has focus
#   device-drive.sh screencap <out.png>   -- capture, only if ours has focus
#   device-drive.sh logcat <tag>          -- dump a tag (no focus check: read-only)
set -euo pipefail

# MSYS would rewrite `/sdcard/...` into a Windows path on the way to adb.
export MSYS_NO_PATHCONV=1

# Exact names: a prefix like `ch.chiavora` would also match other packages.
ALLOWED=("ch.chiavora.app" "ch.chiavora.harness")

focused() {
  # A locked or sleeping phone reports another window, which fails the check.
  adb shell dumpsys window 2>/dev/null |
    grep -m1 -oE 'mCurrentFocus=Window\{[^}]*\}' |
    sed -E 's/.* ([A-Za-z0-9_.]+)\/.*/\1/' || true
}

require_ours() {
  local what="$1"
  local now
  now="$(focused)"
  for package in "${ALLOWED[@]}"; do
    if [ "$now" = "$package" ]; then
      return 0
    fi
  done
  echo "REFUSED: $what" >&2
  echo "  focused window is '${now:-<none>}', which is not one of: ${ALLOWED[*]}" >&2
  echo "  The phone is in use, locked, or the app did not come to the front." >&2
  exit 3
}

case "${1:-}" in
  focus)
    echo "${_:-}$(focused)"
    ;;

  launch)
    package="${2:?usage: launch <package>}"
    adb shell am start -n "$package/.MainActivity" >/dev/null 2>&1 || true
    # Poll for focus rather than sleep a guessed interval; cold starts vary.
    for _ in $(seq 1 20); do
      if [ "$(focused)" = "$package" ]; then
        echo "focused: $package"
        exit 0
      fi
      sleep 1
    done
    echo "REFUSED: $package did not take focus within 20s (focused: $(focused))" >&2
    exit 3
    ;;

  tap)
    x="${2:?usage: tap <x> <y>}"
    y="${3:?usage: tap <x> <y>}"
    require_ours "tap at ($x, $y)"
    adb shell input tap "$x" "$y"
    ;;

  screencap)
    out="${2:?usage: screencap <out.png>}"
    require_ours "screencap to $out"
    adb shell screencap -p /sdcard/chv-drive.png
    adb pull /sdcard/chv-drive.png "$out" >/dev/null
    adb shell rm /sdcard/chv-drive.png
    echo "captured: $out"
    ;;

  logcat)
    adb logcat -d -s "${2:?usage: logcat <tag>}"
    ;;

  *)
    sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1
    exit 2
    ;;
esac

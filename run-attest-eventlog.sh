#!/usr/bin/env bash
# Host harness for the ATTEST-EVENTLOG milestone (go-tpm2/attest v0.2.0): build
# the tamago/amd64 attesteventlog ELF, start a real swtpm (software TPM 2.0),
# boot the guest headless under QEMU (-M pc, TCG) with `-device tpm-crb` wired to
# that swtpm, and wait for the guest's verdict on the serial console.
#
# The guest plays BOTH protocol roles in one process: the go-tpm2/attest Node
# drives the real swtpm (CreateEK/CreatePrimary/ActivateCredential, several real
# PCR_Extends on PCR16, Quote, PCR_Read), building a crypto-agile TCG event log
# of those extends; the pure-Go Verifier runs in-process and validates the
# v0.2.0 EventLogPolicy: it REPLAYS the log into virtual PCRs, confirms they
# EQUAL the real swtpm PCRs, and confirms every event is on the allowlist
# (ADMITTED). Then the negatives: dropping a measurement from the allowlist ->
# ErrUnapprovedMeasurement, and corrupting a log digest -> ErrEventLogMismatch
# (replay != real PCR). It prints ATTEST-EVENTLOG: ... PASS / FAIL. We exit
# non-zero on FAIL (or no verdict).
#
# Machine/RAM/device choices mirror run-attest-protocol.sh and were each forced
# by a real observed failure: -M pc (NOT q35: q35+TPM = SMI storm that
# triple-faults the firmware-less guest), -m 2G, -device isa-debug-exit. swtpm
# 0.10.1 is launched with --flags startup-clear so the guest's own Startup is
# redundant/tolerated — and so PCR16 starts at all-zero (the replay's start).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TAMAGO="${TAMAGO:-/Users/david_delavennat/Documents/VCS/GIT/github.com/tannevaled/tamago-go/bin/go}"
SWTPM="${SWTPM:-/opt/homebrew/bin/swtpm}"
ELF="$HERE/attesteventlog.elf"
SERIAL="/tmp/attesteventlog_serial.log"
STATE="/tmp/attesteventlog_state"
SOCK="/tmp/attesteventlog_swtpm.sock"
CPU="${CPU:-max}"

echo "== build =="
( cd "$HERE" && GOWORK=off GOOS=tamago GOARCH=amd64 \
  GOOSPKG=github.com/usbarmory/tamago \
  "$TAMAGO" build -ldflags "-T 0x10010000 -R 0x1000" -o "$ELF" ./cmd/attesteventlog ) || exit 1

# Fresh swtpm state and sockets every run.
rm -f "$SERIAL" "$SOCK"
rm -rf "$STATE"
mkdir -p "$STATE"

echo "== swtpm =="
"$SWTPM" socket \
  --tpm2 \
  --tpmstate dir="$STATE" \
  --ctrl type=unixio,path="$SOCK" \
  --flags startup-clear \
  --log level=1 &
SWPID=$!

# Wait for the swtpm control socket to appear before launching QEMU.
for _ in $(seq 1 40); do
  [ -S "$SOCK" ] && break
  if ! kill -0 "$SWPID" 2>/dev/null; then
    echo "RESULT: FAIL (swtpm exited before its control socket appeared)"
    exit 4
  fi
  sleep 0.1
done

echo "== boot =="
qemu-system-x86_64 -M pc -accel tcg -cpu "$CPU" -m 2G \
  -display none -no-reboot \
  -chardev socket,id=chrtpm,path="$SOCK" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-crb,tpmdev=tpm0 \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -serial "file:$SERIAL" \
  -kernel "$ELF" &
QPID=$!

# Wait (max ~120s) for the guest verdict. EK+AK creation, an ECDH-backed
# ActivateCredential, three PCR extends, three Quotes and PCR reads add real
# swtpm crypto, so give it headroom.
for _ in $(seq 1 480); do
  if grep -q "; PASS" "$SERIAL" 2>/dev/null; then break; fi
  if grep -q "ATTEST-EVENTLOG: FAIL" "$SERIAL" 2>/dev/null; then break; fi
  if ! kill -0 "$QPID" 2>/dev/null; then break; fi
  sleep 0.25
done

kill "$QPID" 2>/dev/null
wait "$QPID" 2>/dev/null
kill "$SWPID" 2>/dev/null
wait "$SWPID" 2>/dev/null

echo "== serial =="
cat "$SERIAL" 2>/dev/null

echo "== verdict =="
if grep -q "; PASS" "$SERIAL" 2>/dev/null; then
  echo "RESULT: PASS (EventLogPolicy replay==real-swtpm-PCRs ADMITTED; unapproved + tampered-log REJECTED)"
  exit 0
fi
if grep -q "ATTEST-EVENTLOG: FAIL" "$SERIAL" 2>/dev/null; then
  echo "RESULT: FAIL (see ATTEST-EVENTLOG: FAIL line above)"
  exit 3
fi
echo "RESULT: FAIL (no verdict on serial — guest never reported)"
exit 2

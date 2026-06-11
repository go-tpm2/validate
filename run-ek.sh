#!/usr/bin/env bash
# Host harness for the ENDORSEMENT-KEY feature: build the tamago/amd64 tpmek
# ELF, start a real swtpm, boot the guest headless under QEMU (-M pc, TCG) with
# `-device tpm-crb` wired to that swtpm, and wait for the guest's verdict on
# the serial console.
#
# The guest runs Startup -> CreateEK -> print the EK public point -> CreateEK
# again -> assert the point is stable (the EK is deterministic from the
# endorsement seed), and prints TPM-EK: ... PASS / FAIL. We exit non-zero on
# FAIL (or no verdict).
#
# Machine/RAM/device choices mirror run-attest.sh (see run.sh for rationale).
# The EK is an ECC primary, so the swtpm does an ECC keygen twice; give the
# guest the same headroom as the attest harness.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TAMAGO="${TAMAGO:-/Users/david_delavennat/Documents/VCS/GIT/github.com/tannevaled/tamago-go/bin/go}"
SWTPM="${SWTPM:-/opt/homebrew/bin/swtpm}"
ELF="$HERE/tpmek.elf"
SERIAL="/tmp/tpmek_serial.log"
STATE="/tmp/tpmek_state"
SOCK="/tmp/tpmek_swtpm.sock"
CPU="${CPU:-max}"

echo "== build =="
( cd "$HERE" && GOWORK=off GOOS=tamago GOARCH=amd64 \
  GOOSPKG=github.com/usbarmory/tamago \
  "$TAMAGO" build -ldflags "-T 0x10010000 -R 0x1000" -o "$ELF" ./cmd/tpmek ) || exit 1

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

for _ in $(seq 1 240); do
  if grep -q "TPM-EK: EK Credential Profile ECC-P256 (L-2) created on a real swtpm, PASS" "$SERIAL" 2>/dev/null; then break; fi
  if grep -q "TPM-EK: FAIL" "$SERIAL" 2>/dev/null; then break; fi
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
if grep -q "TPM-EK: EK Credential Profile ECC-P256 (L-2) created on a real swtpm, PASS" "$SERIAL" 2>/dev/null; then
  echo "RESULT: PASS (EK Credential Profile ECC-P256 on a real swtpm via CRB)"
  exit 0
fi
if grep -q "TPM-EK: FAIL" "$SERIAL" 2>/dev/null; then
  echo "RESULT: FAIL (see TPM-EK: FAIL line above)"
  exit 3
fi
echo "RESULT: FAIL (no verdict on serial — guest never reported)"
exit 2

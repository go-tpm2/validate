#!/usr/bin/env bash
# Host harness for the CREDENTIAL-ACTIVATION milestone: build the tamago/amd64
# tpmcred ELF, start a real swtpm (software TPM 2.0), boot the guest headless
# under QEMU (-M pc, TCG) with `-device tpm-crb` wired to that swtpm, and wait
# for the guest's verdict on the serial console.
#
# The guest drives the TPM through go-tpm2/crb + go-tpm2/tpm2, runs
# CreateEK -> CreatePrimary(AK) -> ObjectName(AK) -> MakeCredential(off-TPM) ->
# StartAuthSession+PolicySecret(endorsement) -> ActivateCredential (POSITIVE,
# recovered MUST equal the challenge) -> a credential for a WRONG AK Name +
# fresh policy session -> ActivateCredential (NEGATIVE, must be REJECTED),
# printing TPM-CRED: ... PASS / FAIL. We exit non-zero on FAIL (or no verdict).
#
# Machine/RAM/device choices mirror run-seal.sh and were each forced by a real
# observed failure (see run.sh for the full rationale): -M pc (NOT q35:
# q35+TPM = SMI storm that triple-faults the firmware-less guest), -m 2G,
# -device isa-debug-exit. swtpm 0.10.1 is launched with --flags startup-clear
# so the guest's own Startup is redundant and tolerated.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TAMAGO="${TAMAGO:-/Users/david_delavennat/Documents/VCS/GIT/github.com/tannevaled/tamago-go/bin/go}"
SWTPM="${SWTPM:-/opt/homebrew/bin/swtpm}"
ELF="$HERE/tpmcred.elf"
SERIAL="/tmp/tpmcred_serial.log"
STATE="/tmp/tpmcred_state"
SOCK="/tmp/tpmcred_swtpm.sock"
CPU="${CPU:-max}"

echo "== build =="
( cd "$HERE" && GOWORK=off GOOS=tamago GOARCH=amd64 \
  GOOSPKG=github.com/usbarmory/tamago \
  "$TAMAGO" build -ldflags "-T 0x10010000 -R 0x1000" -o "$ELF" ./cmd/tpmcred ) || exit 1

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

# Wait (max ~90s) for the guest to report a PASS/FAIL verdict on serial. The
# EK + AK primary creation, an ECDH-backed ActivateCredential, and a second
# (negative) activation add real swtpm crypto, so give it headroom.
for _ in $(seq 1 360); do
  if grep -q "; PASS" "$SERIAL" 2>/dev/null; then break; fi
  if grep -q "TPM-CRED: FAIL" "$SERIAL" 2>/dev/null; then break; fi
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
  echo "RESULT: PASS (MakeCredential off-TPM recovered EXACTLY by a real swtpm via ActivateCredential; wrong-AK REJECTED)"
  exit 0
fi
if grep -q "TPM-CRED: FAIL" "$SERIAL" 2>/dev/null; then
  echo "RESULT: FAIL (see TPM-CRED: FAIL line above)"
  exit 3
fi
echo "RESULT: FAIL (no verdict on serial — guest never reported)"
exit 2

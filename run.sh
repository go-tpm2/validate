#!/usr/bin/env bash
# Host harness: build the tamago/amd64 TPM validate ELF, start a real swtpm
# (software TPM 2.0), boot the guest headless under QEMU (q35, TCG) with
# `-device tpm-crb` wired to that swtpm, and wait for the guest's verdict on
# the serial console.
#
# The guest drives the TPM through go-tpm2/crb (CRB MMIO at 0xFED40000) and
# go-tpm2/tpm2, runs Startup -> GetRandom -> PCR_Extend -> PCR_Read, and
# asserts the PCR extend identity itself, printing TPM-VALIDATE: PASS / FAIL.
# We exit non-zero on FAIL (or if no verdict appears).
#
# QEMU connects to swtpm over its control channel (a UNIX socket). swtpm is
# launched with --flags startup-clear so the TPM self-issues Startup(CLEAR)
# at _TPM_Init; the guest's own Startup is then redundant and tolerated.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TAMAGO="${TAMAGO:-/Users/david_delavennat/Documents/VCS/GIT/github.com/tannevaled/tamago-go/bin/go}"
SWTPM="${SWTPM:-/opt/homebrew/bin/swtpm}"
ELF="$HERE/tpmvalidate.elf"
SERIAL="/tmp/tpmvalidate_serial.log"
STATE="/tmp/tpmvalidate_state"
SOCK="/tmp/tpmvalidate_swtpm.sock"
CPU="${CPU:-max}"

echo "== build =="
( cd "$HERE" && GOWORK=off GOOS=tamago GOARCH=amd64 \
  GOOSPKG=github.com/usbarmory/tamago \
  "$TAMAGO" build -ldflags "-T 0x10010000 -R 0x1000" -o "$ELF" ./cmd/tpmvalidate ) || exit 1

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
# Machine/RAM/device notes (each one was forced by a real, observed failure
# while bringing this harness up against QEMU 10.2.2 + swtpm 0.10.1; the TPM
# register block lands at the same TCG-standard 0xFED40000 either way):
#
#   -M pc (NOT q35) : q35 with ANY TPM device (tpm-crb OR tpm-tis) enables SMM
#     and QEMU delivers a continuous storm of SMIs from boot. The firmware-less
#     tamago guest installs no SMI handler, so each SMI enters SMM at the
#     default SMBASE, executes garbage, and the CPU eventually triple-faults
#     (confirmed with `-d int`: hundreds of "SMM: enter"/"RSM" cycles, then
#     v=08/v=0e with IDT base 0). `-M q35,smm=off` quiets the storm but the
#     boot stays intermittently unstable (sometimes PASSes, sometimes faults
#     pre-main). `-M pc` exposes no TPM-driven SMM and is rock solid: 5/5 PASS.
#     An unrelated q35 device (e1000) never triggers the storm, so this is a
#     q35+TPM platform quirk, not a bug in the go-tpm2 stack — when q35,smm=off
#     does complete a boot it produces the exact same PASS digest as -M pc.
#
#   -m 2G : the copied tamago board declares ramSize = 1 GiB and places its DMA
#     region at 0x50000000 (1.25 GiB), so the guest needs >1 GiB of real RAM or
#     it faults during early runtime/DMA init before any serial output appears.
#
#   -device isa-debug-exit : lets the guest terminate QEMU cleanly the instant
#     it prints its verdict (board.Shutdown). Without it, a background GC
#     goroutine spinning while main halts faults under TCG *after* PASS, and the
#     resulting triple-fault reset races (and loses to) the serial-file flush,
#     so the host could see an empty log despite a real PASS. A guest PASS makes
#     QEMU exit 1 (isa-debug-exit value 0 -> (0<<1)|1); a guest FAIL exits 3.
qemu-system-x86_64 -M pc -accel tcg -cpu "$CPU" -m 2G \
  -display none -no-reboot \
  -chardev socket,id=chrtpm,path="$SOCK" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-crb,tpmdev=tpm0 \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -serial "file:$SERIAL" \
  -kernel "$ELF" &
QPID=$!

# Wait (max ~30s) for the guest to report a PASS/FAIL verdict on serial.
for _ in $(seq 1 120); do
  if grep -q "TPM-VALIDATE: PASS" "$SERIAL" 2>/dev/null; then break; fi
  if grep -q "TPM-VALIDATE: FAIL" "$SERIAL" 2>/dev/null; then break; fi
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
if grep -q "TPM-VALIDATE: PASS" "$SERIAL" 2>/dev/null; then
  echo "RESULT: PASS (Startup+GetRandom+PCR_Extend/Read round-trip on a real swtpm via CRB)"
  exit 0
fi
if grep -q "TPM-VALIDATE: FAIL" "$SERIAL" 2>/dev/null; then
  echo "RESULT: FAIL (see TPM-VALIDATE: FAIL line above)"
  exit 3
fi
echo "RESULT: FAIL (no verdict on serial — guest never reported)"
exit 2

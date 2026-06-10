# go-tpm2/validate

Real-hardware validation harness for the go-tpm2 stack. It boots a
[TamaGo](https://github.com/usbarmory/tamago) `amd64` guest under QEMU, drives a
**real TPM 2.0** — QEMU's `-device tpm-crb` backed by a live
[`swtpm`](https://github.com/stefanberger/swtpm) — through `go-tpm2/crb` (the
Command Response Buffer transport) and `go-tpm2/tpm2` (the command layer), and
asserts a full

```
Startup(CLEAR) -> GetRandom -> PCR_Extend -> PCR_Read
```

cycle end to end. The guest performs the proof itself and prints
`TPM-VALIDATE: PASS` / `FAIL` on COM1; `run.sh` parses the verdict (and the
guest also terminates QEMU with a matching exit code via `isa-debug-exit`).

This is the milestone that confirms or corrects the `// INFERRED:` register
bits in `go-tpm2/crb` and the PCR-handle / auth-area encoding in
`go-tpm2/tpm2` against actual hardware behaviour — the same kind of live
round-trip discipline used in the go-virtio work.

## Run

```sh
./run.sh
```

Requires `swtpm` (`/opt/homebrew/bin/swtpm`), `qemu-system-x86_64`, and the
TamaGo toolchain (path set via `$TAMAGO`). It builds the guest with:

```sh
GOWORK=off GOOS=tamago GOARCH=amd64 GOOSPKG=github.com/usbarmory/tamago \
  "$TAMAGO" build -ldflags "-T 0x10010000 -R 0x1000" -o tpmvalidate.elf ./cmd/tpmvalidate
```

## What the cycle proves

- **GetRandom**: two successive 32-byte reads come back non-zero and differ.
- **PCR_Extend / PCR_Read** on the SHA-256 bank of the debug PCR (16): after the
  extend, `PCR_new == SHA256(PCR_old || digest)`, recomputed in-guest with
  `crypto/sha256`. That identity holding against the live swtpm proves the CRB
  MMIO handshake, the command framing, the bare-index PCR handle, and the
  empty-auth password session are all correct.

## Findings against the live swtpm (QEMU 10.2.2 + swtpm 0.10.1)

- `crb.regData = 0x80` (data buffer offset) — **CONFIRMED**: QEMU reports
  `CTRL_CMD_ADDR = CTRL_RSP_ADDR = 0xFED40080`, i.e. offset `0x80`.
- `crb.bufSize` — **CORRECTED 4096 -> 3968**: the locality is a `0x80`-byte
  control area at `0xFED40000` followed by the data buffer at
  `0xFED40080..0xFED40FFF`, so `CTRL_CMD_SIZE = CTRL_RSP_SIZE = 3968`. The old
  `4096` was the full locality size, not the buffer, and would have admitted a
  declared response 128 bytes past the real buffer end.
- PCR-handle encoding (`tpm2`: PCR[n] marshals as bare index `n`) and the
  password auth area (`authorizationSize = 9`) — **CONFIRMED** by the matching
  `SHA256(old||digest)` digest.

## Machine choice: `-M pc`, not `-M q35`

On this QEMU, attaching **any** TPM device (`tpm-crb` or `tpm-tis`) to `q35`
enables SMM, and QEMU delivers a continuous storm of SMIs from boot. The
firmware-less TamaGo guest has no SMI handler, so each SMI enters SMM at the
default SMBASE, runs garbage, and the CPU triple-faults before `main`
(`-d int` shows hundreds of `SMM: enter`/`RSM` cycles then `v=08`/`v=0e` with
`IDT` base 0). `-M q35,smm=off` quiets the storm but the boot stays
intermittently unstable. `-M pc` exposes no TPM-driven SMM and is reliable
(5/5 PASS); it maps `tpm-crb` at the same `0xFED40000`, so the CRB round-trip
being validated is identical. An unrelated q35 device (e1000) never triggers
the storm — this is a q35+TPM platform quirk, not a go-tpm2 bug.

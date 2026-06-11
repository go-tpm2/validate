# go-tpm2/validate

[![CI](https://github.com/go-tpm2/validate/actions/workflows/ci.yml/badge.svg)](https://github.com/go-tpm2/validate/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

Real-hardware validation **harness** (not a library) for the go-tpm2 stack.
**v0.5.0.** Each harness boots a
[TamaGo](https://github.com/usbarmory/tamago) `amd64` guest under QEMU and
drives a **real TPM 2.0** — QEMU's `-device tpm-crb` (or `-device tpm-tis`)
backed by a live [`swtpm`](https://github.com/stefanberger/swtpm) **0.10.1**
— through [`go-tpm2/crb`](https://github.com/go-tpm2/crb) /
[`go-tpm2/tis`](https://github.com/go-tpm2/tis) (the MMIO transports) and
[`go-tpm2/tpm2`](https://github.com/go-tpm2/tpm2) (the command layer). The
guest performs the proof itself, prints `…: PASS` / `FAIL` on COM1, and
terminates QEMU with a matching exit code via `isa-debug-exit`; the
`run-*.sh` wrapper starts swtpm, parses the verdict, and exits non-zero on
FAIL.

This is where the `// INFERRED:` register bits in `go-tpm2/crb`/`tis` and the
encodings in `go-tpm2/tpm2` are confirmed or corrected against actual TPM
behaviour — the same live round-trip discipline used in the go-virtio work.

## Harnesses

Eight guest harnesses under `cmd/`, each with its `run-*.sh` wrapper:

| Harness | Transport | Script | What it proves against real swtpm |
|---|---|---|---|
| `cmd/tpmvalidate` | **CRB** | `run.sh` | `Startup → GetRandom → PCR_Extend → PCR_Read`: CRB MMIO handshake + framing + bare-index PCR handle + empty-auth session |
| `cmd/tpmvalidate-tis` | **TIS** | `run-tis.sh` | Same cycle over the TIS/FIFO transport (burstCount + Expect bit) |
| `cmd/tpmattest` | CRB | `run-attest.sh` | `Quote` over a `CreatePrimary` AK, then off-TPM `VerifyQuote` of the ECDSA-P256 signature + PCR digest |
| `cmd/tpmseal` | CRB | `run-seal.sh` | PolicyPCR **seal/unseal**: a secret sealed to a PCR value unseals ONLY while that PCR holds it (TPM policy session) |
| `cmd/tpmnv` | CRB | `run-nv.sh` | NV storage: `NVDefineSpace → NVWrite → NVRead → NVReadPublic → NVUndefineSpace` round-trips |
| `cmd/tpmcap` | CRB | `run-cap.sh` | Typed `GetCapability` decoders (PCR banks, properties, manufacturer, algorithms, handles) against live capability data |
| `cmd/tpmek` | CRB | `run-ek.sh` | The EK Credential Profile ECC-P256 (L-2) template produces the expected EK on the live TPM |
| `cmd/tpmcred` | CRB | `run-cred.sh` | Credential activation: an off-TPM `MakeCredential` (from EK public + AK Name) is recovered EXACTLY by `TPM2_ActivateCredential` — proving AK and EK share one TPM |

## Run

```sh
./run.sh            # CRB validate
./run-tis.sh        # TIS validate
./run-seal.sh       # … etc, one per harness above
```

Each script requires `swtpm` (`/opt/homebrew/bin/swtpm`),
`qemu-system-x86_64`, and the TamaGo toolchain (path via `$TAMAGO`). The
guest is built with:

```sh
GOWORK=off GOOS=tamago GOARCH=amd64 GOOSPKG=github.com/usbarmory/tamago \
  "$TAMAGO" build -ldflags "-T 0x10010000 -R 0x1000" \
  -o tpmvalidate.elf ./cmd/tpmvalidate
```

> **CI is build-only.** Hosted CI cannot run the swtpm + full-system QEMU
> round-trips, so the workflow builds the TamaGo toolchain from source (the
> version pinned in `go.mod`) and cross-builds all eight harnesses for
> tamago/amd64. The actual PASS/FAIL proofs run locally via `run-*.sh`.

## What the base cycle proves

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

## swtpm wiring

QEMU connects to swtpm over its control channel (a UNIX socket); each
`run-*.sh` launches `swtpm socket --tpm2 --tpmstate dir=… --ctrl
type=unixio,path=…` with `--flags startup-clear` (so the TPM self-issues
`Startup(CLEAR)` at `_TPM_Init`; the guest's own `Startup` is then redundant
and tolerated), wires it via `-chardev socket,…  -tpmdev emulator,…  -device
tpm-crb|tpm-tis,tpmdev=…`, and uses fresh swtpm state + sockets every run.

## The go-tpm2 stack

This harness validates the four library repos:
[`common`](https://github.com/go-tpm2/common),
[`crb`](https://github.com/go-tpm2/crb),
[`tis`](https://github.com/go-tpm2/tis), and
[`tpm2`](https://github.com/go-tpm2/tpm2).

## Specifications

- TCG TPM 2.0 Library, **Parts 1–4**.
- TCG PC Client Platform TPM Profile (**PTP**) — CRB + FIFO interfaces.
- TCG **EK Credential Profile** (the `tpmek`/`tpmcred` templates).

## License

BSD-3-Clause. See [LICENSE](LICENSE).

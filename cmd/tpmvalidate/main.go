// Headless go-tpm2 validate harness: boots a tamago/amd64 guest under QEMU
// (q35, TCG), drives a REAL TPM 2.0 — QEMU's `-device tpm-crb` backed by a
// live swtpm — through the go-tpm2/crb transport and the go-tpm2/tpm2 command
// layer, and proves a full Startup -> GetRandom -> PCR_Extend -> PCR_Read
// cycle end to end. No host-side observation is needed: the guest performs the
// proof itself and reports TPM-VALIDATE: PASS / FAIL on COM1. run.sh starts
// swtpm, parses the verdict, and exits non-zero on FAIL.
//
// This is the real-hardware milestone that CONFIRMS or CORRECTS the
// `// INFERRED:` register bits in go-tpm2/crb (regData=0x80, bufSize=4096,
// CTRL_CANCEL value, …) and the PCR-handle / auth-area encoding in
// go-tpm2/tpm2 — the same kind of live round-trip that found nine bugs in the
// go-virtio work. A PASS here means the assertions held against a live swtpm.
//
// Cycle and assertions (any failure => FAIL):
//
//   - Open: crb.Open binds to the CRB window at 0xFED40000 and validates
//     INTERFACE_ID advertises CRB. The harness ALSO reads CTRL_CMD_SIZE /
//     CTRL_RSP_SIZE / CTRL_CMD_LADDR / CTRL_CMD_HADDR / CTRL_RSP_ADDR straight
//     off the MMIO block and prints them, so the transcript empirically
//     confirms (or refutes) crb's INFERRED data-buffer base (0x80) and size
//     (4096).
//   - Startup(CLEAR): brings the TPM out of _TPM_Init. swtpm is launched with
//     --flags startup-clear, so a second Startup may report TPM_RC_INITIALIZE;
//     that specific rc is tolerated (the TPM is already started).
//   - GetRandom(32): asserts 32 bytes back, not all-zero, and that a second
//     read differs (a stuck/zero RNG fails).
//   - PCR_Extend(pcr=16, SHA256, digest=0x01..0x01): folds a known digest into
//     the debug PCR. PCR 16 is chosen because it is the debug PCR.
//   - PCR_Read before and after: asserts the bank returns a 32-byte SHA-256
//     digest and that after the extend, new == SHA256(old || digest) — the
//     exact PCR extend identity, recomputed in-guest with crypto/sha256.
//
// If new == SHA256(old||digest) holds against the live swtpm, the whole stack
// — CRB MMIO handshake, command framing, the PCR handle encoding, and the
// password auth area — is proven correct on real hardware.
package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/go-tpm2/validate/board"
	"github.com/go-tpm2/validate/regs"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/crb"
	"github.com/go-tpm2/tpm2"
)

// CRB control-area register offsets the harness reads directly to confirm
// crb's INFERRED buffer base/size. These mirror crb's (unexported) constants.
const (
	regCtrlCmdSize  = 0x58
	regCtrlCmdLAddr = 0x5C
	regCtrlCmdHAddr = 0x60
	regCtrlRspSize  = 0x64
	regCtrlRspAddr  = 0x68 // 64-bit; low dword here, high dword at +4
)

// debugPCR is PCR 16, the architecturally defined debug PCR.
const debugPCR = 16

func main() {
	fmt.Printf("TPM-VALIDATE: boot ok, harness entered main\n")

	r := regs.New()

	// Surface the raw control-area registers BEFORE Open does anything, so a
	// failure in Open still leaves the evidence on the wire. These are the
	// values that confirm or correct crb's INFERRED regData/bufSize.
	cmdSize := r.Read32(regCtrlCmdSize)
	rspSize := r.Read32(regCtrlRspSize)
	cmdLAddr := r.Read32(regCtrlCmdLAddr)
	cmdHAddr := r.Read32(regCtrlCmdHAddr)
	rspLAddr := r.Read32(regCtrlRspAddr)
	rspHAddr := r.Read32(regCtrlRspAddr + 4)

	cmdPhys := uint64(cmdHAddr)<<32 | uint64(cmdLAddr)
	rspPhys := uint64(rspHAddr)<<32 | uint64(rspLAddr)
	cmdOff := cmdPhys - regs.CRBBase
	rspOff := rspPhys - regs.CRBBase

	fmt.Printf("TPM-VALIDATE: CRB base=%#x CMD_SIZE=%d RSP_SIZE=%d\n",
		uint64(regs.CRBBase), cmdSize, rspSize)
	fmt.Printf("TPM-VALIDATE: CMD_ADDR=%#x (off %#x) RSP_ADDR=%#x (off %#x)\n",
		cmdPhys, cmdOff, rspPhys, rspOff)
	// Check the crb data-buffer layout against the live device. regData=0x80
	// was INFERRED and is CONFIRMED here; bufSize was INFERRED as 4096 and the
	// hardware corrected it to 3968 (the locality is 0x80 control area + 3968
	// data), which crb now uses. Report agreement against the corrected value.
	fmt.Printf("TPM-VALIDATE: INFERRED-CHECK regData=0x80 -> CMD_off=%#x %s ; bufSize(=3968, was 4096) -> CMD_SIZE=%d %s\n",
		cmdOff, agree(cmdOff == 0x80), cmdSize, agree(cmdSize == 3968))

	// --- Open the CRB transport and the command layer. --------------------
	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-VALIDATE: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		// swtpm is launched with --flags startup-clear, so the TPM is
		// already started; a redundant Startup returns TPM_RC_INITIALIZE
		// (0x100). Tolerate exactly that; anything else is a real failure.
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-VALIDATE: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-VALIDATE: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-VALIDATE: Startup(CLEAR) OK\n")
	}

	// --- GetRandom(32): entropy proof. ------------------------------------
	a, err := t.GetRandom(32)
	if err != nil {
		fmt.Printf("TPM-VALIDATE: FAIL GetRandom(#1): %v\n", err)
		halt()
	}
	if len(a) != 32 {
		fmt.Printf("TPM-VALIDATE: FAIL GetRandom(#1) length: got %d want 32\n", len(a))
		halt()
	}
	if allZero(a) {
		fmt.Printf("TPM-VALIDATE: FAIL GetRandom(#1) all-zero (no entropy)\n")
		halt()
	}
	b, err := t.GetRandom(32)
	if err != nil {
		fmt.Printf("TPM-VALIDATE: FAIL GetRandom(#2): %v\n", err)
		halt()
	}
	if equal(a, b) {
		fmt.Printf("TPM-VALIDATE: FAIL two GetRandom(32) reads identical (stuck RNG)\n")
		halt()
	}
	fmt.Printf("TPM-VALIDATE: GetRandom #1 = %s\n", hexAll(a))
	fmt.Printf("TPM-VALIDATE: GetRandom #2 = %s\n", hexAll(b))

	// --- PCR_Read(16, SHA256) BEFORE the extend. --------------------------
	sel := []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{debugPCR}}}
	_, before, err := t.PCRRead(sel)
	if err != nil {
		fmt.Printf("TPM-VALIDATE: FAIL PCRRead(before): %v\n", err)
		halt()
	}
	if len(before) != 1 || len(before[0]) != 32 {
		fmt.Printf("TPM-VALIDATE: FAIL PCRRead(before) shape: %d digests, len0=%d\n",
			len(before), digestLen(before))
		halt()
	}
	old := before[0]
	fmt.Printf("TPM-VALIDATE: PCR[16] before = %s\n", hexAll(old))

	// --- PCR_Extend(16, SHA256, 0x01..0x01). ------------------------------
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = 0x01
	}
	if err := t.PCRExtend(debugPCR, uint16(common.AlgSHA256), digest); err != nil {
		fmt.Printf("TPM-VALIDATE: FAIL PCRExtend: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-VALIDATE: PCRExtend(16, SHA256, 01..01) OK\n")

	// --- PCR_Read(16, SHA256) AFTER the extend. ---------------------------
	_, after, err := t.PCRRead(sel)
	if err != nil {
		fmt.Printf("TPM-VALIDATE: FAIL PCRRead(after): %v\n", err)
		halt()
	}
	if len(after) != 1 || len(after[0]) != 32 {
		fmt.Printf("TPM-VALIDATE: FAIL PCRRead(after) shape: %d digests, len0=%d\n",
			len(after), digestLen(after))
		halt()
	}
	now := after[0]
	fmt.Printf("TPM-VALIDATE: PCR[16] after  = %s\n", hexAll(now))

	// The PCR extend identity: PCR_new = H( PCR_old || digest ).
	h := sha256.New()
	h.Write(old)
	h.Write(digest)
	expected := h.Sum(nil)
	fmt.Printf("TPM-VALIDATE: expected      = %s\n", hexAll(expected))

	if equal(now, old) {
		fmt.Printf("TPM-VALIDATE: FAIL PCR[16] unchanged after extend\n")
		halt()
	}
	if !equal(now, expected) {
		fmt.Printf("TPM-VALIDATE: FAIL PCR[16] != SHA256(old||digest)\n")
		halt()
	}

	fmt.Printf("TPM-VALIDATE: PASS Startup+GetRandom(entropy,distinct)+PCR_Extend/Read(SHA256(old||digest)) on a real swtpm via CRB\n")
	// Clean QEMU exit (code 0) via isa-debug-exit; see board.Shutdown.
	board.Shutdown(0)
}

// isRC reports whether err is a *tpm2.TPMError carrying the given raw rc.
func isRC(err error, rc uint32) bool {
	if e, ok := err.(*tpm2.TPMError); ok {
		return e.RC == rc
	}
	return false
}

func agree(b bool) string {
	if b {
		return "CONFIRMED"
	}
	return "MISMATCH"
}

func digestLen(d [][]byte) int {
	if len(d) == 0 {
		return -1
	}
	return len(d[0])
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// hexAll renders b as lowercase hex.
func hexAll(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// halt prints nothing more and asks QEMU to terminate with a non-zero exit
// code (isa-debug-exit value 1 -> process status 3), so a FAIL both surfaces
// on serial and propagates a failure to the host harness.
func halt() {
	board.Shutdown(1)
}

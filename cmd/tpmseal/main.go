// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 PCR-SEALING harness: boots a tamago/amd64 guest under QEMU
// (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by a live
// swtpm) through go-tpm2/crb + go-tpm2/tpm2, and proves the measured-boot
// PAYOFF end to end: a secret SEALED to a PCR value unseals ONLY when that
// PCR still holds the sealed-to value, enforced by a TPM 2.0 POLICY SESSION.
//
//	Startup(CLEAR)
//	CreateStoragePrimary    -> an ECC P-256 restricted-decrypt storage parent
//	PCR_Read(16)            -> baseline
//	PCR_Extend(16, M1)      -> fold a known measurement
//	PCR_Read(16)            -> the "good" value to seal against
//	SealToPCR(secret, {16}=good) -> TPM2_Create a sealed keyedhash object
//	                                whose authPolicy = PolicyPCRDigest(good)
//	Load + StartAuthSession(POLICY) + PolicyPCR + Unseal
//	                        -> POSITIVE: the secret must come back intact
//	PCR_Extend(16, M2)      -> PCR16 now != good
//	fresh policy session + PolicyPCR + Unseal
//	                        -> NEGATIVE: must FAIL with a policy error
//
// The swtpm is the oracle. A PASS means a live TPM confirmed that our offline
// PolicyPCRDigest construction matches what TPM2_PolicyPCR computes (else the
// positive unseal would fail), AND that the policy is actually enforced (else
// the negative unseal would wrongly succeed). The same self-consistent-fake
// trap that the CRB bufSize / TIS stsValid bugs sprang cannot hide here: only
// a real TPM both releases the secret on a matching policy and rejects a
// non-matching one.
//
// run-seal.sh starts swtpm, parses the verdict on COM1, and exits non-zero on
// FAIL.
package main

import (
	"fmt"

	"github.com/go-tpm2/validate/board"
	"github.com/go-tpm2/validate/regs"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/crb"
	"github.com/go-tpm2/tpm2"
)

// debugPCR is PCR 16, the architecturally defined debug/application PCR — the
// one the other validate harnesses extend, freely resettable/extendable
// without owning a hierarchy.
const debugPCR = 16

// secret is the payload sealed to the PCR state.
const secret = "GO-TPM2-SEALED-SECRET"

// rcPolicyFail is the canonical FMT1 base value of TPM_RC_POLICY_FAIL:
// RC_FMT1 (0x080) + 0x01D = 0x09D. Raised when a policy assertion does not
// pass, i.e. the session's policyDigest does not match the object's
// authPolicy. The TPM ORs in an N field (handle/session number) in bits
// [11:8] of the returned rc, so the negative-case Unseal arrives as 0x99D
// (N=9 -> session 1); masking with rcFMT1Base recovers 0x09D. TCG "TPM 2.0
// Part 2: Structures", clause "TPM_RC (Response Codes)" / "Response Code
// Formats" (RC_FMT1).
const rcPolicyFail = 0x09D

// rcFMT1Base masks a returned FMT1 rc down to its base error, clearing the
// N (handle/parameter/session-number) field in bits [11:8] while keeping the
// format bit (0x080), the parameter bit (0x040), and the 6-bit error number
// (0x03F). TCG "Part 2", "Response Code Formats".
const rcFMT1Base = 0x0BF

func main() {
	fmt.Printf("TPM-SEAL: boot ok, harness entered main\n")

	r := regs.New()

	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-SEAL: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-SEAL: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-SEAL: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-SEAL: Startup(CLEAR) OK\n")
	}

	// --- Storage parent. --------------------------------------------------
	parent, err := t.CreateStoragePrimary()
	if err != nil {
		fmt.Printf("TPM-SEAL: FAIL CreateStoragePrimary: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-SEAL: storage parent handle = %#x\n", parent)

	sel := []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{debugPCR}}}

	// --- Extend PCR16 with a known measurement M1, then read the "good"
	//     value we will seal to. -----------------------------------------
	m1 := fill(0xA1, 32)
	if err := t.PCRExtend(debugPCR, uint16(common.AlgSHA256), m1); err != nil {
		fmt.Printf("TPM-SEAL: FAIL PCRExtend(M1): %v\n", err)
		halt()
	}
	_, good, err := t.PCRRead(sel)
	if err != nil || len(good) != 1 || len(good[0]) != 32 {
		fmt.Printf("TPM-SEAL: FAIL PCRRead(good): %v\n", err)
		halt()
	}
	fmt.Printf("TPM-SEAL: PCR[16] good = %s\n", hexAll(good[0]))

	// --- Seal the secret to the good PCR state. ---------------------------
	priv, pub, policy, err := t.SealToPCR(parent, []byte(secret), sel, good)
	if err != nil {
		fmt.Printf("TPM-SEAL: FAIL SealToPCR: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-SEAL: sealed; offline policyDigest = %s\n", hexAll(policy))

	// Debug cross-check: read back the session policyDigest the TPM computes
	// from the CURRENT (good) PCRs and confirm it equals our offline value.
	// This isolates a policy-digest mismatch before we even attempt Unseal.
	{
		nonce, nerr := t.GetRandom(32)
		if nerr != nil || len(nonce) != 32 {
			fmt.Printf("TPM-SEAL: FAIL GetRandom(nonce): %v\n", nerr)
			halt()
		}
		sess, _, serr := t.StartAuthSession(nonce)
		if serr != nil {
			fmt.Printf("TPM-SEAL: FAIL StartAuthSession(debug): %v\n", serr)
			halt()
		}
		if perr := t.PolicyPCR(sess, sel); perr != nil {
			fmt.Printf("TPM-SEAL: FAIL PolicyPCR(debug): %v\n", perr)
			halt()
		}
		tpmDigest, derr := t.PolicyGetDigest(sess)
		if derr != nil {
			fmt.Printf("TPM-SEAL: FAIL PolicyGetDigest: %v\n", derr)
			halt()
		}
		fmt.Printf("TPM-SEAL: TPM session policyDigest = %s\n", hexAll(tpmDigest))
		if !equal(tpmDigest, policy) {
			fmt.Printf("TPM-SEAL: FAIL policyDigest MISMATCH (offline construction wrong)\n")
			halt()
		}
		fmt.Printf("TPM-SEAL: policyDigest MATCH (offline == TPM)\n")
	}

	// --- POSITIVE: unseal while PCR16 still holds the good value. ----------
	nonce1, err := t.GetRandom(32)
	if err != nil || len(nonce1) != 32 {
		fmt.Printf("TPM-SEAL: FAIL GetRandom(nonce1): %v\n", err)
		halt()
	}
	out, err := t.UnsealWithPCR(parent, priv, pub, sel, nonce1)
	if err != nil {
		fmt.Printf("TPM-SEAL: FAIL positive Unseal: %v\n", err)
		halt()
	}
	if string(out) != secret {
		fmt.Printf("TPM-SEAL: FAIL unsealed %q != %q\n", string(out), secret)
		halt()
	}
	fmt.Printf("TPM-SEAL: unseal-good OK secret=%q\n", string(out))

	// --- NEGATIVE: change PCR16, then a fresh policy session must FAIL. -----
	m2 := fill(0xB2, 32)
	if err := t.PCRExtend(debugPCR, uint16(common.AlgSHA256), m2); err != nil {
		fmt.Printf("TPM-SEAL: FAIL PCRExtend(M2): %v\n", err)
		halt()
	}
	_, changed, err := t.PCRRead(sel)
	if err == nil && len(changed) == 1 {
		fmt.Printf("TPM-SEAL: PCR[16] changed = %s\n", hexAll(changed[0]))
	}
	nonce2, err := t.GetRandom(32)
	if err != nil || len(nonce2) != 32 {
		fmt.Printf("TPM-SEAL: FAIL GetRandom(nonce2): %v\n", err)
		halt()
	}
	_, err = t.UnsealWithPCR(parent, priv, pub, sel, nonce2)
	if err == nil {
		fmt.Printf("TPM-SEAL: FAIL unseal-after-change SUCCEEDED (policy not enforced!)\n")
		halt()
	}
	te, ok := err.(*tpm2.TPMError)
	if !ok {
		fmt.Printf("TPM-SEAL: FAIL negative Unseal returned non-TPM error: %v\n", err)
		halt()
	}
	// The returned rc is FMT1 with an N (session-number) field ORed in; mask
	// it to the base error and require exactly TPM_RC_POLICY_FAIL (0x09D), so
	// a genuine policy rejection is distinguished from any other failure.
	fmt.Printf("TPM-SEAL: unseal-after-change REJECTED (rc=%#x)\n", te.RC)
	if int(te.RC)&rcFMT1Base != rcPolicyFail {
		fmt.Printf("TPM-SEAL: FAIL negative rc %#x is not TPM_RC_POLICY_FAIL (base 0x09D)\n", te.RC)
		halt()
	}

	fmt.Printf("TPM-SEAL: unseal-good OK secret=%q; unseal-after-change REJECTED (rc=%#x); PASS\n",
		secret, te.RC)
	board.Shutdown(0)
}

// isRC reports whether err is a *tpm2.TPMError carrying the given raw rc.
func isRC(err error, rc uint32) bool {
	if e, ok := err.(*tpm2.TPMError); ok {
		return e.RC == rc
	}
	return false
}

// fill returns an n-byte slice of the byte v.
func fill(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
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

// halt asks QEMU to terminate with a non-zero exit code so a FAIL surfaces on
// serial and propagates to the host harness.
func halt() {
	board.Shutdown(1)
}

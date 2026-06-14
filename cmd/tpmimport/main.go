// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 OBJECT-DUPLICATION / IMPORT harness: boots a tamago/amd64
// guest under QEMU (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb`
// backed by a live swtpm) through go-tpm2/crb + go-tpm2/tpm2, and proves the
// OFFLINE control-plane wrap end to end: a secret WRAPPED off-TPM (pure-Go
// WrapToPCR, no TPM) to the node's storage-key public + a PolicyPCR over the
// node's current PCRs is TPM2_Imported under that storage key, Loaded, and
// Unsealed — recovering EXACTLY the original ONLY when the live PCRs still
// match the wrapped-to values, enforced by a TPM 2.0 POLICY SESSION.
//
//	Startup(CLEAR)
//	CreateStoragePrimaryPub -> ECC P-256 restricted-decrypt storage parent (SRK)
//	                           + its public point (x, y)
//	PCR_Read(16)            -> baseline
//	PCR_Extend(16, M1)      -> fold a known measurement
//	PCR_Read(16)            -> the "good" value to wrap against
//	WrapToPCR(srkPub, secret, {16}=good)   -> OFFLINE, no-TPM control-plane wrap
//	                           producing objectPublic / duplicate / inSymSeed
//	                           (KDFe "DUPLICATE", KDFa "STORAGE"/"INTEGRITY")
//	Import(SRK, ...) -> Load -> StartAuthSession(POLICY) + PolicyPCR + Unseal
//	                        -> POSITIVE: the secret must come back intact
//	PCR_Extend(16, M2)      -> PCR16 now != good
//	fresh Import -> Load -> PolicyPCR + Unseal
//	                        -> NEGATIVE: must FAIL with a policy error
//
// The swtpm is the oracle. A PASS means a live TPM accepted our OFFLINE
// duplication wrap (the ECDH-to-SRK seed, the "DUPLICATE"/"STORAGE"/"INTEGRITY"
// KDF labels, the outer HMAC over encSensitive||Name, the imported-object
// TPMA_OBJECT, and the Import symmetricAlg/inSymSeed framing) — TPM2_Import is
// the unforgiving check here, rejecting any wrap it cannot reproduce — AND that
// the resulting object's PCR policy is actually enforced (else the negative
// unseal would wrongly succeed). The self-consistent-fake trap (a unit test
// that wraps and unwraps with the same code) cannot hide here: only a real TPM
// both Imports/releases on a matching policy and rejects a non-matching one.
//
// run-import.sh starts swtpm, parses the verdict on COM1, and exits non-zero on
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

// secret is the payload OFFLINE-wrapped to the PCR state and recovered by the
// import->load->unseal round trip.
const secret = "GO-TPM2-IMPORTED-SECRET"

// rcPolicyFail is the canonical FMT1 base value of TPM_RC_POLICY_FAIL:
// RC_FMT1 (0x080) + 0x01D = 0x09D. Raised when a policy assertion does not
// pass, i.e. the session's policyDigest does not match the imported object's
// authPolicy. The TPM ORs in an N field (handle/session number) in bits
// [11:8] of the returned rc, so the negative-case Unseal arrives as 0x99D
// (N=9 -> session 1); masking with rcFMT1Base recovers 0x09D. TCG "TPM 2.0
// Part 2: Structures", clause "TPM_RC (Response Codes)".
const rcPolicyFail = 0x09D

// rcFMT1Base masks a returned FMT1 rc down to its base error, clearing the
// N (handle/parameter/session-number) field in bits [11:8] while keeping the
// format bit (0x080), the parameter bit (0x040), and the 6-bit error number
// (0x03F). TCG "Part 2", "Response Code Formats".
const rcFMT1Base = 0x0BF

func main() {
	fmt.Printf("TPM-IMPORT: boot ok, harness entered main\n")

	r := regs.New()

	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-IMPORT: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-IMPORT: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-IMPORT: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-IMPORT: Startup(CLEAR) OK\n")
	}

	// --- Storage parent (SRK) + its public point. -------------------------
	// CreateStoragePrimaryPub returns the storage key handle AND its ECC
	// public (x, y) — the point the OFFLINE WrapToPCR wraps against (the
	// control plane never sees the TPM; it has only this public).
	parent, srkPub, err := t.CreateStoragePrimaryPub()
	if err != nil {
		fmt.Printf("TPM-IMPORT: FAIL CreateStoragePrimaryPub: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-IMPORT: storage parent handle = %#x\n", parent)
	fmt.Printf("TPM-IMPORT: SRK pub.x = %s\n", hexAll(srkPub.X))
	fmt.Printf("TPM-IMPORT: SRK pub.y = %s\n", hexAll(srkPub.Y))

	sel := []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{debugPCR}}}

	// --- Extend PCR16 with a known measurement M1, then read the "good"
	//     value we will WRAP to. -------------------------------------------
	m1 := fill(0xA1, 32)
	if err := t.PCRExtend(debugPCR, uint16(common.AlgSHA256), m1); err != nil {
		fmt.Printf("TPM-IMPORT: FAIL PCRExtend(M1): %v\n", err)
		halt()
	}
	_, good, err := t.PCRRead(sel)
	if err != nil || len(good) != 1 || len(good[0]) != 32 {
		fmt.Printf("TPM-IMPORT: FAIL PCRRead(good): %v\n", err)
		halt()
	}
	fmt.Printf("TPM-IMPORT: PCR[16] good = %s\n", hexAll(good[0]))

	// --- OFFLINE control-plane wrap: WrapToPCR (pure Go, NO TPM). ----------
	// Bind the secret to a KEYEDHASH sealed object whose authPolicy is the
	// PolicyPCR digest over the good PCR state, and OUTER-WRAP its sensitive
	// area for the node's SRK public. The three returned blobs are exactly
	// TPM2_Import's inputs.
	wrap, err := tpm2.WrapToPCR(srkPub, []byte(secret), sel, good, nil)
	if err != nil {
		fmt.Printf("TPM-IMPORT: FAIL WrapToPCR: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-IMPORT: offline wrap OK (objectPublic=%dB duplicate=%dB inSymSeed=%dB)\n",
		len(wrap.ObjectPublic), len(wrap.Duplicate), len(wrap.InSymSeed))
	fmt.Printf("TPM-IMPORT: offline policyDigest = %s\n", hexAll(tpm2.PolicyPCRDigest(sel, good)))

	// Debug cross-check: confirm our offline PolicyPCRDigest matches what the
	// TPM's PolicyPCR computes over the CURRENT (good) PCRs. This isolates a
	// policy-digest mismatch (would surface as a positive-case policy failure)
	// from a duplication-wrap bug (would surface as an Import integrity error).
	{
		nonce, nerr := t.GetRandom(32)
		if nerr != nil || len(nonce) != 32 {
			fmt.Printf("TPM-IMPORT: FAIL GetRandom(debug nonce): %v\n", nerr)
			halt()
		}
		sess, _, serr := t.StartAuthSession(nonce)
		if serr != nil {
			fmt.Printf("TPM-IMPORT: FAIL StartAuthSession(debug): %v\n", serr)
			halt()
		}
		if perr := t.PolicyPCR(sess, sel); perr != nil {
			fmt.Printf("TPM-IMPORT: FAIL PolicyPCR(debug): %v\n", perr)
			halt()
		}
		tpmDigest, derr := t.PolicyGetDigest(sess)
		if derr != nil {
			fmt.Printf("TPM-IMPORT: FAIL PolicyGetDigest: %v\n", derr)
			halt()
		}
		fmt.Printf("TPM-IMPORT: TPM session policyDigest = %s\n", hexAll(tpmDigest))
		if !equal(tpmDigest, tpm2.PolicyPCRDigest(sel, good)) {
			fmt.Printf("TPM-IMPORT: FAIL policyDigest MISMATCH (offline construction wrong)\n")
			halt()
		}
		fmt.Printf("TPM-IMPORT: policyDigest MATCH (offline == TPM)\n")
	}

	// --- POSITIVE: Import -> Load -> PolicyPCR + Unseal while PCR16 still
	//     holds the good value. The recovered secret must equal the original. -
	nonce1, err := t.GetRandom(32)
	if err != nil || len(nonce1) != 32 {
		fmt.Printf("TPM-IMPORT: FAIL GetRandom(nonce1): %v\n", err)
		halt()
	}
	out, err := t.ImportAndUnseal(parent, wrap.ObjectPublic, wrap.Duplicate, wrap.InSymSeed, sel, nonce1)
	if err != nil {
		fmt.Printf("TPM-IMPORT: FAIL positive Import/Unseal: %v\n", err)
		halt()
	}
	if string(out) != secret {
		fmt.Printf("TPM-IMPORT: FAIL unsealed %q != %q\n", string(out), secret)
		halt()
	}
	fmt.Printf("TPM-IMPORT: unseal-good OK secret=%q\n", string(out))

	// --- NEGATIVE: change PCR16, then a fresh Import -> Load -> PolicyPCR +
	//     Unseal must FAIL. The duplication blobs are identical (the offline
	//     wrap is bound to the OLD good PCRs); only the live PCR state moved,
	//     so the policy session can no longer satisfy the object's authPolicy. -
	m2 := fill(0xB2, 32)
	if err := t.PCRExtend(debugPCR, uint16(common.AlgSHA256), m2); err != nil {
		fmt.Printf("TPM-IMPORT: FAIL PCRExtend(M2): %v\n", err)
		halt()
	}
	_, changed, err := t.PCRRead(sel)
	if err == nil && len(changed) == 1 {
		fmt.Printf("TPM-IMPORT: PCR[16] changed = %s\n", hexAll(changed[0]))
	}
	nonce2, err := t.GetRandom(32)
	if err != nil || len(nonce2) != 32 {
		fmt.Printf("TPM-IMPORT: FAIL GetRandom(nonce2): %v\n", err)
		halt()
	}
	_, err = t.ImportAndUnseal(parent, wrap.ObjectPublic, wrap.Duplicate, wrap.InSymSeed, sel, nonce2)
	if err == nil {
		fmt.Printf("TPM-IMPORT: FAIL unseal-after-change SUCCEEDED (policy not enforced!)\n")
		halt()
	}
	te, ok := err.(*tpm2.TPMError)
	if !ok {
		fmt.Printf("TPM-IMPORT: FAIL negative Import/Unseal returned non-TPM error: %v\n", err)
		halt()
	}
	// The returned rc is FMT1 with an N (session-number) field ORed in; mask
	// it to the base error and require exactly TPM_RC_POLICY_FAIL (0x09D), so
	// a genuine policy rejection is distinguished from any other failure
	// (notably an Import integrity error, which would mean the wrap itself was
	// wrong rather than the policy being enforced).
	fmt.Printf("TPM-IMPORT: unseal-after-change REJECTED (rc=%#x)\n", te.RC)
	if int(te.RC)&rcFMT1Base != rcPolicyFail {
		fmt.Printf("TPM-IMPORT: FAIL negative rc %#x is not TPM_RC_POLICY_FAIL (base 0x09D)\n", te.RC)
		halt()
	}

	fmt.Printf("TPM-IMPORT: unseal-good OK secret=%q; unseal-after-change REJECTED (rc=%#x); PASS\n",
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

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 ATTESTATION harness: boots a tamago/amd64 guest under QEMU
// (-M pc, TCG), drives a REAL TPM 2.0 (QEMU's `-device tpm-crb` backed by a
// live swtpm) through the go-tpm2/crb transport and the go-tpm2/tpm2 command
// layer, and proves the full measured-boot attestation milestone end to end:
//
//	Startup(CLEAR)
//	CreatePrimary  -> an ECC P-256 restricted signing Attestation Key (AK)
//	PCR_Extend(16) -> fold a known digest into the debug PCR
//	PCR_Read(16)   -> read back the post-extend PCR value
//	Quote(AK, {PCR16}, nonce) -> a TPM-signed TPMS_ATTEST over the PCR digest
//	VerifyQuote    -> IN-GUEST: ECDSA-P256 verify the signature over the
//	                  attest with the AK public point AND confirm the quoted
//	                  pcrDigest == SHA256(PCR16 value)
//
// No host-side observation is needed: the guest performs the cryptographic
// proof itself and reports TPM-ATTEST: ... PASS / FAIL on COM1. run-attest.sh
// starts swtpm, parses the verdict, and exits non-zero on FAIL.
//
// A PASS means a live swtpm CONFIRMED every marshaling detail of the
// attestation path: the TPM2B_PUBLIC for an ECC restricted signing key, the
// TPM2_CreatePrimary / TPM2_Quote auth areas, the TPMS_ATTEST layout, and the
// TPMT_SIGNATURE (ECDSA r,s) decode. The same self-consistent-fake trap that
// the CRB bufSize and TIS stsValid bugs sprang cannot hide here: the guest
// re-derives the signed digest and the PCR digest independently and the swtpm
// either signs bytes that verify against the public key it returned, or it
// does not.
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

// debugPCR is PCR 16, the architecturally defined debug PCR — the same PCR the
// non-attest validate harness extends.
const debugPCR = 16

func main() {
	fmt.Printf("TPM-ATTEST: boot ok, harness entered main\n")

	r := regs.New()

	// --- Open the CRB transport and the command layer. --------------------
	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-ATTEST: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		// swtpm is launched with --flags startup-clear, so a redundant
		// Startup returns TPM_RC_INITIALIZE (0x100); tolerate exactly that.
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-ATTEST: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-ATTEST: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-ATTEST: Startup(CLEAR) OK\n")
	}

	// --- CreatePrimary: an ECC P-256 restricted signing AK. ---------------
	akHandle, akPub, err := t.CreatePrimary()
	if err != nil {
		fmt.Printf("TPM-ATTEST: FAIL CreatePrimary: %v\n", err)
		halt()
	}
	if len(akPub.X) == 0 || len(akPub.Y) == 0 {
		fmt.Printf("TPM-ATTEST: FAIL CreatePrimary returned empty AK point\n")
		halt()
	}
	fmt.Printf("TPM-ATTEST: AK handle = %#x\n", akHandle)
	fmt.Printf("TPM-ATTEST: AK pub X  = %s\n", hexAll(akPub.X))
	fmt.Printf("TPM-ATTEST: AK pub Y  = %s\n", hexAll(akPub.Y))

	// --- PCR_Extend(16, SHA256, 0x01..0x01). ------------------------------
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = 0x01
	}
	if err := t.PCRExtend(debugPCR, uint16(common.AlgSHA256), digest); err != nil {
		fmt.Printf("TPM-ATTEST: FAIL PCRExtend: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-ATTEST: PCRExtend(16, SHA256, 01..01) OK\n")

	// --- PCR_Read(16): the value the quote must commit to. ----------------
	sel := []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{debugPCR}}}
	_, pcrs, err := t.PCRRead(sel)
	if err != nil {
		fmt.Printf("TPM-ATTEST: FAIL PCRRead: %v\n", err)
		halt()
	}
	if len(pcrs) != 1 || len(pcrs[0]) != 32 {
		fmt.Printf("TPM-ATTEST: FAIL PCRRead shape: %d digests\n", len(pcrs))
		halt()
	}
	fmt.Printf("TPM-ATTEST: PCR[16]   = %s\n", hexAll(pcrs[0]))

	// --- Quote(AK, {PCR16}, nonce). ---------------------------------------
	nonce := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE}
	quoted, sig, err := t.Quote(akHandle, nonce, sel)
	if err != nil {
		fmt.Printf("TPM-ATTEST: FAIL Quote: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-ATTEST: quoted    = %s\n", hexAll(quoted))
	fmt.Printf("TPM-ATTEST: sig.R     = %s\n", hexAll(sig.R))
	fmt.Printf("TPM-ATTEST: sig.S     = %s\n", hexAll(sig.S))

	// --- VerifyQuote IN-GUEST: signature + pcrDigest. ---------------------
	// The expected pcrDigest is SHA256 of the concatenated selected PCR
	// values; for one PCR that is SHA256(PCR16). VerifyQuote re-derives it
	// internally from the values we pass, and also ECDSA-verifies the
	// signature over SHA256(quoted) with the AK public point.
	info, err := tpm2.VerifyQuote(akPub, quoted, sig, pcrs)
	if err != nil {
		fmt.Printf("TPM-ATTEST: FAIL VerifyQuote: %v\n", err)
		halt()
	}

	// Bind the quote to our challenge: extraData must echo the nonce.
	if !equal(info.ExtraData, nonce) {
		fmt.Printf("TPM-ATTEST: FAIL extraData != nonce: got %s want %s\n",
			hexAll(info.ExtraData), hexAll(nonce))
		halt()
	}

	// Independent cross-check of the pcrDigest the TPM committed to.
	want := sha256.Sum256(pcrs[0])
	if !equal(info.Quote.PCRDigest, want[:]) {
		fmt.Printf("TPM-ATTEST: FAIL quoted pcrDigest %s != SHA256(PCR16) %s\n",
			hexAll(info.Quote.PCRDigest), hexAll(want[:]))
		halt()
	}
	fmt.Printf("TPM-ATTEST: pcrDigest = %s (== SHA256(PCR16))\n", hexAll(info.Quote.PCRDigest))

	// Negative control: a one-byte tamper of the signed attest must FAIL the
	// signature check, proving the verify is real and not a no-op.
	tampered := append([]byte(nil), quoted...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := tpm2.VerifyQuote(akPub, tampered, sig, pcrs); err == nil {
		fmt.Printf("TPM-ATTEST: FAIL tampered attest still verified (verify is a no-op!)\n")
		halt()
	}
	fmt.Printf("TPM-ATTEST: negative control OK (tampered attest rejected)\n")

	fmt.Printf("TPM-ATTEST: signature OK, pcrDigest matches, PASS\n")
	board.Shutdown(0)
}

// isRC reports whether err is a *tpm2.TPMError carrying the given raw rc.
func isRC(err error, rc uint32) bool {
	if e, ok := err.(*tpm2.TPMError); ok {
		return e.RC == rc
	}
	return false
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

// halt asks QEMU to terminate with a non-zero exit code so a FAIL both
// surfaces on serial and propagates to the host harness.
func halt() {
	board.Shutdown(1)
}

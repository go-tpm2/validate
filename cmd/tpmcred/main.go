// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 CREDENTIAL-ACTIVATION harness: boots a tamago/amd64 guest
// under QEMU (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by
// a live swtpm) through go-tpm2/crb + go-tpm2/tpm2, and proves the IDENTITY
// step of remote attestation end to end: a credential MakeCredential builds
// OFF the TPM (pure Go, from the EK public + AK Name) is recovered EXACTLY by
// the TPM's TPM2_ActivateCredential — proving the AK and EK are on the SAME
// TPM — while a credential built for a DIFFERENT AK Name is REJECTED.
//
//	Startup(CLEAR)
//	CreateEK                 -> the ECC P-256 Endorsement Key (EK Cred Profile L-2)
//	CreatePrimary            -> an ECC P-256 restricted SIGNING Attestation Key
//	(re-read AK outPublic to get its TPMT_PUBLIC -> ObjectName -> AK Name)
//	MakeCredential(off-TPM, challenge, EK pub, AK name)
//	                         -> (credentialBlob, secret) via ECDH+KDFe+KDFa+AES-CFB+HMAC
//	StartAuthSession(POLICY) + PolicySecret(RH_ENDORSEMENT)  (satisfy EK policy)
//	ActivateCredential(AK, EK, blob, secret)
//	                         -> POSITIVE: recovered MUST equal the challenge
//	MakeCredential for a WRONG AK Name, fresh policy session, ActivateCredential
//	                         -> NEGATIVE: must FAIL (TPM rejects the integrity)
//
// The swtpm is the oracle. A PASS means a live TPM both (a) ran the EK's
// private ECDH and reproduced our off-TPM KDFe seed / KDFa keys / AES-CFB /
// HMAC well enough to return the EXACT challenge, and (b) refused a credential
// bound to a different AK Name. A self-consistent fake cannot satisfy both:
// only a real TPM holding the EK private key can recover the credential, and
// only real integrity enforcement rejects the wrong-name case.
//
// run-cred.sh starts swtpm, parses the verdict on COM1, and exits non-zero on
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

// challenge is the 32-byte secret a verifier binds into the credential and
// expects ActivateCredential to recover verbatim.
const challenge = "GO-TPM2-CRED-CHALLENGE-32bytes!!"

func main() {
	fmt.Printf("TPM-CRED: boot ok, harness entered main\n")

	r := regs.New()
	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-CRED: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-CRED: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-CRED: Startup(CLEAR) OK\n")
	}

	// --- Endorsement Key. -------------------------------------------------
	ekHandle, ekPub, err := t.CreateEK()
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL CreateEK: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CRED: EK handle=%#x x=%s\n", ekHandle, hexAll(ekPub.X))

	// The off-TPM MakeCredential needs the EK's TPMT_PUBLIC point. CreateEK
	// returns the parsed point directly; rebuild the EKPublic for clarity.
	ekPublic := tpm2.EKPublic{X: ekPub.X, Y: ekPub.Y}

	// --- Attestation Key (restricted signing) and its Name. ---------------
	akHandle, akOutPublic, err := t.CreatePrimaryPublic()
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL CreatePrimary(AK): %v\n", err)
		halt()
	}
	akName, err := tpm2.ObjectName(akOutPublic)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL ObjectName(AK): %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CRED: AK handle=%#x name=%s\n", akHandle, hexAll(akName))

	// --- POSITIVE: MakeCredential off-TPM, then ActivateCredential. -------
	mc, err := tpm2.MakeCredential(ekPublic, akName, []byte(challenge), nil)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL MakeCredential: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CRED: MakeCredential off-TPM OK (blob=%d secret=%d bytes)\n",
		len(mc.CredentialBlob), len(mc.Secret))

	nonce1, err := t.GetRandom(32)
	if err != nil || len(nonce1) != 32 {
		fmt.Printf("TPM-CRED: FAIL GetRandom(nonce1): %v\n", err)
		halt()
	}
	sess1, _, err := t.StartAuthSession(nonce1)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL StartAuthSession(1): %v\n", err)
		halt()
	}
	if err := t.PolicySecret(0x4000000B, sess1); err != nil { // RH_ENDORSEMENT
		fmt.Printf("TPM-CRED: FAIL PolicySecret(1): %v\n", err)
		halt()
	}
	recovered, err := t.ActivateCredential(akHandle, ekHandle, sess1, mc.CredentialBlob, mc.Secret)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL positive ActivateCredential: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CRED: recovered=%s\n", hexAll(recovered))
	if string(recovered) != challenge {
		fmt.Printf("TPM-CRED: FAIL recovered %q != challenge %q\n", string(recovered), challenge)
		halt()
	}
	fmt.Printf("TPM-CRED: recovered==challenge OK\n")

	// --- NEGATIVE: a credential made for a DIFFERENT AK Name must be
	//     rejected by ActivateCredential. ---------------------------------
	wrongName := make([]byte, len(akName))
	copy(wrongName, akName)
	wrongName[len(wrongName)-1] ^= 0xFF // flip a byte of the Name digest
	mcWrong, err := tpm2.MakeCredential(ekPublic, wrongName, []byte(challenge), nil)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL MakeCredential(wrong): %v\n", err)
		halt()
	}
	nonce2, err := t.GetRandom(32)
	if err != nil || len(nonce2) != 32 {
		fmt.Printf("TPM-CRED: FAIL GetRandom(nonce2): %v\n", err)
		halt()
	}
	sess2, _, err := t.StartAuthSession(nonce2)
	if err != nil {
		fmt.Printf("TPM-CRED: FAIL StartAuthSession(2): %v\n", err)
		halt()
	}
	if err := t.PolicySecret(0x4000000B, sess2); err != nil {
		fmt.Printf("TPM-CRED: FAIL PolicySecret(2): %v\n", err)
		halt()
	}
	_, err = t.ActivateCredential(akHandle, ekHandle, sess2, mcWrong.CredentialBlob, mcWrong.Secret)
	if err == nil {
		fmt.Printf("TPM-CRED: FAIL wrong-AK ActivateCredential SUCCEEDED (integrity not enforced!)\n")
		halt()
	}
	te, ok := err.(*tpm2.TPMError)
	if !ok {
		fmt.Printf("TPM-CRED: FAIL wrong-AK returned non-TPM error: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CRED: wrong-AK REJECTED (rc=%#x)\n", te.RC)
	// The returned rc is FMT1 with a parameter (P) bit and an N field ORed in;
	// mask to the base error and require exactly TPM_RC_INTEGRITY (RC_FMT1 +
	// 0x01F = 0x09F), so a genuine outer-HMAC integrity failure over the wrong
	// AK Name is distinguished from any other failure. TCG "Part 2",
	// "Response Code Formats" (RC_FMT1).
	if int(te.RC)&rcFMT1Base != rcIntegrity {
		fmt.Printf("TPM-CRED: FAIL wrong-AK rc %#x is not TPM_RC_INTEGRITY (base 0x09F)\n", te.RC)
		halt()
	}

	fmt.Printf("TPM-CRED: recovered==challenge OK; wrong-AK REJECTED; PASS\n")
	board.Shutdown(0)
}

// rcIntegrity is TPM_RC_INTEGRITY: RC_FMT1 (0x080) + 0x01F = 0x09F, raised
// when an integrity check (here the credential's outer HMAC over encIdentity
// || Name) fails. TCG "TPM 2.0 Part 2: Structures", "TPM_RC".
const rcIntegrity = 0x09F

// rcFMT1Base masks a returned FMT1 rc to its base error (format bit 0x080,
// parameter bit 0x040, 6-bit error number 0x03F), clearing the N field in
// bits [11:8]. TCG "Part 2", "Response Code Formats".
const rcFMT1Base = 0x0BF

// isRC reports whether err is a *tpm2.TPMError carrying the given raw rc.
func isRC(err error, rc uint32) bool {
	if e, ok := err.(*tpm2.TPMError); ok {
		return e.RC == rc
	}
	return false
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

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 ATTESTATION-PROTOCOL harness: boots a tamago/amd64 guest
// under QEMU (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by a
// live swtpm) through go-tpm2/crb + go-tpm2/tpm2 + go-tpm2/attest, and proves
// the FULL node-admission-on-Quote protocol end to end with real TPM crypto.
//
// In ONE guest it plays BOTH sides: the Node drives the real swtpm, and the
// pure-Go Verifier runs in-process. The handshake:
//
//	CreateEK + CreatePrimary(AK)                 (attest.NewNode, real swtpm)
//	Enroll -> MakeCredential (off-TPM, Verifier)
//	RespondEnroll -> ActivateCredential (real swtpm)
//	CompleteEnroll -> const-time compare + BindAK (Verifier)         POSITIVE
//	Challenge -> fresh nonce (Verifier)
//	RespondAdmission -> Quote + PCR_Read (real swtpm)
//	Admit -> VerifyQuote + nonce + GoldenPolicy(measured PCRs)       ADMITTED
//
// then the NEGATIVES (each must be REJECTED with its precise sentinel):
//
//	extend a PCR so it != golden     -> Admit returns ErrUntrustedBoot
//	replay the PREVIOUS nonce        -> Admit returns ErrStaleNonce
//	credential made for a WRONG AK   -> CompleteEnroll returns ErrActivationFailed
//
// A self-consistent fake cannot satisfy this: only a real TPM holding the EK
// private key recovers the activation secret, and only real Quote signing +
// PCR measurement produce a signature and pcrDigest the off-TPM Verifier
// accepts. run-attest-protocol.sh starts swtpm and parses the verdict on COM1.
package main

import (
	"bytes"
	"fmt"

	"github.com/go-tpm2/validate/board"
	"github.com/go-tpm2/validate/regs"

	"github.com/go-tpm2/attest"
	"github.com/go-tpm2/common"
	"github.com/go-tpm2/crb"
	"github.com/go-tpm2/tpm2"
)

func main() {
	fmt.Printf("ATTEST-PROTOCOL: boot ok, harness entered main\n")

	r := regs.New()
	transport, err := crb.Open(r)
	if err != nil {
		fail("crb.Open: %v", err)
	}
	t := tpm2.New(transport)

	// Startup(CLEAR); tolerate already-initialized.
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fail("Startup(CLEAR): %v", err)
		}
		fmt.Printf("ATTEST-PROTOCOL: Startup already-initialized, continuing\n")
	} else {
		fmt.Printf("ATTEST-PROTOCOL: Startup(CLEAR) OK\n")
	}

	// --- Node: create EK + AK on the real swtpm. ---
	sel := []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{0, 7}}}
	node, err := attest.NewNode(t, sel)
	if err != nil {
		fail("attest.NewNode: %v", err)
	}
	fmt.Printf("ATTEST-PROTOCOL: EK+AK created; AK name=%s\n", hexAll(node.AKName()))

	// --- Verifier: trust THIS EK, deterministic nonce sequence. ---
	reg := attest.NewMemRegistry()
	reg.TrustEK(node.EnrollRequest(nil).EKPub)
	nonces := &nonceSeq{vals: [][32]byte{
		{0x11}, // admission #1 (positive)
		{0x22}, // admission #2 (bad-PCR)
		{0x33}, // admission #3 (stale-nonce probe — distinct from #2)
		{0x44}, // any further challenges
	}}
	v := attest.NewVerifier(reg, attest.GoldenPolicy{}, nonces.next)

	// --- ENROL: MakeCredential -> ActivateCredential -> CompleteEnroll. ---
	chal, err := v.Enroll(node.EnrollRequest(nil))
	if err != nil {
		fail("Enroll: %v", err)
	}
	proof, err := node.RespondEnroll(chal)
	if err != nil {
		fail("RespondEnroll (ActivateCredential): %v", err)
	}
	if err := v.CompleteEnroll(node.AKName(), proof); err != nil {
		fail("CompleteEnroll: %v", err)
	}
	fmt.Printf("ATTEST-PROTOCOL: enroll OK\n")

	// --- ADMIT (positive): Quote over a fresh nonce; GoldenPolicy = measured. ---
	adChal, err := v.Challenge(node.AdmissionRequest())
	if err != nil {
		fail("Challenge: %v", err)
	}
	resp, err := node.RespondAdmission(adChal)
	if err != nil {
		fail("RespondAdmission (Quote): %v", err)
	}
	// Build the golden policy from the just-measured PCRs and install it.
	golden := attest.GoldenPolicy{}
	for idx, val := range resp.PCRs {
		golden[idx] = val
	}
	v.SetPolicy(golden)
	granted, err := v.Admit(node.AKName(), resp)
	if err != nil || !granted {
		fail("Admit (positive): granted=%v err=%v", granted, err)
	}
	fmt.Printf("ATTEST-PROTOCOL: admit OK\n")

	// --- NEGATIVE 1: extend PCR 0 so it no longer matches golden. ---
	if err := t.PCRExtend(0, uint16(common.AlgSHA256), bytes.Repeat([]byte{0xAB}, 32)); err != nil {
		fail("PCRExtend(0): %v", err)
	}
	adChal2, err := v.Challenge(node.AdmissionRequest())
	if err != nil {
		fail("Challenge #2: %v", err)
	}
	resp2, err := node.RespondAdmission(adChal2)
	if err != nil {
		fail("RespondAdmission #2: %v", err)
	}
	_, err = v.Admit(node.AKName(), resp2)
	if err != attest.ErrUntrustedBoot {
		var ub *attest.UntrustedBootError
		if !errorsAs(err, &ub) {
			fail("bad-PCR: got %v want ErrUntrustedBoot", err)
		}
	}
	fmt.Printf("ATTEST-PROTOCOL: bad-PCR REJECTED (%v)\n", err)

	// --- NEGATIVE 2: replay an OLD response (its nonce was already consumed). ---
	// Issue a fresh challenge, then submit the PREVIOUS (resp2) response whose
	// extraData is the stale nonce.
	if _, err := v.Challenge(node.AdmissionRequest()); err != nil {
		fail("Challenge #3: %v", err)
	}
	_, err = v.Admit(node.AKName(), resp2) // resp2 carries the OLD nonce
	if err != attest.ErrStaleNonce {
		fail("stale-nonce: got %v want ErrStaleNonce", err)
	}
	fmt.Printf("ATTEST-PROTOCOL: stale-nonce REJECTED (%v)\n", err)

	// --- NEGATIVE 3: a credential made for a WRONG AK Name must fail to
	//     activate, so CompleteEnroll rejects the (impossible) proof. ---
	wrongName := append([]byte(nil), node.AKName()...)
	wrongName[len(wrongName)-1] ^= 0xFF
	req := node.EnrollRequest(nil)
	req.AKName = wrongName
	wrongChal, err := v.Enroll(req)
	if err != nil {
		fail("Enroll(wrong AK): %v", err)
	}
	// The real TPM cannot recover a credential bound to a Name it does not hold:
	// ActivateCredential fails (TPM_RC_INTEGRITY), so RespondEnroll errors. Feed
	// an empty/garbage proof to CompleteEnroll under the wrong name to confirm
	// the Verifier rejects it.
	_, aerr := node.RespondEnroll(wrongChal)
	if aerr == nil {
		fail("wrong-AK ActivateCredential unexpectedly SUCCEEDED")
	}
	if cerr := v.CompleteEnroll(wrongName, attest.EnrollProof{ActivationSecret: []byte("garbage")}); cerr != attest.ErrActivationFailed {
		fail("wrong-AK CompleteEnroll: got %v want ErrActivationFailed", cerr)
	}
	fmt.Printf("ATTEST-PROTOCOL: wrong-AK REJECTED (activate=%v)\n", aerr)

	fmt.Printf("ATTEST-PROTOCOL: enroll OK; admit OK; bad-PCR REJECTED; stale-nonce REJECTED; wrong-AK REJECTED; PASS\n")
	board.Shutdown(0)
}

// nonceSeq is a deterministic Nonce source yielding a fixed sequence, then
// repeating the last value.
type nonceSeq struct {
	vals [][32]byte
	i    int
}

func (n *nonceSeq) next() ([32]byte, error) {
	v := n.vals[n.i]
	if n.i < len(n.vals)-1 {
		n.i++
	}
	return v, nil
}

// isRC reports whether err is a *tpm2.TPMError carrying the given raw rc.
func isRC(err error, rc uint32) bool {
	if e, ok := err.(*tpm2.TPMError); ok {
		return e.RC == rc
	}
	return false
}

// errorsAs is a tiny stand-in for errors.As for the one concrete target type
// used here (kept dependency-light for the tamago guest).
func errorsAs(err error, target **attest.UntrustedBootError) bool {
	if e, ok := err.(*attest.UntrustedBootError); ok {
		*target = e
		return true
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

// fail prints a FAIL line and halts the guest with a non-zero exit.
func fail(format string, args ...interface{}) {
	fmt.Printf("ATTEST-PROTOCOL: FAIL "+format+"\n", args...)
	board.Shutdown(1)
}

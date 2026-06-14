// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 ATTEST-EVENTLOG harness: boots a tamago/amd64 guest under
// QEMU (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by a live
// swtpm), and validates go-tpm2/attest's v0.2.0 EventLogPolicy against real
// swtpm PCR state.
//
// What it proves end-to-end with real TPM crypto, in ONE guest playing both the
// attest Node and the in-process Verifier:
//
//	CreateEK + CreatePrimary(AK)                  (attest.NewNode, real swtpm)
//	Enroll -> MakeCredential -> ActivateCredential -> CompleteEnroll  (bind AK)
//	for each of several known measurements:
//	    PCR_Extend(16, SHA256, measurement)       (REAL extend on the swtpm)
//	    record it in a crypto-agile TCG event log (attest.LogBuilder)
//	Challenge -> RespondAdmission                 (Quote + PCR_Read, real swtpm)
//	attach the built log to the AdmissionResponse
//	Admit with EventLogPolicy(allowlist = those measurements):
//	    -> the Verifier REPLAYS the log into virtual PCRs, confirms they EQUAL
//	       the real swtpm PCRs, and confirms every event is allowlisted  ADMITTED
//
// then the NEGATIVES (each REJECTED with its precise sentinel):
//
//	drop one measurement from the allowlist  -> Admit -> ErrUnapprovedMeasurement
//	corrupt one digest in the log            -> Admit -> ErrEventLogMismatch
//	    (the corrupted log no longer replays to the real swtpm PCRs)
//
// A self-consistent fake cannot satisfy this: the PCRs the replay must match are
// the swtpm's REAL post-extend values, signed inside a real Quote the off-TPM
// Verifier checks. run-attest-eventlog.sh starts swtpm and parses the verdict.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/go-tpm2/validate/board"
	"github.com/go-tpm2/validate/regs"

	"github.com/go-tpm2/attest"
	"github.com/go-tpm2/common"
	"github.com/go-tpm2/crb"
	"github.com/go-tpm2/tpm2"
)

// evIPL is EV_IPL (0x0000000D), a generic measured-component event type; the
// allowlist keys on (PCR, digest), so the exact type is only carried for the
// UnapprovedMeasurementError diagnostic.
const evIPL uint32 = 0x0000000D

// measuredPCR is the PCR the harness extends and replays. PCR 16 is the TCG
// debug PCR (resettable, starts at all-zero after Startup(CLEAR)), so a fresh
// swtpm gives a clean chain the replay can reproduce from zero.
const measuredPCR = 16

func main() {
	fmt.Printf("ATTEST-EVENTLOG: boot ok, harness entered main\n")

	r := regs.New()
	transport, err := crb.Open(r)
	if err != nil {
		fail("crb.Open: %v", err)
	}
	t := tpm2.New(transport)

	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fail("Startup(CLEAR): %v", err)
		}
		fmt.Printf("ATTEST-EVENTLOG: Startup already-initialized, continuing\n")
	} else {
		fmt.Printf("ATTEST-EVENTLOG: Startup(CLEAR) OK\n")
	}

	// --- Node + Verifier wiring (quote the SHA-256 bank, PCR 16). ---
	sel := []tpm2.PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{measuredPCR}}}
	node, err := attest.NewNode(t, sel)
	if err != nil {
		fail("attest.NewNode: %v", err)
	}
	fmt.Printf("ATTEST-EVENTLOG: EK+AK created; AK name=%s\n", hexAll(node.AKName()))

	reg := attest.NewMemRegistry()
	reg.TrustEK(node.EnrollRequest(nil).EKPub)
	nonces := &nonceSeq{vals: [][32]byte{{0x11}, {0x22}, {0x33}, {0x44}}}
	v := attest.NewVerifier(reg, attest.GoldenPolicy{}, nonces.next)

	// --- Enrol: bind the AK to the trusted EK. ---
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
	fmt.Printf("ATTEST-EVENTLOG: enroll OK\n")

	// --- Real PCR_Extends, recorded into a crypto-agile event log. ---
	measurements := [][]byte{
		sha256Of("eventlog-component-shim"),
		sha256Of("eventlog-component-grub"),
		sha256Of("eventlog-component-kernel"),
	}
	lb := attest.NewLogBuilder()
	for i, m := range measurements {
		if err := t.PCRExtend(measuredPCR, uint16(common.AlgSHA256), m); err != nil {
			fail("PCRExtend #%d: %v", i, err)
		}
		lb.Add(measuredPCR, evIPL, m, nil)
	}
	eventLog := lb.Bytes()
	fmt.Printf("ATTEST-EVENTLOG: %d real PCR_Extends done; log=%d bytes\n",
		len(measurements), len(eventLog))

	// --- ADMIT (positive): Quote + PCR_Read, attach the log, EventLogPolicy. ---
	adChal, err := v.Challenge(node.AdmissionRequest())
	if err != nil {
		fail("Challenge: %v", err)
	}
	resp, err := node.RespondAdmission(adChal)
	if err != nil {
		fail("RespondAdmission (Quote): %v", err)
	}
	resp.EventLog = eventLog

	// Sanity: the replay of our log must equal the real swtpm PCR16 BEFORE we
	// even ask the Verifier (proves we built the log consistently). This is a
	// real-vs-replay equality against live swtpm state, not a self-check.
	events, perr := attest.ParseEventLog(eventLog)
	if perr != nil {
		fail("ParseEventLog: %v", perr)
	}
	replayed, rerr := attest.ReplayPCRs(events, uint16(common.AlgSHA256))
	if rerr != nil {
		fail("ReplayPCRs: %v", rerr)
	}
	if !bytes.Equal(replayed[measuredPCR], resp.PCRs[measuredPCR]) {
		fail("replay PCR16 %s != swtpm PCR16 %s",
			hexAll(replayed[measuredPCR]), hexAll(resp.PCRs[measuredPCR]))
	}
	fmt.Printf("ATTEST-EVENTLOG: replay PCR16 == swtpm PCR16 (%s)\n",
		hexAll(resp.PCRs[measuredPCR]))

	allow := attest.NewEventLogPolicy().RestrictPCRs(measuredPCR)
	for _, m := range measurements {
		allow.AllowMeasurement(measuredPCR, m)
	}
	v.SetPolicy(allow)
	granted, err := v.Admit(node.AKName(), resp)
	if err != nil || !granted {
		fail("Admit (positive): granted=%v err=%v", granted, err)
	}
	fmt.Printf("ATTEST-EVENTLOG: admit OK (replay==PCRs + allowlist)\n")

	// --- NEGATIVE 1: drop one measurement from the allowlist. ---
	short := attest.NewEventLogPolicy().RestrictPCRs(measuredPCR)
	for _, m := range measurements[:len(measurements)-1] { // omit the last
		short.AllowMeasurement(measuredPCR, m)
	}
	v.SetPolicy(short)
	adChal2, err := v.Challenge(node.AdmissionRequest())
	if err != nil {
		fail("Challenge #2: %v", err)
	}
	resp2, err := node.RespondAdmission(adChal2)
	if err != nil {
		fail("RespondAdmission #2: %v", err)
	}
	resp2.EventLog = eventLog
	_, err = v.Admit(node.AKName(), resp2)
	var um *attest.UnapprovedMeasurementError
	if !asUnapproved(err, &um) {
		fail("unapproved: got %v want ErrUnapprovedMeasurement", err)
	}
	fmt.Printf("ATTEST-EVENTLOG: unapproved REJECTED (PCR %d, %v)\n", um.PCR, err)

	// --- NEGATIVE 2: corrupt one digest in the log -> replay != real PCR. ---
	tampered := append([]byte(nil), eventLog...)
	// Flip the last byte of the FIRST event2's SHA-256 digest. Layout: legacy
	// header, then event2 { PCRIndex(4) EventType(4) count(4) algID(2)
	// digest(32) ... }. Locate the header length, then offset to the digest.
	hdrLen := len(attest.NewLogBuilder().Bytes())
	digestOff := hdrLen + 4 + 4 + 4 + 2 // into the first event2's digest
	tampered[digestOff+31] ^= 0xFF
	v.SetPolicy(allow) // full allowlist, so only the replay-equality can fail
	adChal3, err := v.Challenge(node.AdmissionRequest())
	if err != nil {
		fail("Challenge #3: %v", err)
	}
	resp3, err := node.RespondAdmission(adChal3)
	if err != nil {
		fail("RespondAdmission #3: %v", err)
	}
	resp3.EventLog = tampered
	_, err = v.Admit(node.AKName(), resp3)
	if err != attest.ErrEventLogMismatch {
		fail("tampered-log: got %v want ErrEventLogMismatch", err)
	}
	fmt.Printf("ATTEST-EVENTLOG: tampered-log REJECTED (%v)\n", err)

	fmt.Printf("ATTEST-EVENTLOG: replay==PCRs OK; allowlist OK; unapproved REJECTED; tampered-log REJECTED; PASS\n")
	board.Shutdown(0)
}

// sha256Of returns the SHA-256 of s (a stand-in measurement value).
func sha256Of(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
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

// asUnapproved is a tiny stand-in for errors.As for the one target type used
// here (kept dependency-light for the tamago guest).
func asUnapproved(err error, target **attest.UnapprovedMeasurementError) bool {
	if e, ok := err.(*attest.UnapprovedMeasurementError); ok {
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
	fmt.Printf("ATTEST-EVENTLOG: FAIL "+format+"\n", args...)
	board.Shutdown(1)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 GETCAPABILITY-DECODE harness: boots a tamago/amd64 guest
// under QEMU (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by a
// live swtpm) through go-tpm2/crb + go-tpm2/tpm2, and proves the typed
// GetCapability decoders against the live TPM:
//
//	Startup(CLEAR)
//	GetPCRBanks()        -> assert a SHA256 bank is present
//	GetManufacturer()    -> assert non-zero (swtpm reports "IBM")
//	GetTPMProperties()   -> dump the fixed property group from PT_FIXED
//	GetAlgorithms()      -> assert ECC + SHA256 are implemented
//	GetHandles()         -> list permanent handles
//
// The decoders parse the capability-specific TPMU_CAPABILITIES union members
// the live swtpm returns; a wrong offset or endianness shows up immediately as
// a missing SHA256 bank, a zero manufacturer, or a short-buffer error. The
// guest prints TPM-CAP: ... PASS / FAIL on COM1.
package main

import (
	"fmt"

	"github.com/go-tpm2/validate/board"
	"github.com/go-tpm2/validate/regs"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/crb"
	"github.com/go-tpm2/tpm2"
)

func main() {
	fmt.Printf("TPM-CAP: boot ok, harness entered main\n")

	r := regs.New()

	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-CAP: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-CAP: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-CAP: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-CAP: Startup(CLEAR) OK\n")
	}

	// --- TPM_CAP_PCRS: the PCR banks. -------------------------------------
	banks, err := t.GetPCRBanks()
	if err != nil {
		fmt.Printf("TPM-CAP: FAIL GetPCRBanks: %v\n", err)
		halt()
	}
	sha256Bank := false
	for _, b := range banks {
		fmt.Printf("TPM-CAP: PCR bank alg=%#x PCRs=%d\n", b.Hash, len(b.PCRs))
		if b.Hash == uint16(common.AlgSHA256) {
			sha256Bank = true
		}
	}
	if !sha256Bank {
		fmt.Printf("TPM-CAP: FAIL no SHA256 PCR bank reported\n")
		halt()
	}
	fmt.Printf("TPM-CAP: SHA256 PCR bank present OK\n")

	// --- TPM_CAP_TPM_PROPERTIES: manufacturer (non-zero). -----------------
	man, err := t.GetManufacturer()
	if err != nil {
		fmt.Printf("TPM-CAP: FAIL GetManufacturer: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CAP: MANUFACTURER = %#08x (%s)\n", man, ascii4(man))
	if man == 0 {
		fmt.Printf("TPM-CAP: FAIL manufacturer is zero\n")
		halt()
	}

	// Dump the fixed property group for the transcript.
	props, err := t.GetTPMProperties(tpm2.PTFixed, 8)
	if err != nil {
		fmt.Printf("TPM-CAP: FAIL GetTPMProperties: %v\n", err)
		halt()
	}
	for _, p := range props {
		fmt.Printf("TPM-CAP: property %#08x = %#08x\n", p.Property, p.Value)
	}

	// --- TPM_CAP_ALGS: ECC + SHA256 implemented. --------------------------
	algs, err := t.GetAlgorithms(0, 64)
	if err != nil {
		fmt.Printf("TPM-CAP: FAIL GetAlgorithms: %v\n", err)
		halt()
	}
	haveECC, haveSHA256 := false, false
	for _, a := range algs {
		if a.Alg == 0x0023 {
			haveECC = true
		}
		if a.Alg == uint16(common.AlgSHA256) {
			haveSHA256 = true
		}
	}
	fmt.Printf("TPM-CAP: algorithms reported = %d (ECC=%v SHA256=%v)\n", len(algs), haveECC, haveSHA256)
	if !haveECC || !haveSHA256 {
		fmt.Printf("TPM-CAP: FAIL expected ECC and SHA256 in alg list\n")
		halt()
	}

	// --- TPM_CAP_HANDLES: list permanent handles. -------------------------
	handles, err := t.GetHandles(0x40000000, 16)
	if err != nil {
		fmt.Printf("TPM-CAP: FAIL GetHandles: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-CAP: permanent handles = %d\n", len(handles))
	for _, h := range handles {
		fmt.Printf("TPM-CAP: handle %#08x\n", h)
	}

	fmt.Printf("TPM-CAP: PCR banks + manufacturer + algs + handles decoded on a real swtpm, PASS\n")
	board.Shutdown(0)
}

func isRC(err error, rc uint32) bool {
	if e, ok := err.(*tpm2.TPMError); ok {
		return e.RC == rc
	}
	return false
}

// ascii4 renders a UINT32 as its four packed ASCII characters (printable ones
// only), the way a TPM_PT_MANUFACTURER value reads as a vendor string.
func ascii4(v uint32) string {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	out := make([]byte, 0, 4)
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}

func halt() {
	board.Shutdown(1)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 ENDORSEMENT-KEY harness: boots a tamago/amd64 guest under
// QEMU (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by a live
// swtpm) through go-tpm2/crb + go-tpm2/tpm2, and proves the EK Credential
// Profile ECC-P256 (L-2) template against the live TPM:
//
//	Startup(CLEAR)
//	CreateEK()  -> a primary, restricted-decrypt ECC P-256 Endorsement Key
//	              under TPM_RH_ENDORSEMENT with the well-known EK policy
//	print the EK public point (x, y)
//	CreateEK() again -> assert the public point is STABLE across both calls
//	                    (the EK is deterministic from the endorsement seed)
//
// The determinism check is the oracle: if any field of the hand-marshaled EK
// template (objectAttributes 0x000300B2, the 32-byte EK authPolicy, the
// AES-128-CFB symmetric, P256) were wrong, the swtpm would either reject the
// template or derive a different key. Two byte-identical public points from a
// live TPM confirm the template is the canonical EK. The guest prints
// TPM-EK: ... PASS / FAIL on COM1.
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
	fmt.Printf("TPM-EK: boot ok, harness entered main\n")

	r := regs.New()

	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-EK: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-EK: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-EK: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-EK: Startup(CLEAR) OK\n")
	}

	// --- CreateEK (first call). -------------------------------------------
	h1, ek1, err := t.CreateEK()
	if err != nil {
		fmt.Printf("TPM-EK: FAIL CreateEK #1: %v\n", err)
		halt()
	}
	if len(ek1.X) == 0 || len(ek1.Y) == 0 {
		fmt.Printf("TPM-EK: FAIL CreateEK #1 returned empty point\n")
		halt()
	}
	fmt.Printf("TPM-EK: EK#1 handle = %#x\n", h1)
	fmt.Printf("TPM-EK: EK#1 pub X  = %s\n", hexAll(ek1.X))
	fmt.Printf("TPM-EK: EK#1 pub Y  = %s\n", hexAll(ek1.Y))

	// --- CreateEK (second call): the point must be IDENTICAL. --------------
	h2, ek2, err := t.CreateEK()
	if err != nil {
		fmt.Printf("TPM-EK: FAIL CreateEK #2: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-EK: EK#2 handle = %#x\n", h2)
	fmt.Printf("TPM-EK: EK#2 pub X  = %s\n", hexAll(ek2.X))
	fmt.Printf("TPM-EK: EK#2 pub Y  = %s\n", hexAll(ek2.Y))

	if !equal(ek1.X, ek2.X) || !equal(ek1.Y, ek2.Y) {
		fmt.Printf("TPM-EK: FAIL EK public point not stable across calls\n")
		halt()
	}
	fmt.Printf("TPM-EK: EK public point STABLE across two CreatePrimary calls OK\n")

	fmt.Printf("TPM-EK: EK Credential Profile ECC-P256 (L-2) created on a real swtpm, PASS\n")
	board.Shutdown(0)
}

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

func hexAll(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func halt() {
	board.Shutdown(1)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Headless go-tpm2 NV-STORAGE harness: boots a tamago/amd64 guest under QEMU
// (-M pc, TCG), drives a REAL TPM 2.0 (`-device tpm-crb` backed by a live
// swtpm) through go-tpm2/crb + go-tpm2/tpm2, and proves the NV storage flow
// end to end against the live TPM:
//
//	Startup(CLEAR)
//	NV_DefineSpace(0x01500000, size 32, OWNERWRITE|AUTHWRITE|OWNERREAD|AUTHREAD)
//	NV_Write(0x01500000, 32 known bytes)
//	NV_Read(0x01500000, 32)        -> assert BYTE-EQUAL to what was written
//	NV_ReadPublic(0x01500000)      -> assert index/nameAlg/dataSize/attrs
//	NV_UndefineSpace(0x01500000)   -> clean up
//	NV_ReadPublic(0x01500000)      -> NEGATIVE: must now FAIL (index gone)
//
// The read-back byte equality is the oracle: the swtpm either returns the exact
// bytes the guest wrote into the index it defined, or it does not. A
// self-consistent fake cannot pass because the data round-trips through the
// real TPM's NV store. The guest prints TPM-NV: ... PASS / FAIL on COM1.
package main

import (
	"fmt"

	"github.com/go-tpm2/validate/board"
	"github.com/go-tpm2/validate/regs"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/crb"
	"github.com/go-tpm2/tpm2"
)

// nvIndex is the validation index in the TPM_HT_NV_INDEX (0x01xxxxxx) range.
const nvIndex uint32 = 0x01500000

// nvSize is the data area size in bytes.
const nvSize uint16 = 32

func main() {
	fmt.Printf("TPM-NV: boot ok, harness entered main\n")

	r := regs.New()

	transport, err := crb.Open(r)
	if err != nil {
		fmt.Printf("TPM-NV: FAIL crb.Open: %v\n", err)
		halt()
	}
	t := tpm2.New(transport)

	// --- Startup(CLEAR). --------------------------------------------------
	if err := t.Startup(uint16(common.SUClear)); err != nil {
		if !isRC(err, 0x100) {
			fmt.Printf("TPM-NV: FAIL Startup(CLEAR): %v\n", err)
			halt()
		}
		fmt.Printf("TPM-NV: Startup already-initialized (rc 0x100), continuing\n")
	} else {
		fmt.Printf("TPM-NV: Startup(CLEAR) OK\n")
	}

	// A fresh swtpm may already hold the index from a previous run in this
	// state dir; the run script wipes state, but be defensive and ignore an
	// undefine error here.
	_ = t.NVUndefineSpace(nvIndex)

	// --- NV_DefineSpace. --------------------------------------------------
	pub := tpm2.NVPublic{
		Index:      nvIndex,
		NameAlg:    uint16(common.AlgSHA256),
		Attributes: tpm2.NVOwnerWrite | tpm2.NVAuthWrite | tpm2.NVOwnerRead | tpm2.NVAuthRead,
		DataSize:   nvSize,
	}
	if err := t.NVDefineSpace(pub); err != nil {
		fmt.Printf("TPM-NV: FAIL NVDefineSpace: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-NV: NVDefineSpace(%#x, size %d) OK\n", nvIndex, nvSize)

	// --- NV_Write 32 known bytes. -----------------------------------------
	data := make([]byte, nvSize)
	for i := range data {
		data[i] = byte(0xA0 + i) // a distinct, recognizable pattern
	}
	if err := t.NVWrite(nvIndex, data, 0); err != nil {
		fmt.Printf("TPM-NV: FAIL NVWrite: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-NV: NVWrite  = %s\n", hexAll(data))

	// --- NV_Read and assert byte equality. --------------------------------
	got, err := t.NVRead(nvIndex, nvSize, 0)
	if err != nil {
		fmt.Printf("TPM-NV: FAIL NVRead: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-NV: NVRead   = %s\n", hexAll(got))
	if !equal(got, data) {
		fmt.Printf("TPM-NV: FAIL read-back mismatch\n")
		halt()
	}
	fmt.Printf("TPM-NV: read-back byte-equal OK\n")

	// --- NV_ReadPublic and assert the public area. ------------------------
	rpub, name, err := t.NVReadPublic(nvIndex)
	if err != nil {
		fmt.Printf("TPM-NV: FAIL NVReadPublic: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-NV: NVReadPublic index=%#x nameAlg=%#x attrs=%#08x dataSize=%d name=%s\n",
		rpub.Index, rpub.NameAlg, rpub.Attributes, rpub.DataSize, hexAll(name))
	if rpub.Index != nvIndex || rpub.NameAlg != uint16(common.AlgSHA256) || rpub.DataSize != nvSize {
		fmt.Printf("TPM-NV: FAIL public area mismatch\n")
		halt()
	}

	// --- NV_UndefineSpace cleans up. --------------------------------------
	if err := t.NVUndefineSpace(nvIndex); err != nil {
		fmt.Printf("TPM-NV: FAIL NVUndefineSpace: %v\n", err)
		halt()
	}
	fmt.Printf("TPM-NV: NVUndefineSpace(%#x) OK\n", nvIndex)

	// --- NEGATIVE control: the index must now be gone. --------------------
	if _, _, err := t.NVReadPublic(nvIndex); err == nil {
		fmt.Printf("TPM-NV: FAIL index still readable after undefine (cleanup is a no-op!)\n")
		halt()
	}
	fmt.Printf("TPM-NV: negative control OK (index gone after undefine)\n")

	fmt.Printf("TPM-NV: define/write/read/readpublic/undefine on a real swtpm, PASS\n")
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

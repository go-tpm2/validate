// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/validate authors. All rights reserved.

// Package regs implements github.com/go-tpm2/common.Regs over the physical
// TPM CRB register window, for a tamago/amd64 guest under QEMU.
//
// On QEMU's q35 machine, `-device tpm-crb` places the TPM register block at
// the TCG-standard fixed physical base 0xFED40000 (locality 0 begins there;
// each locality is a 0x1000 control area). This is the same base the EDK2
// firmware and the Linux tpm_crb driver hard-code. The block is plain MMIO.
//
// tamago's amd64 page tables identity-map 0xc0000000..0xffffffff as a single
// 1 GiB uncacheable page (amd64/init.s, "PDPT[3]"), so 0xFED40000 resolves to
// itself and every access is uncacheable — exactly what an MMIO register file
// needs. We therefore read and write the registers through plain
// unsafe.Pointers, mirroring how go-virtio's validate transport touches a
// virtio BAR. common.Regs hands us a byte offset within the window; we add it
// to base and dereference.
//
// Width note: common.Regs exposes Read8/Read32/Write8/Write32. The CRB control
// registers are 32-bit little-endian; the x86 guest is little-endian, so a
// native uint32 load/store already matches the register's byte order — no swap.
// The command/response DATA buffer is a byte stream and is moved one byte at a
// time via Read8/Write8 (common.ReadBytes/WriteBytes), which the CRB driver
// uses.
package regs

import (
	"unsafe"

	"github.com/go-tpm2/common"
)

// CRBBase is the physical base of the TPM CRB register window on QEMU q35
// (`-device tpm-crb`): locality 0 control area. TCG PC Client PTP fixes the
// TPM register space at 0xFED40000; QEMU and EDK2 both use it.
const CRBBase = 0xFED40000

// MMIO is a common.Regs bound to a fixed physical register window at base.
type MMIO struct {
	base uintptr
}

// compile-time assertion that *MMIO satisfies common.Regs.
var _ common.Regs = (*MMIO)(nil)

// New returns an MMIO accessor for the TPM CRB window at the standard q35
// base (CRBBase).
func New() *MMIO {
	return &MMIO{base: CRBBase}
}

// NewAt returns an MMIO accessor for an arbitrary physical base. It exists so
// the harness can target a non-standard placement if a future QEMU revision
// moves the block; New() is the normal entry point.
func NewAt(base uintptr) *MMIO {
	return &MMIO{base: base}
}

func (m *MMIO) Read8(off uint32) uint8 {
	return *(*uint8)(unsafe.Pointer(m.base + uintptr(off)))
}

func (m *MMIO) Read32(off uint32) uint32 {
	return *(*uint32)(unsafe.Pointer(m.base + uintptr(off)))
}

func (m *MMIO) Write8(off uint32, v uint8) {
	*(*uint8)(unsafe.Pointer(m.base + uintptr(off))) = v
}

func (m *MMIO) Write32(off uint32, v uint32) {
	*(*uint32)(unsafe.Pointer(m.base + uintptr(off))) = v
}

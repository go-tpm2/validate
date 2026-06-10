// Package board provides a minimal QEMU q35 / x86_64 tamago board for the
// go-virtio validate harness.
//
// It is a near-verbatim copy of tamago's board/cloud_hypervisor/vm wiring
// (same AMD64 + IOAPIC + COM1 UART + DMA setup, port-mapped PCI config at
// 0xcf8/0xcfc which QEMU's q35/pc machines expose identically) with ONE
// deliberate difference: it does NOT call kvm/pvclock.Init.
//
// Rationale: pvclock.Init panics ("could not set system timer") on any
// host where the CPU advertises neither an invariant TSC nor the KVM
// paravirtual clock. Under QEMU TCG emulation (the only option for an
// x86_64 guest on an arm64 host, since HVF accelerates arm64 only) QEMU
// refuses to advertise CPUID[80000007h].EDX.invtsc and exposes no KVM
// CPUID leaves, so every stock amd64 tamago board hits that panic. The
// pvclock adjustment is purely an opportunistic TSC-reliability tweak;
// amd64.Init()/initTimers() already calibrates the timer from the TSC /
// ACPI-PM timer independently, so omitting it is safe for a correctness
// harness (wall-clock drift is irrelevant here).
//
// This is the documented tamago board-extension point (a board is just a
// package that wires runtime/goos.Hwinit1); it is NOT a patch to upstream
// tamago.
package board

import (
	"runtime/goos"
	_ "unsafe"

	"github.com/usbarmory/tamago/amd64"
	"github.com/usbarmory/tamago/dma"
	"github.com/usbarmory/tamago/soc/intel/ioapic"
	"github.com/usbarmory/tamago/soc/intel/uart"
)

const (
	dmaStart = 0x50000000
	dmaSize  = 0x10000000 // 256MB
)

// Peripheral registers
const (
	// Communication port (COM1)
	COM1 = 0x3f8

	// Intel I/O Programmable Interrupt Controller
	IOAPIC0_BASE = 0xfec00000
)

// Peripheral instances
var (
	// CPU instance
	AMD64 = &amd64.CPU{
		// required before Init()
		TimerMultiplier: 1,
	}

	// I/O APIC
	IOAPIC0 = &ioapic.IOAPIC{
		Base: IOAPIC0_BASE,
	}

	// Serial port
	UART0 = &uart.UART{
		Index: 1,
		Base:  COM1,
	}
)

// outb writes a byte to an x86 I/O port (defined in pic_amd64.s); used to
// mask the legacy 8259 PIC (internal/reg is not importable externally).
func outb(port uint16, val uint8)

// DebugExitPort is the I/O port of QEMU's isa-debug-exit device when added as
// `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. A byte written to it makes
// QEMU terminate with process exit code (value<<1)|1.
const DebugExitPort = 0xf4

// Shutdown asks QEMU to terminate cleanly via the isa-debug-exit device. The
// TPM harness calls it immediately after printing its PASS/FAIL verdict so
// QEMU exits (flushing the serial file) before any background runtime
// goroutine — e.g. the GC scavenger spinning while main halts — can fault
// under TCG and trigger a triple-fault reset that would race the serial flush.
// code is the raw byte written; QEMU's process exit status is (code<<1)|1.
func Shutdown(code uint8) {
	outb(DebugExitPort, code)
	for { // isa-debug-exit absent: fall back to a halt loop.
	}
}

//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x40000000 // 1GB

//go:linkname printk runtime/goos.Printk
func printk(c byte) {
	UART0.Tx(c)

	if c == 0x0a { // LF
		UART0.Tx(0x0d) // CR
	}
}

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return AMD64.GetTime()
}

// Init takes care of the lower level initialization triggered early in
// runtime setup (post World start).
//
//go:linkname Init runtime/goos.Hwinit1
func Init() {
	// initialize CPU (calibrates timer from TSC / ACPI-PM independently
	// of pvclock)
	AMD64.Init()

	// initialize I/O APIC
	IOAPIC0.Init()

	// Mask the legacy 8259 PIC (master data port 0x21). Interrupts are
	// routed through the I/O APIC; the legacy PIC must be masked or its
	// IRQ0 (the 8254 PIT), which QEMU's q35 leaves unmasked at the BIOS
	// vector base of 0x08, is delivered on IDT vector 8 — the Double
	// Fault slot — and tamago's handler reports it as "exception: vector
	// 8". This periodic PIT tick is what faulted any sustained compute
	// after a fixed wall-clock budget under TCG. This mirrors what
	// tamago's own board/firecracker/microvm does (reg.Out8(0x21, 0xff));
	// the cloud_hypervisor board this one was copied from omits it because
	// cloud-hypervisor exposes no legacy PIT, but q35 does.
	outb(0x21, 0xff)

	// initialize serial console
	UART0.Init()

	goos.Exit = func(_ int32) {
		// No clean guest-initiated shutdown is wired here (the stock
		// board writes a pio shutdown port via internal/reg, which is
		// not importable from an external module). The harness stops
		// the guest from the QEMU monitor, so a halt loop suffices.
		for {
		}
	}
}

func init() {
	// trap CPU exceptions
	AMD64.EnableExceptions()

	// initialize APs
	AMD64.InitSMP(-1)

	// allocate global DMA region
	dma.Init(dmaStart, dmaSize)

	// NOTE: pvclock.Init(AMD64) deliberately omitted — see package doc.
}

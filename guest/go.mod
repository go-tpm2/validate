// Guest harnesses: bare-metal programs built with the tamago toolchain
// (GOOS=tamago). This is the repository's only Go module, nested so a host
// `go mod tidy` at the repository root never sees the
// github.com/usbarmory/tamago imports, which only compile for tamago's GOOS,
// and never strips the go.sum entries the guest build needs
// (go-tpm2/validate#4). Maintain go.sum with a tamago toolchain:
// GOOS=tamago GOARCH=amd64 GOOSPKG=github.com/usbarmory/tamago go mod tidy
module github.com/go-tpm2/validate/guest

go 1.27.1

require (
	github.com/go-tpm2/attest v0.5.0
	github.com/go-tpm2/common v0.3.0
	github.com/go-tpm2/crb v0.3.0
	github.com/go-tpm2/tis v0.3.0
	github.com/go-tpm2/tpm2 v0.8.0
	github.com/usbarmory/tamago v1.27.4
)

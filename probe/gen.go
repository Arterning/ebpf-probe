package probe

// Build requirements (Ubuntu / Debian):
//
//   sudo apt-get install clang libbpf-dev linux-headers-$(uname -r)
//
// Generate (run once, then commit the generated *_bpf*.go files):
//
//   make generate
//
// The generated files embed compiled BPF bytecode and are NOT in .gitignore.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS" Flow ../bpf/flow.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS" Exec ../bpf/exec.c

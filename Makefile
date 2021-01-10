VMLINUX = vmlinux_$(shell uname -r).h

.PHONY: build
build: src/bpf/vmlinux.h
	cargo build

.PHONY: test
test:
	cargo test -- $(ARGS)

.PHONY: vmlinux
vmlinux: | src/bpf/vmlinux.h

src/bpf/$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/$(VMLINUX)

src/bpf/vmlinux.h: src/bpf/$(VMLINUX)
	ln -snfr src/bpf/$(VMLINUX) src/bpf/vmlinux.h

.PHONY: install
install:
	cargo install --path .

.PHONY: clean
clean:
	cargo clean


VMLINUX = vmlinux_$(shell uname -r).h

.PHONY: build
build: src/bpf/vmlinux.h
	cargo libbpf build
	cargo libbpf gen
	cargo build

.PHONY: test
test:
	# An ugly hack, since cargo test wants to overwrite our build files
	sudo cargo libbpf make --target-dir /tmp/bpfcontain-tests
	sudo cargo test --target-dir /tmp/bpfcontain-tests -- $(ARGS)

.PHONY: vmlinux
vmlinux: | src/bpf/vmlinux.h

src/bpf/$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/$(VMLINUX)

src/bpf/vmlinux.h: src/bpf/$(VMLINUX)
	ln -snfr src/bpf/$(VMLINUX) src/bpf/vmlinux.h

.PHONY: install
install:
	cargo install

.PHONY: clean
clean:
	cargo clean


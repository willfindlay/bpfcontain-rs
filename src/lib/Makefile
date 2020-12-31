INCLUDE_DIR = /usr/include/bpfcontain/
LIBRARY_DIR = /usr/lib/

.PHONY: all
all: | libbpfcontain.so

.PHONY: install
install: all
	sudo mkdir -p $(LIBRARY_DIR)
	sudo cp libbpfcontain.so $(LIBRARY_DIR)
	sudo ldconfig -n -v $(LIBRARY_DIR)
	sudo mkdir -p $(INCLUDE_DIR)
	sudo cp libbpfcontain.h $(INCLUDE_DIR)

libbpfcontain.o: libbpfcontain.c libbpfcontain.h
	gcc -fPIC -c libbpfcontain.c -o libbpfcontain.o

libbpfcontain.so: libbpfcontain.o
	gcc -shared libbpfcontain.o -o libbpfcontain.so

.PHONY: clean
clean:
	rm -f libbpfcontain.o libbpfcontain.so

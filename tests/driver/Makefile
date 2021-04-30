# SPDX-License-Identifier: GPL-2.0-or-later
#
# BPFContain - Container security with eBPF
# Copyright (C) 2020  William Findlay
#
# Apr. 30, 2021  William Findlay  Created this.

CC=gcc

CFLAGS=-Wall
LDFLAGS=

PNAME=driver
_OBJ=driver.o helpers.o
HEADER=helpers.h

OBJ = $(patsubst %,obj/%,$(_OBJ))

.PHONY: all
all: driver

driver: $(OBJ)
	$(CC) -o $(PNAME) $(OBJ) $(CFLAGS) $(LDFLAGS)

obj/%.o: %.c $(HEADER)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	@rm -f driver
	@rm -f obj/*.o

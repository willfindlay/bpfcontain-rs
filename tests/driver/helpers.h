// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Apr. 30, 2021  William Findlay  Created this.

#ifndef HELPERS_H
#define HELPERS_H

/*
 * print_usage() - print usage information to stderr and exit
 *
 * Return: Does not return. Program aborts with return code -1.
 */
void print_usage();

/*
 * print_error() - print an error message to stderr and exit
 *
 * Return: Does not return. Program aborts with return code -1.
 */
void print_error(char *s);

#endif /* ifndef HELPERS_H */

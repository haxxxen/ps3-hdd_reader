/*
* Copyright (c) 2011-2012 by ps3dev.net
* This file is released under the GPLv2.
*/

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#ifndef _UTIL_H_
#define _UTIL_H_
#include <windows.h>
// #include "types.h"
void _hexdump(FILE *fp, const char *name, unsigned int offset, unsigned char *buf, int len, BOOL print_addr);
unsigned char *_read_buffer(char *file, unsigned int *length);
void _write_buffer(char *file, unsigned char *buffer, unsigned int length);
void _es16_buffer(unsigned char *buf, unsigned int length);
int _print_buf(unsigned char *b, unsigned __int64 s, unsigned __int64 c);
__int64 seek_device(HANDLE device, __int64 byte_offset);
void print_commas(__int64 n, char *out);
#endif
#ifdef __cplusplus
}
#endif

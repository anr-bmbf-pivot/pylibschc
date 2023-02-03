# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

import typing

from cpython.bool cimport bool
from libc.stddef cimport size_t
from libc.stdint cimport uint8_t, uint32_t
from libc.stdlib cimport free, malloc
from libc.string cimport memcmp, memcpy, memset

from . cimport clibschc

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


cdef class BitArray:
    cdef clibschc.schc_bitarray_t _bit_array
    cdef size_t size

    def __cinit__(self, n: typing.Union[bytes, int]):
        self.size = len(n) if isinstance(n, bytes) else n
        self._bit_array.ptr = <uint8_t *>malloc(self.size)
        if self._bit_array.ptr is NULL:
            raise MemoryError("Unable to allocate bit array")
        if self.size > 0:
            if isinstance(n, bytes):
                memcpy(<void *>self._bit_array.ptr, <char *>n, self.size)
            else:
                memset(<void *>self._bit_array.ptr, 0, self.size)
        else:
            self._bit_array.ptr = NULL
        self._bit_array.offset = 0
        self._bit_array.padding = 0
        self._bit_array.len = self.size
        if isinstance(n, bytes):
            self._bit_array.bit_len = self.size * 8
        else:
            self._bit_array.bit_len = 0
    
    def __dealloc__(self):
        free(<void *>self._bit_array.ptr)

    cdef int _eq(self, BitArray other):
        return (
            self._bit_array.offset == other._bit_array.offset
            and self._bit_array.padding == other._bit_array.padding
            and self._bit_array.bit_len == other._bit_array.bit_len
            and self._bit_array.len == other._bit_array.len
            and (
                memcmp(
                    <void *>self._bit_array.ptr,
                    <void *>other._bit_array.ptr,
                    self._bit_array.len,
                ) == 0
            )
        )

    def __eq__(self, other: BitArray) -> bool:
        try:
            return bool(self._eq(other))
        except:
            raise

    def __ne__(self, other: BitArray) -> bool:
        return not (self == other)

    property buffer:
        def __get__(self) -> bytes:
            if self._bit_array.ptr is NULL:
                return b""
            return <bytes> self._bit_array.ptr[:self._bit_array.len]
        
        def __set__(self, buffer: bytes):
            if len(buffer) > self.size:
                self.size = len(buffer)
                free(<void *>self._bit_array.ptr)
                self._bit_array.ptr = <uint8_t *>malloc(self.size)
                if self._bit_array.ptr is NULL:
                    raise MemoryError("Unable to allocate bit array")
            elif len(buffer) == 0:
                self.size = 0
                free(<void *>self._bit_array.ptr)
                self._bit_array.ptr = NULL
            if self.size > 0:
                memcpy(
                    <void *>self._bit_array.ptr, <void *>(<char *>buffer), len(buffer)
                )
            self._bit_array.len = len(buffer)
            self._bit_array.bit_len = len(buffer) * 8

        def __del__(self):
            memset(<void *>self._bit_array.ptr, 0, self.size)
            self._bit_array.offset = 0
            self._bit_array.padding = 0
            self._bit_array.len = 0
            self._bit_array.bit_len = 0

    property offset:
        def __get__(self) -> int:
            return self._bit_array.offset
    
    property padding:
        def __get__(self) -> int:
            return self._bit_array.padding
    
    property length:
        def __get__(self) -> int:
            return self._bit_array.len
    
    property bit_length:
        def __get__(self) -> int:
            return self._bit_array.bit_len

    def get_bits(self, pos: int, length: int) -> int:
        if length > 32:
            raise ValueError("`length` must be lesser or equal to 32")
        if (<uint32_t>pos + <uint8_t>length) > self._bit_array.bit_len:
            raise ValueError(
                f"`pos + length` overflows buffer size ({self._bit_array.bit_len})"
            )
        return clibschc.get_bits(self._bit_array.ptr, pos, length)

    def copy_bits(self, pos: int, data: bytes, length: int) -> int:
        if (<uint32_t>pos + <uint8_t>length) > self._bit_array.bit_len:
            raise ValueError(
                f"`pos + length` overflows buffer size ({self._bit_array.bit_len})"
            )
        clibschc.clear_bits(self._bit_array.ptr, pos, length)
        return clibschc.copy_bits(
            self._bit_array.ptr, pos, <uint8_t *>(<char *>data), 0, length
        )

from libc.stdint cimport uint8_t, uint16_t, uint32_t

cdef extern from "libschc/bit_operations.h":
    uint32_t get_bits(const uint8_t A[], uint32_t pos, uint8_t len)
    void clear_bits(const uint8_t A[], uint32_t pos, uint8_t len)
    void copy_bits(
        uint8_t DST[], uint32_t dst_pos,
        const uint8_t SRC[], uint32_t src_pos,
        uint32_t len
    )
    unsigned BITS_TO_BYTES(unsigned x)

cdef extern from "libschc/schc.h":
    ctypedef struct schc_bitarray_t:
        uint8_t  *ptr
        uint32_t offset
        uint8_t padding
        uint16_t len
        uint32_t bit_len

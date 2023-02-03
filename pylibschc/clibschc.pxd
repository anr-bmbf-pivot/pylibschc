# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

from libc.stdint cimport uint8_t, uint16_t, uint32_t

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


cdef extern from "schc_config.h":
    const int BITMAP_SIZE_BYTES
    const int COAP_FIELDS
    const int DTAG_SIZE_BITS
    const int FCN_SIZE_BITS
    const int IP6_FIELDS
    const int MAX_FIELD_LENGTH
    const int MIC_SIZE_BYTES
    const int UDP_FIELDS
    const int MAX_MTU_LENGTH

cdef extern from "rules/rule_config.h":
    schc_device **devices
    int DEVICE_COUNT

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

    ctypedef enum COAPO_fields:
        COAP_IFMATCH
        COAP_URIHOST
        COAP_ETAG
        COAP_IFNOMATCH
        COAP_URIPORT
        COAP_LOCPATH
        COAP_URIPATH
        COAP_CONTENTF
        COAP_MAXAGE
        COAP_URIQUERY
        COAP_ACCEPT
        COAP_LOCQUERY
        COAP_PROXYURI
        COAP_PROXYSCH
        COAP_SIZE1
        COAP_NORESP
        COAP_OPTIONS_MAX

    ctypedef enum schc_header_fields:
        IP6_V
        IP6_TC
        IP6_FL
        IP6_LEN
        IP6_NH
        IP6_HL
        IP6_DEVPRE
        IP6_DEVIID
        IP6_APPPRE
        IP6_APPIID
        UDP_DEV
        UDP_APP
        UDP_LEN
        UDP_CHK
        COAP_V
        COAP_T
        COAP_TKL
        COAP_C
        COAP_MID
        COAP_TKN
        COAP_PAYLOAD

    ctypedef enum direction:
        UP
        DOWN
        BI

    ctypedef enum CDA:
        NOTSENT
        VALUESENT
        MAPPINGSENT
        LSB
        COMPLENGTH
        COMPCHK
        DEVIID
        APPIID

    ctypedef enum schc_layer_t:
        SCHC_IPV6
        SCHC_UDP
        SCHC_COAP

    ctypedef enum reliability_mode:
        ACK_ALWAYS
        ACK_ON_ERROR
        NO_ACK
        NOT_FRAGMENTED
        MAX_RELIABILITY_MODES

    cdef struct schc_field:
        uint16_t field
        uint8_t MO_param_length
        uint8_t field_length
        uint8_t field_pos
        direction dir
        unsigned char target_value[MAX_FIELD_LENGTH]
        uint8_t (*MO)(schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
        CDA action;

    cdef struct schc_layer_rule_t:
        uint8_t up
        uint8_t down
        uint8_t length
        schc_field content[0]

    cdef struct schc_ipv6_rule_t:
        uint8_t up
        uint8_t down
        uint8_t length
        schc_field content[IP6_FIELDS]

    cdef struct schc_udp_rule_t:
        uint8_t up
        uint8_t down
        uint8_t length
        schc_field content[UDP_FIELDS]

    cdef struct schc_coap_rule_t:
        uint8_t up
        uint8_t down
        uint8_t length
        schc_field content[COAP_FIELDS]

    cdef struct schc_compression_rule_t:
        uint32_t rule_id
        uint8_t rule_id_size_bits
        const schc_ipv6_rule_t *ipv6_rule
        const schc_udp_rule_t *udp_rule
        const schc_coap_rule_t *coap_rule

    cdef struct schc_fragmentation_rule_t:
        uint32_t rule_id
        uint8_t rule_id_size_bits
        reliability_mode mode
        direction dir
        uint8_t FCN_SIZE
        uint8_t MAX_WND_FCN
        uint8_t WINDOW_SIZE
        uint8_t DTAG_SIZE

    cdef struct schc_device:
        schc_device *next
        uint32_t device_id
        uint32_t uncomp_rule_id
        uint8_t uncomp_rule_id_size_bits
        uint8_t compression_rule_count
        const schc_compression_rule_t **compression_context;
        uint8_t fragmentation_rule_count
        const schc_fragmentation_rule_t **fragmentation_context

    uint8_t mo_equal(
        schc_field *target_field, unsigned char *field_value, uint16_t field_offset
    );
    uint8_t mo_ignore(
        schc_field *target_field, unsigned char *field_value, uint16_t field_offset
    );
    uint8_t mo_MSB(
        schc_field *target_field, unsigned char *field_value, uint16_t field_offset
    );
    uint8_t mo_matchmap(
        schc_field *target_field, unsigned char *field_value, uint16_t field_offset
    );

cdef extern from "rules.h":
    ctypedef schc_mo_op_t

    schc_compression_rule_t **schc_rules_create_compr_ctx(unsigned rule_count)
    schc_ipv6_rule_t *schc_rules_create_ipv6_rule()
    schc_udp_rule_t *schc_rules_create_udp_rule()
    schc_coap_rule_t *schc_rules_create_coap_rule()
    schc_fragmentation_rule_t **schc_rules_create_frag_ctx(unsigned rule_count)
    void schc_rules_free_compr_ctx(schc_compression_rule_t **ctx, unsigned rule_count)
    void schc_rules_free_frag_ctx(schc_fragmentation_rule_t **ctx, unsigned rule_count)

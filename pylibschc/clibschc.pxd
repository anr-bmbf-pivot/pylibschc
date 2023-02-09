# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

from cpython.object cimport PyObject
from libc.stdint cimport int8_t, uint8_t, uint16_t, uint32_t

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

cdef extern from "mo.h":
    ctypedef schc_mo_op_t

cdef extern from "rules.h":
    schc_compression_rule_t **schc_rules_create_compr_ctx(unsigned rule_count)
    schc_ipv6_rule_t *schc_rules_create_ipv6_rule()
    schc_udp_rule_t *schc_rules_create_udp_rule()
    schc_coap_rule_t *schc_rules_create_coap_rule()
    schc_fragmentation_rule_t **schc_rules_create_frag_ctx(unsigned rule_count)
    void schc_rules_free_compr_ctx(schc_compression_rule_t **ctx, unsigned rule_count)
    void schc_rules_free_frag_ctx(schc_fragmentation_rule_t **ctx, unsigned rule_count)

cdef extern from "pylogging.h":
    const int PYLOG_BUFFER_SIZE

    void pylog_init(PyObject *logger)
    int pylog_debug(const char *format, ...)

cdef extern from "libschc/compressor.h":
    uint8_t schc_compressor_init()
    schc_compression_rule_t *schc_compress(
        uint8_t *data,
        uint16_t total_length,
        schc_bitarray_t *buf,
        uint32_t device_id,
        direction dir
    )
    uint16_t schc_decompress(
        schc_bitarray_t *bit_arr,
        uint8_t *buf,
        uint32_t device_id,
        uint16_t total_length,
        direction dir
    )

cdef extern from "libschc/fragmenter.h":
    const int SCHC_FRAG_INPUT
    const int SCHC_ACK_INPUT
    const int SCHC_SUCCESS
    const int SCHC_END
    const int SCHC_FAILURE
    const int SCHC_NO_FRAGMENTATION

    ctypedef enum tx_state:
        INIT_TX = 0
        SEND = 1
        RESEND = 2
        WAIT_BITMAP = 3
        END_TX = 4
        ERR = 5

    ctypedef enum rx_state:
        RECV_WINDOW = 0
        WAIT_NEXT_WINDOW = 1
        WAIT_MISSING_FRAG = 2
        WAIT_END = 3
        END_RX = 4
        ABORT = 5

    ctypedef struct schc_mbuf_t:
        pass

    ctypedef struct schc_fragmentation_ack_t:
        pass

    ctypedef struct schc_fragmentation_t

    ctypedef struct schc_fragmentation_t:
        schc_fragmentation_t *next
        void (*free_conn_cb)(schc_fragmentation_t *conn)
        uint32_t device_id
        schc_bitarray_t *bit_arr
        uint8_t *tail_ptr
        uint16_t mtu
        uint32_t dc
        uint8_t mic[MIC_SIZE_BYTES]
        uint8_t fc
        uint8_t window
        uint8_t window_cnt
        uint8_t dtag
        uint8_t frag_cnt
        uint8_t bitmap[BITMAP_SIZE_BYTES]
        uint8_t attempts
        tx_state TX_STATE
        rx_state RX_STATE
        uint8_t (*send)(uint8_t *data, uint16_t length, uint32_t device_id)
        void (*post_timer_task)(
            schc_fragmentation_t *conn,
            void (*timer_task)(void *arg),
            uint32_t time_ms,
            void *arg
        )
        void (*end_rx)(schc_fragmentation_t *conn)
        void (*end_tx)(schc_fragmentation_t *conn)
        void (*remove_timer_entry)(schc_fragmentation_t *conn)
        void *timer_ctx
        uint8_t timer_flag
        uint8_t input
        schc_fragmentation_ack_t ack
        schc_mbuf_t *head
        schc_fragmentation_rule_t *fragmentation_rule
        uint8_t rule_id[4]

    int8_t schc_fragmenter_init(schc_fragmentation_t* tx_conn);
    int8_t schc_fragment(schc_fragmentation_t *tx_conn)
    int8_t schc_reassemble(schc_fragmentation_t *rx_conn)
    void schc_reset(schc_fragmentation_t *conn)
    schc_fragmentation_t *schc_input(
        uint8_t *data,
        uint16_t len,
        schc_fragmentation_t * rx_conn,
        uint32_t device_id
    )

    schc_fragmentation_rule_t *get_fragmentation_rule_by_reliability_mode(
        reliability_mode mode,
		uint32_t device_id
    )

    uint16_t get_mbuf_len(schc_fragmentation_t *conn)
    void mbuf_copy(schc_fragmentation_t *conn, uint8_t *ptr)

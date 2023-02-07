/* libSCHC compile-time configuration */

/*
 * Copyright (C) 2018 imec IDLab
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef SCHC_CONFIG_H
#define SCHC_CONFIG_H

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#ifndef NLOGGING
/**
 * :value: 0
 *
 * Toggle logging at compile time: ``NLOGGING=0`` means logging is delegated to
 * :c:func:`pylog_debug`, ``NLOGGING=1`` means all logging functionality is removed from
 * libSCHC.
 */
#define NLOGGING                        0
#endif

#if !NLOGGING
#include "pylogging.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * :value: 0
 *
 * Deactivate CLICK.
 */
#define CLICK                           0

/**
 * :value: 1
 *
 * Use dynamic memory management.
 */
#define DYNAMIC_MEMORY                  1

/**
 * :value: 1
 *
 * Use CoAP.
 */
#define USE_COAP                        1

/**
 * :value: 1
 *
 * Use IPv6 and UDP.
 */
#define USE_IP6_UDP                     1

/**
 * :value: 32
 *
 * The maximum length of a single header field,
 * e.g., you can use 4 ipv6 source iid addresses with match-mapping.
 */
#define MAX_FIELD_LENGTH                32

/**
 * :value: 14
 *
 * Maximum number of header field descriptors present in a IPv6 compression rule.
 */
#define IP6_FIELDS                      14

/**
 * :value: 4
 *
 * Maximum number of header field descriptors present in a UDP compression rule.
 */
#define UDP_FIELDS                      4

/**
 * :value: 16
 *
 * Maximum number of header field descriptors present in a CoAP compression rule.
 */
#define COAP_FIELDS                     16

/**
 * :value: 16
 *
 * Maximum number of header field descriptors present in a CoAP compression rule.
 */
#define MAX_HEADER_LENGTH               256

/**
 * :value: 24
 *
 * Maximum CoAP header length.
 */
#define MAX_COAP_HEADER_LENGTH          64

/**
 * :value: 256
 *
 * Maximum CoAP payload length.
 */
#define MAX_PAYLOAD_LENGTH              256

/**
 * :value: :c:macro:`MAX_COAP_HEADER_LENGTH` + :c:macro:`MAX_PAYLOAD_LENGTH`
 *
 * Maximum CoAP message size.
 */
#define MAX_COAP_MSG_SIZE               MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH

/**
 * :value: 1280
 *
 * The maximum transfer unit of the underlying technology.
 */
#define MAX_MTU_LENGTH                  1280

/**
 * :value: 1
 *
 * The maximum number of tokens inside a JSON structure.
 */
#define JSON_TOKENS                     1

#if !NLOGGING
/**
 * Compile-time switchable debug macro for libSCHC.
 */
#define DEBUG_PRINTF(...)               pylog_debug(__VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

/**
 * :value: 3
 *
 * The maximum number of ACK attempts
 */
#define MAX_ACK_REQUESTS                3

/**
 * :value: 6
 *
 * The maximum number of FCN bits
 */
#define FCN_SIZE_BITS                   6

/**
 * :value: 0
 *
 * The maximum number of DTAG bits
 */
#define DTAG_SIZE_BITS                  0

/**
 * :value: 4
 *
 * The maximum number of bytes the MIC consists of
 */
#define MIC_SIZE_BYTES                  4

/**
 * :value: (1 << :c:macro:`FCN_SIZE_BITS`) / 8
 *
 * The length of the bitmap in bytes */
#define BITMAP_SIZE_BYTES               ((1 << FCN_SIZE_BITS) / 8)

#ifdef __cplusplus
}
#endif

#endif /* SCHC_CONFIG_H */
/**
 * @internal
 * @}
 */

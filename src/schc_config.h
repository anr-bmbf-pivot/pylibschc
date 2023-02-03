/*
 * Copyright (C) 2018 imec IDLab
 * Copyright (C) 2022 Freie Universität Berlin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @addtogroup  pkg_libschc_config
 *
 * @internal
 * @name        libSCHC-side compile-time config for libSCHC
 * @{
 *
 * @file
 *
 * Usually this file and its macros need not to be touched. Use the compile-time
 * configuration macros in @ref libschc_config.h to configure @ref pkg_libschc.
 *
 * @author  boortmans <bart.moons@gmail.com>
 * @author  Martine S. Lenders <m.lenders@fu-berlin.de>
 */
#ifndef SCHC_CONFIG_H
#define SCHC_CONFIG_H

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLICK                           0

#define DYNAMIC_MEMORY                  1

/* #define SCHC_CONF_RX_CONNS              2 */
/* #define SCHC_CONF_MBUF_POOL_LEN         128 */

#define USE_COAP                        1

#define USE_IP6_UDP                     1

/* the maximum length of a single header field
 * e.g. you can use 4 ipv6 source iid addresses with match-mapping */
#define MAX_FIELD_LENGTH                32

/* maximum number of header fields present in a rule (vertical, top to bottom) */
#define IP6_FIELDS                      14
#define UDP_FIELDS                      4
#define COAP_FIELDS                     16

#define MAX_HEADER_LENGTH               256

#define MAX_COAP_HEADER_LENGTH          64
#define MAX_PAYLOAD_LENGTH              256
#define MAX_COAP_MSG_SIZE               MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH

/* the maximum transfer unit of the underlying technology */
#define MAX_MTU_LENGTH                  1280

/* the maximum number of tokens inside a JSON structure */
#define JSON_TOKENS                     16

#define DEBUG_PRINTF(...)

/* the number of ack attempts */
#define MAX_ACK_REQUESTS                3

/* the number of FCN bits */
#define FCN_SIZE_BITS                   6

/* the number of DTAG bits */
#define DTAG_SIZE_BITS                  0

/* the number of bytes the MIC consists of */
#define MIC_SIZE_BYTES                  4

/* the length of the bitmap */
#define BITMAP_SIZE_BYTES               ((1 << FCN_SIZE_BITS) / 8)

#ifdef __cplusplus
}
#endif

#endif /* SCHC_CONFIG_H */
/**
 * @internal
 * @}
 */

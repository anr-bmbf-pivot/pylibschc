/*
 * generated by pylibschc with schc_config.h
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * #define USE_IP6              1
 * #define USE_UDP              1
 * #define USE_COAP             1
 * #define MAX_FIELD_LENGTH     32
 * #define IP6_FIELDS           14
 * #define UDP_FIELDS           4
 * #define COAP_FIELDS          16
 * #define FCN_SIZE_BITS        6
 * #define DTAG_SIZE_BITS       0
 * #define BITMAP_SIZE_BITS     64
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef RULES_RULE_CONFIG_H
#define RULES_RULE_CONFIG_H

#include "schc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if USE_IP6
static const struct schc_ipv6_rule_t ipv6_rule_00 = {
    .up = 10, .down = 10, .length = 11,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { IP6_V,             0,   4,   1, BI,   {0x06},             &mo_equal,      NOTSENT     },
        { IP6_TC,            0,   8,   1, BI,   {0x00},             &mo_ignore,     NOTSENT     },
        { IP6_FL,            0,  20,   1, BI,   {0x00, 0x00, 0x00}, &mo_ignore,     NOTSENT     },
        { IP6_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPLENGTH  },
        { IP6_NH,            0,   8,   1, BI,   {0x11},             &mo_equal,      NOTSENT     },
        { IP6_HL,            0,   8,   1, UP,   {0x40},             &mo_equal,      NOTSENT     },
        { IP6_HL,            0,   8,   1, DOWN, {0x00},             &mo_ignore,     VALUESENT   },
        { IP6_DEVPRE,        0,  64,   1, BI,   {
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00
            },                                                      &mo_equal,      NOTSENT     },
        { IP6_DEVIID,        0,  64,   1, BI,   {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
            },                                                      &mo_equal,      NOTSENT     },
        { IP6_APPPRE,        4,  64,   1, BI,   {
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x03, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x04, 0x00, 0x00
            },                                                      &mo_matchmap,   MAPPINGSENT },
        { IP6_APPIID,        0,  64,   1, BI,   {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
            },                                                      &mo_equal,      NOTSENT     }
    }
};

static const struct schc_ipv6_rule_t ipv6_rule_01 = {
    .up = 10, .down = 10, .length = 10,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { IP6_V,             0,   4,   1, BI,   {0x06},             &mo_equal,      NOTSENT     },
        { IP6_TC,            0,   8,   1, BI,   {0x00},             &mo_ignore,     NOTSENT     },
        { IP6_FL,            0,  20,   1, BI,   {0x00, 0x00, 0x00}, &mo_ignore,     NOTSENT     },
        { IP6_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPLENGTH  },
        { IP6_NH,            2,   8,   1, BI,   {0x11, 0x3a},       &mo_matchmap,   MAPPINGSENT },
        { IP6_HL,            2,   8,   1, BI,   {0x40, 0xff},       &mo_matchmap,   NOTSENT     },
        { IP6_DEVPRE,        0,  64,   1, BI,   {
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            },                                                      &mo_equal,      NOTSENT     },
        { IP6_DEVIID,       62,  64,   1, BI,   {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
            },                                                      &mo_MSB,        LSB         },
        { IP6_APPPRE,        0,  64,   1, BI,   {
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            },                                                      &mo_equal,      NOTSENT     },
        { IP6_APPIID,       62,  64,   1, BI,   {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
            },                                                      &mo_MSB,        LSB         }
    }
};
#endif /* USE_IP6 */

#if USE_UDP
static const struct schc_udp_rule_t udp_rule_00 = {
    .up = 4, .down = 4, .length = 4,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { UDP_DEV,           2,  16,   1, BI,   {
                0x16, 0x33,
                0x16, 0x34
            },                                                      &mo_matchmap,   MAPPINGSENT },
        { UDP_APP,           2,  16,   1, BI,   {
                0x16, 0x33,
                0x16, 0x34
            },                                                      &mo_matchmap,   MAPPINGSENT },
        { UDP_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPLENGTH  },
        { UDP_CHK,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPCHK     }
    }
};

static const struct schc_udp_rule_t udp_rule_01 = {
    .up = 4, .down = 4, .length = 4,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { UDP_DEV,          12,  16,   1, BI,   {0x1f, 0x40},       &mo_MSB,        LSB         },
        { UDP_APP,          12,  16,   1, BI,   {0x1f, 0x40},       &mo_MSB,        LSB         },
        { UDP_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPLENGTH  },
        { UDP_CHK,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPCHK     }
    }
};

static const struct schc_udp_rule_t udp_rule_02 = {
    .up = 4, .down = 4, .length = 4,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { UDP_DEV,           0,  16,   1, BI,   {0x13, 0x89},       &mo_equal,      NOTSENT     },
        { UDP_APP,           0,  16,   1, BI,   {0x13, 0x88},       &mo_equal,      NOTSENT     },
        { UDP_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPLENGTH  },
        { UDP_CHK,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPCHK     }
    }
};
#endif /* USE_UDP */

#if USE_COAP
static const struct schc_coap_rule_t coap_rule_00 = {
    .up = 9, .down = 9, .length = 9,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { COAP_V,            0,   2,   1, BI,   {0x01},             &mo_equal,      NOTSENT     },
        { COAP_T,            0,   2,   1, BI,   {0x01},             &mo_equal,      NOTSENT     },
        { COAP_TKL,          0,   4,   1, BI,   {0x04},             &mo_equal,      NOTSENT     },
        { COAP_C,            0,   8,   1, BI,   {0x03},             &mo_equal,      NOTSENT     },
        { COAP_MID,         12,  16,   1, BI,   {0x23, 0xb0},       &mo_MSB,        LSB         },
        { COAP_TKN,         24,  32,   1, BI,   {
                0x21, 0xfa, 0x01, 0x00
            },                                                      &mo_MSB,        LSB         },
        { COAP_URIPATH,      0,  40,   1, BI,   {
                0x75, 0x73, 0x61, 0x67, 0x65
            },                                                      &mo_equal,      NOTSENT     },
        { COAP_NORESP,       0,   8,   1, BI,   {0x1a},             &mo_equal,      NOTSENT     },
        { COAP_PAYLOAD,      0,   8,   1, BI,   {0xff},             &mo_equal,      NOTSENT     }
    }
};

static const struct schc_coap_rule_t coap_rule_01 = {
    .up = 7, .down = 8, .length = 10,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { COAP_V,            0,   2,   1, BI,   {0x01},             &mo_equal,      NOTSENT     },
        { COAP_T,            0,   2,   1, BI,   {0x01},             &mo_equal,      NOTSENT     },
        { COAP_TKL,          0,   4,   1, BI,   {0x04},             &mo_equal,      NOTSENT     },
        { COAP_C,            0,   8,   1, UP,   {0x45},             &mo_equal,      NOTSENT     },
        { COAP_C,            0,   8,   1, DOWN, {0x01},             &mo_equal,      NOTSENT     },
        { COAP_MID,         12,  16,   1, UP,   {0x23, 0xb0},       &mo_MSB,        LSB         },
        { COAP_MID,          0,  16,   1, DOWN, {0x00, 0x00},       &mo_ignore,     VALUESENT   },
        { COAP_TKN,          0,  32,   1, BI,   {
                0x00, 0x00, 0x00, 0x00
            },                                                      &mo_ignore,     VALUESENT   },
        { COAP_URIPATH,      0,  32,   1, DOWN, {
                0x74, 0x65, 0x6d, 0x70
            },                                                      &mo_equal,      NOTSENT     },
        { COAP_PAYLOAD,      0,   8,   1, BI,   {0xff},             &mo_equal,      NOTSENT     }
    }
};

static const struct schc_coap_rule_t coap_rule_02 = {
    .up = 1, .down = 1, .length = 1,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { COAP_V,            0,   2,   1, BI,   {0x01},             &mo_equal,      NOTSENT     }
    }
};
#endif /* USE_COAP */

static const struct schc_compression_rule_t comp_rule_001_08_00 = {
    .rule_id = 1U,
    .rule_id_size_bits = 8U,
#if USE_IP6
    .ipv6_rule = &ipv6_rule_00,
#endif
#if USE_UDP
    .udp_rule = &udp_rule_00,
#endif
#if USE_COAP
    .coap_rule = &coap_rule_00,
#endif
};

static const struct schc_compression_rule_t comp_rule_002_08_00 = {
    .rule_id = 2U,
    .rule_id_size_bits = 8U,
#if USE_IP6
    .ipv6_rule = &ipv6_rule_00,
#endif
#if USE_UDP
    .udp_rule = &udp_rule_01,
#endif
#if USE_COAP
    .coap_rule = &coap_rule_01,
#endif
};

static const struct schc_compression_rule_t comp_rule_003_08_00 = {
    .rule_id = 3U,
    .rule_id_size_bits = 8U,
#if USE_IP6
    .ipv6_rule = &ipv6_rule_01,
#endif
#if USE_UDP
    .udp_rule = &udp_rule_02,
#endif
#if USE_COAP
    .coap_rule = &coap_rule_02,
#endif
};

static const struct schc_compression_rule_t comp_rule_004_08_00 = {
    .rule_id = 4U,
    .rule_id_size_bits = 8U,
#if USE_IP6
    .ipv6_rule = &ipv6_rule_01,
#endif
#if USE_UDP
    .udp_rule = NULL,
#endif
#if USE_COAP
    .coap_rule = NULL,
#endif
};

static const struct schc_fragmentation_rule_t frag_rule_021_08_00 = {
    .rule_id = 21U,
    .rule_id_size_bits = 8U,
    .mode = NO_ACK,
    .dir = BI,
    .FCN_SIZE =      1U,    /* FCN field size (N in RFC) */
    .MAX_WND_FCN =   0U,    /* Maximum fragments per window (WINDOW_SIZE in RFC) */
    .WINDOW_SIZE =   0U,    /* W field size (M in RFC) */
    .DTAG_SIZE =     0U     /* DTAG field size (T in RFC) */
};

static const struct schc_fragmentation_rule_t frag_rule_022_08_00 = {
    .rule_id = 22U,
    .rule_id_size_bits = 8U,
    .mode = ACK_ON_ERROR,
    .dir = BI,
    .FCN_SIZE =      6U,    /* FCN field size (N in RFC) */
    .MAX_WND_FCN =  62U,    /* Maximum fragments per window (WINDOW_SIZE in RFC) */
    .WINDOW_SIZE =   2U,    /* W field size (M in RFC) */
    .DTAG_SIZE =     0U     /* DTAG field size (T in RFC) */
};

static const struct schc_fragmentation_rule_t frag_rule_022_08_01 = {
    .rule_id = 22U,
    .rule_id_size_bits = 8U,
    .mode = NO_ACK,
    .dir = UP,
    .FCN_SIZE =      1U,    /* FCN field size (N in RFC) */
    .MAX_WND_FCN =   0U,    /* Maximum fragments per window (WINDOW_SIZE in RFC) */
    .WINDOW_SIZE =   0U,    /* W field size (M in RFC) */
    .DTAG_SIZE =     0U     /* DTAG field size (T in RFC) */
};

static const struct schc_fragmentation_rule_t frag_rule_023_08_00 = {
    .rule_id = 23U,
    .rule_id_size_bits = 8U,
    .mode = ACK_ALWAYS,
    .dir = BI,
    .FCN_SIZE =      6U,    /* FCN field size (N in RFC) */
    .MAX_WND_FCN =  62U,    /* Maximum fragments per window (WINDOW_SIZE in RFC) */
    .WINDOW_SIZE =   2U,    /* W field size (M in RFC) */
    .DTAG_SIZE =     0U     /* DTAG field size (T in RFC) */
};

static const struct schc_compression_rule_t *compression_rules_00[] = {
    &comp_rule_001_08_00,
    &comp_rule_002_08_00,
    &comp_rule_003_08_00,
    &comp_rule_004_08_00,
};

static const struct schc_compression_rule_t *compression_rules_01[] = {
    &comp_rule_001_08_00,
    &comp_rule_002_08_00,
    &comp_rule_003_08_00,
};

static const struct schc_fragmentation_rule_t *fragmentation_rules_00[] = {
    &frag_rule_021_08_00,
    &frag_rule_022_08_00,
    &frag_rule_023_08_00,
};

static const struct schc_fragmentation_rule_t *fragmentation_rules_01[] = {
    &frag_rule_021_08_00,
    &frag_rule_022_08_00,
};

static const struct schc_fragmentation_rule_t *fragmentation_rules_02[] = {
    &frag_rule_022_08_01,
};

static const struct schc_device device1 = {
    .device_id = 1U,
    .uncomp_rule_id = 20U,
    .uncomp_rule_id_size_bits = 8U,
    .compression_rule_count = sizeof(compression_rules_00) / sizeof(compression_rules_00[0]),
    .compression_context = &compression_rules_00,
    .fragmentation_rule_count = sizeof(fragmentation_rules_00) / sizeof(fragmentation_rules_00[0]),
    .fragmentation_context = &fragmentation_rules_00,
};

static const struct schc_device device2 = {
    .device_id = 2U,
    .uncomp_rule_id = 20U,
    .uncomp_rule_id_size_bits = 8U,
    .compression_rule_count = sizeof(compression_rules_00) / sizeof(compression_rules_00[0]),
    .compression_context = &compression_rules_00,
    .fragmentation_rule_count = sizeof(fragmentation_rules_00) / sizeof(fragmentation_rules_00[0]),
    .fragmentation_context = &fragmentation_rules_00,
};

static const struct schc_device device3 = {
    .device_id = 3U,
    .uncomp_rule_id = 0U,
    .uncomp_rule_id_size_bits = 8U,
    .compression_rule_count = sizeof(compression_rules_01) / sizeof(compression_rules_01[0]),
    .compression_context = &compression_rules_01,
    .fragmentation_rule_count = sizeof(fragmentation_rules_01) / sizeof(fragmentation_rules_01[0]),
    .fragmentation_context = &fragmentation_rules_01,
};

static const struct schc_device device4 = {
    .device_id = 4U,
    .uncomp_rule_id = 20U,
    .uncomp_rule_id_size_bits = 6U,
    .compression_rule_count = 0U,
    .compression_context = NULL,
    .fragmentation_rule_count = sizeof(fragmentation_rules_02) / sizeof(fragmentation_rules_02[0]),
    .fragmentation_context = &fragmentation_rules_02,
};

static const struct schc_device device5 = {
    .device_id = 5U,
    .uncomp_rule_id = 0U,
    .uncomp_rule_id_size_bits = 0U,
    .compression_rule_count = 0U,
    .compression_context = NULL,
    .fragmentation_rule_count = 0U,
    .fragmentation_context = NULL,
};

static const struct schc_device* devices[] = {
    &device1,
    &device2,
    &device3,
    &device4,
    &device5
};

#define DEVICE_COUNT    ((int)(sizeof(devices) / sizeof(devices[0])))

#ifdef __cplusplus
}
#endif

#endif /* RULES_RULE_CONFIG_H */

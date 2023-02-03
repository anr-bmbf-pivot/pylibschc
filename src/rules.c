/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdlib.h>

#include "schc.h"
#include "rules/rule_config.h"

#include "rules.h"


int DEVICE_COUNT = 0;
struct schc_device **devices = NULL;

struct schc_compression_rule_t **schc_rules_create_compr_ctx(unsigned rule_count)
{
    struct schc_compression_rule_t **ctx = malloc(
        sizeof(struct schc_compression_rule_t) * rule_count
    );
    for (unsigned i = 0; i < rule_count; i++) {
        ctx[i] = malloc(sizeof(struct schc_compression_rule_t));
        *(ctx[i]) = (struct schc_compression_rule_t){ 0 };
    }
    return ctx;
}

struct schc_ipv6_rule_t *schc_rules_create_ipv6_rule(void)
{
    return malloc(sizeof(struct schc_ipv6_rule_t));
}

struct schc_udp_rule_t *schc_rules_create_udp_rule(void)
{
    return malloc(sizeof(struct schc_udp_rule_t));
}

struct schc_coap_rule_t *schc_rules_create_coap_rule(void)
{
    return malloc(sizeof(struct schc_coap_rule_t));
}

struct schc_fragmentation_rule_t **schc_rules_create_frag_ctx(unsigned rule_count)
{
    struct schc_fragmentation_rule_t **ctx = malloc(
        sizeof(struct schc_fragmentation_rule_t) * rule_count
    );
    for (unsigned i = 0; i < rule_count; i++) {
        ctx[i] = malloc(sizeof(struct schc_fragmentation_rule_t));
        *(ctx[i]) = (struct schc_fragmentation_rule_t){ 0 };
    }
    return ctx;
}

static void _free_compr_rule(struct schc_compression_rule_t *ctx)
{
    if (ctx->ipv6_rule) {
        free(ctx->ipv6_rule);
    }
    if (ctx->udp_rule) {
        free(ctx->udp_rule);
    }
    if (ctx->coap_rule) {
        free(ctx->coap_rule);
    }
    free(ctx);
}

void schc_rules_free_compr_ctx(struct schc_compression_rule_t **ctx, unsigned rule_count)
{
    for (unsigned i = 0; i < rule_count; i++) {
        _free_compr_rule(ctx[i]);
    }
    free(ctx);
}

void schc_rules_free_frag_ctx(struct schc_fragmentation_rule_t **ctx, unsigned rule_count)
{
    for (unsigned i = 0; i < rule_count; i++) {
        free(ctx[i]);
    }
    free(ctx);
}

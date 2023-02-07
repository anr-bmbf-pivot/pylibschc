/* Dynamic memory manipulation of rule contexts */

/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef RULES_H
#define RULES_H

struct schc_compression_rule_t **schc_rules_create_compr_ctx(unsigned rule_count);
struct schc_ipv6_rule_t *schc_rules_create_ipv6_rule(void);
struct schc_udp_rule_t *schc_rules_create_udp_rule(void);
struct schc_coap_rule_t *schc_rules_create_coap_rule(void);
struct schc_fragmentation_rule_t **schc_rules_create_frag_ctx(unsigned rule_count);
void schc_rules_free_compr_ctx(struct schc_compression_rule_t **ctx, unsigned rule_count);
void schc_rules_free_frag_ctx(struct schc_fragmentation_rule_t **ctx, unsigned rule_count);

#endif /* !RULES_H */

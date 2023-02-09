/* Dynamic memory manipulation of rule contexts */

/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef RULES_H
#define RULES_H

/**
 * Allocates the array for the compression context of a device.
 *
 * :param rule_count: The number of rule entries to be added to the compression context.
 * :type rule_count: unsigned
 * :return: An array of allocates ``struct schc_compression_rule_t`` pointers.
 * :retval NULL: when the context can not be allocated.
 * :rtype: ``struct schc_compression_rule_t **``
 */
struct schc_compression_rule_t **schc_rules_create_compr_ctx(unsigned rule_count);

/**
 * Allocate an IPv6 layer rule
 *
 * :return: A ``struct schc_ipv6_rule_t`` pointer.
 * :retval NULL: when the layer rule can not be allocated.
 * :rtype: ``struct schc_ipv6_rule_t *``
 */
struct schc_ipv6_rule_t *schc_rules_create_ipv6_rule(void);

/**
 * Allocate an UDP layer rule
 *
 * :return: A ``struct schc_udp_rule_t`` pointer.
 * :retval NULL: when the layer rule can not be allocated.
 * :rtype: ``struct schc_udp_rule_t *``
 */
struct schc_udp_rule_t *schc_rules_create_udp_rule(void);

/**
 * Allocate an CoAP layer rule
 *
 * :return: A ``struct schc_coap_rule_t`` pointer.
 * :retval NULL: when the layer rule can not be allocated.
 * :rtype: ``struct schc_coap_rule_t *``
 */
struct schc_coap_rule_t *schc_rules_create_coap_rule(void);

/**
 * Allocates the array for the fragmentation context of a device.
 *
 * :param rule_count: The number of rule entries to be added to the fragmentation context.
 * :type rule_count: unsigned
 * :return: An array of allocates ``struct schc_fragmentation_rule_t`` pointers.
 * :retval NULL: When the context can not be allocated.
 * :rtype: ``struct schc_fragmentation_rule_t **``
 */
struct schc_fragmentation_rule_t **schc_rules_create_frag_ctx(unsigned rule_count);

/**
 * Frees the compression context allocated with :func:`schc_rules_create_compr_ctx()`.
 *
 * :param ctx: The context to be free'd.
 * :type ctx: ``struct schc_compression_rule_t **``
 * :param rule_count: The number of rules that are contained in ``ctx``.
 * :type rule_count: unsigned
 */
void schc_rules_free_compr_ctx(struct schc_compression_rule_t **ctx, unsigned rule_count);

/**
 * Frees the fragmentation context allocated with :func:`schc_rules_create_frag_ctx()`.
 *
 * :param ctx: The context to be free'd.
 * :type ctx: ``struct schc_fragmentation_rule_t **``
 * :param rule_count: The number of rules that are contained in ``ctx``.
 * :type rule_count: unsigned
 */
void schc_rules_free_frag_ctx(struct schc_fragmentation_rule_t **ctx, unsigned rule_count);

#endif /* !RULES_H */

/* Rule configuration stub for libSCHC to allow for dynamic rule management */

/*
 * Copyright (C) 2018 imec IDLab
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef RULES_RULE_CONFIG_H
#define RULES_RULE_CONFIG_H

#include "schc.h"

/**
 * The devices registered to libSCHC.
 */
extern struct schc_device **devices;

/**
 * The number entries in :c:var:`devices`.
 */
extern int DEVICE_COUNT;

#endif /* RULES_RULE_CONFIG_H */

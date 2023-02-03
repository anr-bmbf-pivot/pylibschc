/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdlib.h>

#include "schc.h"
#include "rules/rule_config.h"


int DEVICE_COUNT = 0;
struct schc_device **devices = NULL;

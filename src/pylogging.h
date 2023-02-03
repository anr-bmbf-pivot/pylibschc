/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef PYLOGGING_H
#define PYLOGGING_H

#include "Python.h"

#define PYLOG_BUFFER_SIZE   1024


void pylog_init(PyObject *logger);
int pylog_debug(const char *format, ...);

#endif /* PYLOGGING_H */

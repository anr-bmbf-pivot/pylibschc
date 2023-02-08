/* Redirect :c:macro:`DEBUG_PRINTF()` to :py:func:`logging.debug`. */

/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef PYLOGGING_H
#define PYLOGGING_H

#include "Python.h"

/**
 * Maximum line buffer length.
 */
#define PYLOG_BUFFER_SIZE   1024

/**
 * Add a record to the python loggers :py:data:`logging.DEBUG` log.
 *
 * :param format: a ``printf()`` format string
 *
 * The remaining parameters will be formatted as with ``printf()``
 */
int pylog_debug(const char *format, ...);

#endif /* PYLOGGING_H */

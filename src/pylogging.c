/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "Python.h"

#include "pylogging.h"

pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
static PyObject *_logger = NULL;
static PyObject *_get_level = NULL;
static PyObject *_debug = NULL;
static char *_concat_buffer = NULL;
static size_t _concat_buffer_size = 0;
static long _debug_level = 0;

void pylog_init(PyObject *logger)
{
    PyObject *logging = NULL, *debug_level = NULL;

    if (_logger != logger) {
        Py_XDECREF(_logger);
        Py_XDECREF(_get_level);
        Py_XDECREF(_debug);
        _logger = logger;
        _get_level = PyObject_GetAttrString(_logger, "getEffectiveLevel");
        if (!_get_level) {
            goto error;
        }
        _debug = PyObject_GetAttrString(_logger, "debug");
        if (!_debug) {
            goto error;
        }
        logging = PyImport_ImportModule("logging");
        if (!logging) {
            goto error;
        }
        debug_level = PyObject_GetAttrString(logging, "DEBUG");
        if (!debug_level) {
            goto error;
        }
        if ((_debug_level = PyLong_AsLong(debug_level)) < 0) {
            goto error;
        }
    }
    Py_XDECREF(logging);
    Py_XDECREF(debug_level);
    _concat_buffer = NULL;
    _concat_buffer_size = 0;
    return;

error:
    _logger = NULL;
}

int pylog_debug(const char *format, ...)
{
    va_list args;

    if (_logger) {
        PyObject *level = PyObject_CallObject(_get_level, NULL);
        PyObject *log_result;

        if (level && ((PyLong_AsLong(level) > _debug_level) || PyErr_Occurred())) {
            Py_DECREF(level);
            return 0;
        }
        Py_XDECREF(level);
        int size = PYLOG_BUFFER_SIZE;
        char *str;
        bool str_malloced = true;
        /* if concat buffer is initialized, let vsnprintf continue concatenation */
        pthread_mutex_lock(&_mutex);
        if (_concat_buffer) {
            str = &_concat_buffer[_concat_buffer_size];
            size -= _concat_buffer_size;
            str_malloced = false;
        }
        /* else, allocate a new string */
        else if ((str = (char *)malloc(sizeof(char) * size)) == NULL) {
            size = -1;
            goto early_out;
        }
        va_start(args, format);
        size = vsnprintf(str, size, format, args);
        va_end(args);
        if (size < 0) {
            goto end;
        }

        /* check if string ends a line (but does not overflow alloc'd area) */
        if (((_concat_buffer_size + size) < (PYLOG_BUFFER_SIZE)) &&
            (str[size - 1] == '\n')) {
            str[--size] = '\0';
        }
        /* else, if concat buffer is not initialized yet, initialize it */
        else if (!_concat_buffer) {
            _concat_buffer = str;
            _concat_buffer_size = size;
            goto early_out;
        }
        /* else if buffer still fits count new content for concat buffer */
        else if ((_concat_buffer_size + size) < (PYLOG_BUFFER_SIZE - 1)) {
            _concat_buffer_size += size;
            goto early_out;
        }
        /* else if size is 0 and no concat buffer initialized, do not log */
        else if ((size == 0) && (!_concat_buffer)) {
            goto end;
        }
        if (_concat_buffer) {  /* if concat buffer is initialized, log it */
            str = &_concat_buffer[0];
            size = _concat_buffer_size;
        }
        if ((log_result = PyObject_CallFunction(_debug, "s", str)) == NULL) {
            size = -1;
            goto end;
        }
        Py_DECREF(log_result);
end:
        if (str_malloced) {
            free(str);
        }
        else {
            if (_concat_buffer) {
                free(_concat_buffer);
            }
        }
        _concat_buffer = NULL;
        _concat_buffer_size = 0;
early_out:
        pthread_mutex_unlock(&_mutex);
        return size;
    }
    return 0;
}

# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import logging
import math

import pylibschc.libschc  # pylint: disable=import-error,no-name-in-module

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


def test_pylog_debug(caplog):
    # pylint: disable=no-member
    with caplog.at_level(logging.DEBUG):
        pylibschc.libschc.test_pylog_debug(b"This is a %s   %d\n", b"test", 12345)
    assert "This is a test   12345" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        pylibschc.libschc.test_pylog_debug(b"This is another %s for %d", b"test", 42)
    # no newline so this shouldn't show up
    assert "This is another test for 42" not in caplog.text
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        pylibschc.libschc.test_pylog_debug(b" %s%02x", b"0x", 255)
    # no newline so this shouldn't show up
    assert "This is another test for 42 0xff" not in caplog.text
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        pylibschc.libschc.test_pylog_debug(b", but now we %s: %d\n", b"print", 7357)
    assert "This is another test for 42 0xff, but now we print: 7357" in caplog.text


def test_pylog_debug_buffer_overflow(caplog):
    # pylint: disable=no-member
    numbers = 256
    assert pylibschc.libschc.PYLOG_BUFFER_SIZE < (
        (numbers * len("0xXX ")) + len(f"{numbers:04x}\n")
    )
    assert (2 * pylibschc.libschc.PYLOG_BUFFER_SIZE) > (
        (numbers * len("0xXX ")) + len(f"{numbers:04x}\n")
    )
    with caplog.at_level(logging.DEBUG):
        for i in range(numbers):
            pylibschc.libschc.test_pylog_debug(b"%s%02x ", b"0x", i)
        pylibschc.libschc.test_pylog_debug(b"%s%04x\n", b"", numbers)
    assert (
        len(caplog.records)
        == math.ceil(
            ((numbers * len("0xXX ")) + len(f"{numbers:04x}\n"))
            / pylibschc.libschc.PYLOG_BUFFER_SIZE
        )
        == 2
    )
    truncated_chars = int(
        round(
            len("0xXX ")
            * (
                (pylibschc.libschc.PYLOG_BUFFER_SIZE / len("0xXX "))
                - (pylibschc.libschc.PYLOG_BUFFER_SIZE // len("0xXX "))
            )
        )
    ) - len("\n")
    assert (
        caplog.records[0].message
        == "".join(
            f"0x{i:02x} "
            for i in range(pylibschc.libschc.PYLOG_BUFFER_SIZE // len("0xXX "))
        )
        + (f"0x{pylibschc.libschc.PYLOG_BUFFER_SIZE // len('0xXX '):02x}")[
            :truncated_chars
        ]
    )
    assert (
        caplog.records[1].message
        == "".join(
            f"0x{i:02x} "
            for i in range(
                pylibschc.libschc.PYLOG_BUFFER_SIZE // len("0xXX ") + 1, numbers
            )
        )
        + f"{numbers:04x}"
    )

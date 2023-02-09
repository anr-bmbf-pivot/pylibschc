# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import pytest

import pylibschc.libschc  # pylint: disable=import-error,no-name-in-module

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


def test_bit_array():
    test = b"Lorem ipsum"
    bit_array = pylibschc.libschc.BitArray(len(test))  # pylint: disable=no-member
    bit_array.buffer = test
    assert bit_array.buffer == test
    assert bit_array.offset == 0
    assert bit_array.padding == 0
    assert bit_array.length == len(test)
    assert bit_array.bit_length == len(test) * 8


def test_bit_array_get_bits():
    test = b"\x92\xd1"
    bit_array = pylibschc.libschc.BitArray(len(test))  # pylint: disable=no-member
    bit_array.buffer = test
    assert bit_array.get_bits(0, 8) == 0x92
    assert bit_array.get_bits(0, 3) == 0x4
    assert bit_array.get_bits(0, 14) == 0x24B4
    with pytest.raises(ValueError):
        bit_array.get_bits(0, 33)
    with pytest.raises(ValueError):
        bit_array.get_bits(0, -233)
    with pytest.raises(ValueError):
        bit_array.get_bits(-1, 32)
    with pytest.raises(ValueError):
        bit_array.get_bits(16, 1)


def test_bit_array_copy_bits():
    test = b"\x92\xd1"
    bit_array = pylibschc.libschc.BitArray(len(test))  # pylint: disable=no-member
    bit_array.buffer = test
    bit_array.copy_bits(1, b"\xff", 2)
    assert bit_array.buffer == b"\xf2\xd1"
    bit_array.copy_bits(1, b"\x31", 8)
    assert bit_array.buffer == b"\x98\xd1"
    with pytest.raises(ValueError):
        bit_array.copy_bits(2, b"\xf0", 15)
    with pytest.raises(ValueError):
        bit_array.copy_bits(-1, b"\xf0", 8)
    with pytest.raises(ValueError):
        bit_array.copy_bits(2, b"\xf0", -8)

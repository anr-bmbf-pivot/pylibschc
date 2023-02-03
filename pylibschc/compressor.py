# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

import typing

import pylibschc.device

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


# pylint: disable=import-error
from .libschc import (
    BitArray,
    CompressorDecompressor as InnerCompressorDecompressor,
    CompressionResult,
    Direction,
)


class CompressorDecompressor:
    _inner_cls = InnerCompressorDecompressor
    _inner = None

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        if not cls._inner:
            cls._inner = cls._inner_cls()
            cls._inner.init()
        return super().__new__(cls)

    def __init__(self, device: pylibschc.device.Device, direction: Direction):
        if direction == Direction.BI:
            raise ValueError("direction must be either UP or DOWN, not BI")
        self.device = device
        self.direction = direction

    def output(
        self, data: typing.Union[bytes, BitArray]
    ) -> typing.Tuple[CompressionResult, BitArray,]:
        if isinstance(data, BitArray):
            byts = data.buffer
        elif isinstance(data, bytes):
            byts = data
        else:
            raise TypeError(f"data ({data}) expected to be either bytes or BitArray")
        return self._inner.compress(byts, self.device.__inner__, self.direction)

    def input(self, data: typing.Union[bytes, BitArray]) -> bytes:
        if isinstance(data, BitArray):
            bit_array = data
        elif isinstance(data, bytes):
            bit_array = BitArray(data)
        else:
            raise TypeError(f"data ({data}) expected to be either bytes or BitArray")
        return self._inner.decompress(bit_array, self.device.__inner__, self.direction)

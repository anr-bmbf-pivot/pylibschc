# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

"""User-facing compressor/decompressor functionality"""

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
    """A Compressor/Decompressor.

    This wraps :class:`pylibschc.libschc.CompressorDecompressor` for a more pythonic
    usage."""

    _inner_cls = InnerCompressorDecompressor
    _inner = None

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        if not cls._inner:
            cls._inner = cls._inner_cls()
            cls._inner.init()
        return super().__new__(cls)

    def __init__(self, device: pylibschc.device.Device, direction: Direction):
        """
        :param device: Device to be used for compression/decompression.
        :type device: :class:`pylibschc.device.Device`
        :param direction: Direction to use for compression/decompression.
        :type direction: :class:`pylibschc.libschc.Direction`
        :raise ValueError: When direction is :attr:`pylibschc.libschc.Direction.BI`.

        .. py:attribute:: device
           :type: pylibschc.device.Device

           Device to be used for compression/decompression.

        .. py:attribute:: direction
           :type: pylibschc.libschc.Direction

           Direction to use for compression/decompression.
        """
        if direction == Direction.BI:
            raise ValueError("direction must be either UP or DOWN, not BI")
        self.device = device
        self.direction = direction

    def output(
        self, data: typing.Union[bytes, BitArray]
    ) -> typing.Tuple[CompressionResult, BitArray]:
        """Compress according to the compression rules of
        :py:attr:`CompressorDecompressor.device`.

        :param data: The data to compress.
        :raise TypeError: When ``data`` is not of the expected input type.
        :return: Whether the packet was compressed or the uncompressed rule was used
            and the compressed packet as a :class:`pylibschc.libschc.BitArray`.
        :rtype: :class:`typing.Tuple` [
            :class:`pylibschc.libschc.CompressionResult` ,
            :class:`pylibschc.libschc.BitArray`
            ]
        """
        if isinstance(data, BitArray):
            byts = data.buffer
        elif isinstance(data, bytes):
            byts = data
        else:
            raise TypeError(f"data ({data}) expected to be either bytes or BitArray")
        return self._inner.compress(byts, self.device.__inner__, self.direction)

    def input(self, data: typing.Union[bytes, BitArray]) -> bytes:
        """Decompress according to the compression rules of
        :py:attr:`CompressorDecompressor.device`.

        :param data: The data to decompress.
        :raise TypeError: When ``data`` is not of the expected input type.
        :return: The decompressed data.
        :rtype: :class:`bytes`
        """
        if isinstance(data, BitArray):
            bit_array = data
        elif isinstance(data, bytes):
            bit_array = BitArray(data)
        else:
            raise TypeError(f"data ({data}) expected to be either bytes or BitArray")
        return self._inner.decompress(bit_array, self.device.__inner__, self.direction)

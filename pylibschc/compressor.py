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

    def __init__(self, device: pylibschc.device.Device):
        """
        :param device: Device to be used for compression/decompression.
        :type device: :class:`pylibschc.device.Device`

        .. py:attribute:: device
           :type: pylibschc.device.Device

           Device to be used for compression/decompression.
        """
        self.device = device

    def output(
        self, data: typing.Union[bytes, BitArray], direction: Direction
    ) -> typing.Tuple[CompressionResult, BitArray]:
        """Compress according to the compression rules of
        :py:attr:`CompressorDecompressor.device`.

        :param data: The data to compress.
        :param direction: Direction to use for compression.
        :raise TypeError: When ``data`` is not of the expected input type.
        :raise ValueError: When direction is :attr:`pylibschc.libschc.Direction.BI`.
        :return: Whether the packet was compressed or the uncompressed rule was used
            and the compressed packet as a :class:`pylibschc.libschc.BitArray`.
        :rtype: :class:`typing.Tuple` [
            :class:`pylibschc.libschc.CompressionResult` ,
            :class:`pylibschc.libschc.BitArray`
            ]
        """
        if direction == Direction.BI:
            raise ValueError("direction must be either UP or DOWN, not BI")
        if isinstance(data, BitArray):
            byts = data.buffer
        elif isinstance(data, bytes):
            byts = data
        else:
            raise TypeError(f"data ({data}) expected to be either bytes or BitArray")
        return self._inner.compress(byts, self.device.__inner__, direction)

    def input(self, data: typing.Union[bytes, BitArray], direction: Direction) -> bytes:
        """Decompress according to the compression rules of
        :py:attr:`CompressorDecompressor.device`.

        :param data: The data to decompress.
        :param direction: Direction to use for decompression.
        :raise TypeError: When ``data`` is not of the expected input type.
        :raise ValueError: When direction is :attr:`pylibschc.libschc.Direction.BI`.
        :return: The decompressed data.
        :rtype: :class:`bytes`
        """
        if direction == Direction.BI:
            raise ValueError("direction must be either UP or DOWN, not BI")
        if isinstance(data, BitArray):
            bit_array = data
        elif isinstance(data, bytes):
            bit_array = BitArray(data)
        else:
            raise TypeError(f"data ({data}) expected to be either bytes or BitArray")
        return self._inner.decompress(bit_array, self.device.__inner__, direction)

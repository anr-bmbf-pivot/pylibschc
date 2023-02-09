# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

"""User-facing representation of libSCHC devices."""

from __future__ import annotations
import typing

from pylibschc import libschc  # pylint: disable=import-error,no-name-in-module
from pylibschc import rules  # pylint: disable=cyclic-import

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


class Device:  # pylint: disable=too-many-instance-attributes
    """A libSCHC device.

    This wraps :class:`pylibschc.libschc.Device` for a more pythonic usage. Two devices
    with the same ``device_id`` are effectively the same object (i.e., this class is a
    multiton)

    """

    _devices = {}

    def __new__(cls, device_id: int, mtu: int, duty_cycle_ms: int):
        # pylint: disable=unused-argument
        if device_id <= 0:
            raise ValueError(f"device_id must be > 0 (was {device_id})")
        if device_id not in cls._devices:
            cls._devices[device_id] = super().__new__(cls)
        return cls._devices[device_id]

    def __init__(self, device_id: int, mtu: int, duty_cycle_ms: int):
        """
        :param device_id: The libSCHC-internal identifier of the device.
        :param mtu: The maximum transmission unit of the link layer of the device.
        :param duty_cycle_ms: The duty cycle in milliseconds of the device.

        .. py:attribute:: mtu
           :type: pylibschc.device.Device

           The maximum transmission unit of the link layer of the device.


        .. py:attribute:: duty_cycle_ms
           :type: pylibschc.libschc.Direction

           The duty cycle in milliseconds of the device.
        """
        try:
            self._inner = libschc.Device.get(device_id)
        except KeyError:
            self._inner = libschc.Device(device_id)
        self.mtu = mtu
        self.duty_cycle_ms = duty_cycle_ms
        self._compression_rules = None
        self._fragmentation_rules = None
        self._uncompressed_rule = None

    @classmethod
    def delete(cls, device_id: int):
        """Delete device identified by ``device_id`` from libSCHC.

        :param device_id: The libSCHC-internal identifier of the device.
        :type device_id: :py:class:`int`"""
        if device_id not in cls._devices:
            return
        device = cls._devices[device_id]
        del cls._devices[device_id]
        # ensure everything is cleaned up
        device._inner.unregister()  # pylint: disable=protected-access
        del device._inner
        del device

    @classmethod
    def get(cls, device_id: int) -> Device:
        """Get device identified by ``device_id``.

        :param device_id: The libSCHC-internal identifier of the device.
        :type device_id: :py:class:`int`"""
        try:
            return cls._devices[device_id]
        except KeyError as exc:
            # try to recover from dangling state
            try:
                cls._devices[device_id] = libschc.Device.get(device_id)
                return cls._devices[device_id]  # pragma: no cover
            except KeyError:
                raise exc  # pylint: disable=raise-missing-from

    @classmethod
    def iter(cls) -> typing.Generator[Device]:
        """Iterates over all devices deployed in libSCHC."""
        for _, device in sorted(cls._devices.items()):
            yield device

    @property
    def __inner__(self):
        return self._inner

    @property
    def compression_rules(self) -> typing.List[rules.CompressionRule]:
        """The compression rules of this device.

        If they are set to None, the internal compression context of the libSCHC version
        of this device will be free'd and its rule count set to 0. If it is set to a
        list of compression rules, the context will be updated accordingly.
        """
        if self._compression_rules is None:
            self._compression_rules = [
                rules.CompressionRule(**r) for r in self._inner.compression_rules
            ]
        return self._compression_rules

    @compression_rules.setter
    def compression_rules(
        self, compression_rules: typing.Optional[typing.List[rules.CompressionRule]]
    ):
        if compression_rules is None:
            del self._inner.compression_rules
        else:
            self._inner.compression_rules = [r.dict() for r in compression_rules or []]
        self._compression_rules = None

    @property
    def device_id(self) -> int:
        """The libSCHC-internal identifier of the device."""
        try:
            return self._inner.device_id
        except AttributeError as exc:  # pragma: no cover, only happens on init error
            raise AttributeError(
                f"{type(self).__name__} has no attribute 'device_id'"
            ) from exc

    @property
    def fragmentation_rules(self) -> typing.List[rules.FragmentationRule]:
        """The fragmentation rules of this device.

        If they are set to None, the internal fragmentation context of the libSCHC
        version of this device will be free'd and its rule count set to 0. If it is set
        to a list of fragmentation rules, the context will be updated accordingly.
        """
        if self._fragmentation_rules is None:
            self._fragmentation_rules = [
                rules.FragmentationRule(**r) for r in self._inner.fragmentation_rules
            ]
        return self._fragmentation_rules

    @fragmentation_rules.setter
    def fragmentation_rules(
        self, fragmentation_rules: typing.Optional[typing.List[rules.FragmentationRule]]
    ):
        if fragmentation_rules is None:
            del self._inner.fragmentation_rules
        else:
            self._inner.fragmentation_rules = [r.dict() for r in fragmentation_rules]
        self._fragmentation_rules = None

    @property
    def uncompressed_rule(self) -> rules.UncompressedRule:
        """The rule for uncompressed packets on this device..

        If this is set to None, the internal rule ID will be set to 0 and its bit size
        to 0. Otherwise, the rule will be updated accordingly.
        """
        if (
            self._uncompressed_rule is None
            and self._inner.uncompressed_rule_id_size_bits > 0
        ):
            self._uncompressed_rule = rules.UncompressedRule(
                rule_id=self._inner.uncompressed_rule_id,
                rule_id_size_bits=self._inner.uncompressed_rule_id_size_bits,
            )
        return self._uncompressed_rule

    @uncompressed_rule.setter
    def uncompressed_rule(
        self, uncompressed_rule: typing.Optional[rules.UncompressedRule]
    ):
        if uncompressed_rule:
            self._inner.uncompressed_rule_id = uncompressed_rule.rule_id
            self._inner.uncompressed_rule_id_size_bits = (
                uncompressed_rule.rule_id_size_bits
            )
        else:
            self._inner.uncompressed_rule_id = 0
            self._inner.uncompressed_rule_id_size_bits = 0
        self._uncompressed_rule = None

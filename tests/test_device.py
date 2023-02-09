# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import pytest

import pylibschc.device  # pylint: disable=import-error
import pylibschc.rules  # pylint: disable=import-error

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


# pylint: disable=R0801
def test_device_init():
    with pytest.raises(ValueError):
        pylibschc.device.Device(0, 50, 5000)
    device = pylibschc.device.Device(1, 50, 5000)
    assert device == pylibschc.device.Device(1, 50, 5000)


def test_device_delete():
    # test what happens if device does not exist (it should be nothing)
    pylibschc.device.Device.delete(1)
    old_device = pylibschc.device.Device(1, 50, 5000)
    pylibschc.device.Device.delete(1)
    with pytest.raises(KeyError):
        pylibschc.device.Device.get(1)
    new_device = pylibschc.device.Device(1, 50, 5000)
    assert old_device != new_device
    # test idempotency
    pylibschc.device.Device.delete(1)


def test_device_get():
    with pytest.raises(KeyError):
        pylibschc.device.Device.get(1)
    init_device = pylibschc.device.Device(1, 50, 5000)
    get_device = pylibschc.device.Device.get(1)
    assert init_device == get_device


def test_device_iter():
    devices = []
    for i in range(1, 12):
        devices.append(pylibschc.device.Device(i, 50, 5000))
    for device, iter_device in zip(devices, pylibschc.device.Device.iter()):
        assert device == iter_device


def test_device_compression_rules():
    device = pylibschc.device.Device(1, 50, 5000)
    compression_rules = [
        pylibschc.rules.CompressionRule(
            rule_id=1,
            rule_id_size_bits=8,
            ipv6_rule=[
                pylibschc.rules.CompressionRuleField(
                    field="IP6_TC",
                    MO_param_length=0,
                    field_length=8,
                    field_pos=1,
                    dir="BI",
                    MO="ignore",
                    action="NotSent",
                ),
                pylibschc.rules.CompressionRuleField(
                    field="IP6_NH",
                    MO_param_length=2,
                    field_length=8,
                    field_pos=1,
                    dir="BI",
                    target_value=[17, 58],
                    MO="matchmap",
                    action="mappingSent",
                ),
            ],
            coap_rule=[
                pylibschc.rules.CompressionRuleField(
                    field="COAP_TKL",
                    MO_param_length=0,
                    field_length=4,
                    field_pos=1,
                    dir="BI",
                    target_value=4,
                    MO="EQUAL",
                    action="NOTSENT",
                ),
            ],
        )
    ]
    assert not device.compression_rules
    device.compression_rules = compression_rules
    assert device.compression_rules == compression_rules
    # check caching
    assert device.compression_rules == compression_rules
    device.compression_rules = None
    assert not device.compression_rules


def test_device_device_id():
    device = pylibschc.device.Device(60182, 50, 5000)
    assert device.device_id == 60182


def test_device_fragmentation_rules():
    device = pylibschc.device.Device(1, 50, 5000)
    fragmentation_rules = [
        pylibschc.rules.FragmentationRule(
            rule_id=22,
            rule_id_size_bits=8,
            mode="ACK_ON_ERROR",
            dir="BI",
            FCN_SIZE=3,
            MAX_WND_FCN=6,
            WINDOW_SIZE=1,
            DTAG_SIZE=0,
        ),
        pylibschc.rules.FragmentationRule(
            rule_id=23,
            rule_id_size_bits=8,
            mode="ACK_ALWAYS",
            dir="BI",
            FCN_SIZE=3,
            MAX_WND_FCN=6,
            WINDOW_SIZE=1,
            DTAG_SIZE=0,
        ),
    ]
    assert not device.fragmentation_rules
    device.fragmentation_rules = fragmentation_rules
    assert device.fragmentation_rules == fragmentation_rules
    # check caching
    assert device.fragmentation_rules == fragmentation_rules
    device.fragmentation_rules = None
    assert not device.fragmentation_rules


def test_device_uncompressed_rule():
    device = pylibschc.device.Device(1, 50, 5000)
    uncompressed_rule = pylibschc.rules.UncompressedRule(
        rule_id=21, rule_id_size_bits=8
    )
    assert not device.uncompressed_rule
    device.uncompressed_rule = uncompressed_rule
    assert device.uncompressed_rule == uncompressed_rule
    # check caching
    assert device.uncompressed_rule == uncompressed_rule
    device.uncompressed_rule = None
    assert not device.uncompressed_rule

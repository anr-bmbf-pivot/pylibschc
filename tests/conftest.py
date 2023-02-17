# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import os
import pathlib
import subprocess

import pytest

import pylibschc.rules


__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


@pytest.fixture(autouse=True)
def reset_devices():
    yield
    device_ids = []
    # get all device ids to not change Device internals during iteration
    for device in pylibschc.device.Device.iter():
        device_ids.append(device.device_id)
    for device_id in device_ids:
        pylibschc.device.Device.delete(device_id)


# pylint: disable=R0801
@pytest.fixture
def test_rules():
    ipv6_rule1 = [
        pylibschc.rules.CompressionRuleField(
            field="IP6_V",
            field_length=4,
            dir="BI",
            target_value=6,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_TC",
            field_length=8,
            dir="BI",
            MO="mo_ignore",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_FL",
            field_length=20,
            dir="BI",
            MO="mo_ignore",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_LEN",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPLENGTH",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_NH",
            field_length=8,
            dir="BI",
            target_value=17,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_HL",
            field_length=8,
            dir="UP",
            target_value=64,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_HL",
            field_length=8,
            dir="DOWN",
            MO="mo_ignore",
            action="VALUESENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_DEVPRE",
            field_length=64,
            dir="BI",
            target_value="2001:db8::/64",
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_DEVIID",
            field_length=64,
            dir="BI",
            target_value="::1",
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_APPPRE",
            MO_param_length=4,
            field_length=64,
            dir="BI",
            target_value=[
                "2001:db8:1::",
                "2001:db8:2::",
                "2001:db8:3::",
                "2001:db8:4::",
            ],
            MO="mo_matchmap",
            action="MAPPINGSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_APPIID",
            field_length=64,
            dir="BI",
            target_value="::2",
            MO="mo_equal",
            action="NOTSENT",
        ),
    ]
    ipv6_rule2 = [
        pylibschc.rules.CompressionRuleField(
            field="IP6_V",
            field_length=4,
            dir="BI",
            target_value=6,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_TC",
            field_length=8,
            dir="BI",
            MO="mo_ignore",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_FL",
            field_length=20,
            dir="BI",
            MO="mo_ignore",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_LEN",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPLENGTH",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_NH",
            MO_param_length=2,
            field_length=8,
            dir="BI",
            target_value=[17, 58],
            MO="mo_matchmap",
            action="MAPPINGSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_HL",
            MO_param_length=2,
            field_length=8,
            dir="BI",
            target_value=[64, 255],
            MO="mo_matchmap",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_DEVPRE",
            field_length=64,
            dir="BI",
            target_value="fe80::/64",
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_DEVIID",
            MO_param_length=62,
            field_length=64,
            dir="BI",
            target_value="::1",
            MO="mo_MSB",
            action="LSB",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_APPPRE",
            field_length=64,
            dir="BI",
            target_value="fe80::/64",
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="IP6_APPIID",
            MO_param_length=62,
            field_length=64,
            dir="BI",
            target_value="::1",
            MO="mo_MSB",
            action="LSB",
        ),
    ]
    udp_rule1 = [
        pylibschc.rules.CompressionRuleField(
            field="UDP_DEV",
            MO_param_length=2,
            field_length=16,
            dir="BI",
            target_value=[5683, 5684],
            MO="mo_matchmap",
            action="MAPPINGSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_APP",
            MO_param_length=2,
            field_length=16,
            dir="BI",
            target_value=[5683, 5684],
            MO="mo_matchmap",
            action="MAPPINGSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_LEN",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPLENGTH",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_CHK",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPCHK",
        ),
    ]
    udp_rule2 = [
        pylibschc.rules.CompressionRuleField(
            field="UDP_DEV",
            MO_param_length=12,
            field_length=16,
            dir="BI",
            target_value=8000,
            MO="mo_MSB",
            action="LSB",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_APP",
            MO_param_length=12,
            field_length=16,
            dir="BI",
            target_value=8000,
            MO="mo_MSB",
            action="LSB",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_LEN",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPLENGTH",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_CHK",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPCHK",
        ),
    ]
    udp_rule3 = [
        pylibschc.rules.CompressionRuleField(
            field="UDP_DEV",
            field_length=16,
            dir="BI",
            target_value=5001,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_APP",
            field_length=16,
            dir="BI",
            target_value=5000,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_LEN",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPLENGTH",
        ),
        pylibschc.rules.CompressionRuleField(
            field="UDP_CHK",
            field_length=16,
            dir="BI",
            MO="mo_ignore",
            action="COMPCHK",
        ),
    ]
    coap_rule1 = [
        pylibschc.rules.CompressionRuleField(
            field="COAP_V",
            field_length=2,
            dir="BI",
            target_value=1,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_T",
            field_length=2,
            dir="BI",
            target_value=1,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_TKL",
            field_length=4,
            dir="BI",
            target_value=4,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_C",
            field_length=8,
            dir="BI",
            target_value=3,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_MID",
            MO_param_length=12,
            field_length=16,
            dir="BI",
            target_value=0x23B0,
            MO="mo_MSB",
            action="LSB",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_TKN",
            MO_param_length=24,
            field_length=32,
            dir="BI",
            target_value=0x21FA0100,
            MO="mo_MSB",
            action="LSB",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_URIPATH",
            field_length=40,
            dir="BI",
            target_value="usage",
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_NORESP",
            field_length=8,
            dir="BI",
            target_value=0x1A,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_PAYLOAD",
            field_length=8,
            dir="BI",
            target_value=0xFF,
            MO="mo_equal",
            action="NOTSENT",
        ),
    ]
    coap_rule2 = [
        pylibschc.rules.CompressionRuleField(
            field="COAP_V",
            field_length=2,
            dir="BI",
            target_value=1,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_T",
            field_length=2,
            dir="BI",
            target_value=1,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_TKL",
            field_length=4,
            dir="BI",
            target_value=4,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_C",
            field_length=8,
            dir="UP",
            target_value=0x45,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_C",
            field_length=8,
            dir="DOWN",
            target_value=0x1,
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_MID",
            MO_param_length=12,
            field_length=16,
            dir="UP",
            target_value=0x23B0,
            MO="mo_MSB",
            action="LSB",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_MID",
            field_length=16,
            dir="DOWN",
            MO="mo_ignore",
            action="VALUESENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_TKN",
            field_length=32,
            dir="BI",
            MO="mo_ignore",
            action="VALUESENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_URIPATH",
            field_length=32,
            dir="DOWN",
            target_value="temp",
            MO="mo_equal",
            action="NOTSENT",
        ),
        pylibschc.rules.CompressionRuleField(
            field="COAP_PAYLOAD",
            field_length=8,
            dir="BI",
            target_value=0xFF,
            MO="mo_equal",
            action="NOTSENT",
        ),
    ]
    coap_rule3 = [
        pylibschc.rules.CompressionRuleField(
            field="COAP_V",
            field_length=2,
            dir="BI",
            target_value=1,
            MO="mo_equal",
            action="NOTSENT",
        ),
    ]
    compression_rules = [
        pylibschc.rules.CompressionRule(
            rule_id=1,
            rule_id_size_bits=8,
            ipv6_rule=ipv6_rule1,
            udp_rule=udp_rule1,
            coap_rule=coap_rule1,
        ),
        pylibschc.rules.CompressionRule(
            rule_id=2,
            rule_id_size_bits=8,
            ipv6_rule=ipv6_rule1,
            udp_rule=udp_rule2,
            coap_rule=coap_rule2,
        ),
        pylibschc.rules.CompressionRule(
            rule_id=3,
            rule_id_size_bits=8,
            ipv6_rule=ipv6_rule2,
            udp_rule=udp_rule3,
            coap_rule=coap_rule3,
        ),
        pylibschc.rules.CompressionRule(
            rule_id=4,
            rule_id_size_bits=8,
            ipv6_rule=ipv6_rule2,
            udp_rule=None,
            coap_rule=None,
        ),
    ]
    fragmentation_rules = [
        pylibschc.rules.FragmentationRule(
            rule_id=21,
            rule_id_size_bits=8,
            mode="NO_ACK",
            dir="BI",
            FCN_SIZE=1,
            MAX_WND_FCN=0,
            WINDOW_SIZE=0,
            DTAG_SIZE=0,
        ),
        pylibschc.rules.FragmentationRule(
            rule_id=22,
            rule_id_size_bits=8,
            mode="ACK_ON_ERROR",
            dir="BI",
            FCN_SIZE=6,
            MAX_WND_FCN=62,
            WINDOW_SIZE=2,
            DTAG_SIZE=0,
        ),
        pylibschc.rules.FragmentationRule(
            rule_id=23,
            rule_id_size_bits=8,
            mode="ACK_ALWAYS",
            dir="BI",
            FCN_SIZE=6,
            MAX_WND_FCN=62,
            WINDOW_SIZE=2,
            DTAG_SIZE=0,
        ),
    ]
    config = pylibschc.rules.Config(
        devices=[
            pylibschc.rules.Device(
                device_id=1,
                mtu=60,
                duty_cycle=100,
                uncompressed_rule=pylibschc.rules.UncompressedRule(
                    rule_id=20, rule_id_size_bits=8
                ),
                compression_rules=compression_rules,
                fragmentation_rules=fragmentation_rules,
            ),
            pylibschc.rules.Device(
                device_id=2,
                mtu=60,
                duty_cycle=100,
                uncompressed_rule=pylibschc.rules.UncompressedRule(
                    rule_id=20, rule_id_size_bits=8
                ),
                compression_rules=compression_rules,
                fragmentation_rules=fragmentation_rules,
            ),
            pylibschc.rules.Device(
                device_id=3,
                mtu=500,
                duty_cycle=5000,
                uncompressed_rule=pylibschc.rules.UncompressedRule(
                    rule_id=0, rule_id_size_bits=8
                ),
                compression_rules=compression_rules[:-1],
                fragmentation_rules=fragmentation_rules[:-1],
            ),
            pylibschc.rules.Device(
                device_id=4,
                mtu=500,
                duty_cycle=5000,
                uncompressed_rule=pylibschc.rules.UncompressedRule(
                    rule_id=20, rule_id_size_bits=6
                ),
                fragmentation_rules=[
                    pylibschc.rules.FragmentationRule(
                        rule_id=22,
                        rule_id_size_bits=8,
                        mode="NO_ACK",
                        dir="UP",
                        FCN_SIZE=1,
                    )
                ],
            ),
            pylibschc.rules.Device(
                device_id=5,
                mtu=500,
                duty_cycle=5000,
            ),
        ],
    )
    yield config
    deployed = config.deploy()
    for device in list(deployed.devices):
        device.compression_rules = None
        device.fragmentation_rules = None
        device.uncompressed_rule = None
        deployed.devices.remove(device)
        del device


@pytest.fixture
def schc_config(request):
    testconf_dir = pathlib.Path(os.path.dirname(request.module.__file__))
    return (testconf_dir / ".." / "src" / "schc_config.h").absolute()


@pytest.fixture
def libschc_repo(request, tmp_path):  # pragma: no cover
    testconf_dir = pathlib.Path(os.path.dirname(request.module.__file__))
    submodule_dir = (testconf_dir / ".." / "src" / "libschc").absolute()
    if (submodule_dir / "examples" / "makefile").exists():
        return submodule_dir
    repo_dir = testconf_dir / ".."
    try:
        subprocess.check_call(
            ["git", "-C", str(repo_dir), "subprocess", "update", "--init"]
        )
    except subprocess.CalledProcessError:
        subprocess.check_call(
            [
                "git",
                "-C",
                str(tmp_path),
                "clone",
                "https://github.com/imec-idlab/libschc.git",
                "libschc",
            ]
        )
        return (tmp_path / "libschc").absolute()
    return submodule_dir

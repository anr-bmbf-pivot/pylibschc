# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import os
import shutil
import subprocess
import typing

from pydantic import BaseModel, ValidationError
import pytest

import pylibschc.rules
from pylibschc._pydantic import EnumByName

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


# pylint: disable=R0801,too-many-lines
def check_model(model: BaseModel, input_dict: dict, exp: typing.Union[dict, Exception]):
    if isinstance(exp, dict):
        obj = model(**input_dict)
        assert obj.dict() == exp
        # check case insensitivity for _pydantic.EnumByName and equality of two
        # different objects
        assert obj == model(
            **{
                k: v.upper()
                if isinstance(v, str) and isinstance(getattr(obj, k), EnumByName)
                else v
                for k, v in input_dict.items()
            }
        )
        # check JSON and Schema JSON to test _pydantic.EnumByName functionality
        try:
            json = obj.json()
            schema_json = obj.schema_json()
            for value in obj.dict().values():
                if isinstance(value, EnumByName):
                    assert f'"{value.name}"' in json
                    assert f'"{value.name}"' in schema_json
        except UnicodeDecodeError:
            # skip on unicode decode error. May happen when IPv6 addresses are tried
            # to be converted; May be removed later if fixed...
            pass
    else:
        with pytest.raises(exp):
            model(**input_dict)


@pytest.mark.parametrize(
    "input_dict, exp",
    [
        pytest.param(
            {
                "field": "IP6_LEN",
                "MO_param_length": 0,
                "field_length": 16,
                "field_pos": 1,
                "dir": "BI",
                "target_value": b"\x00\x00",
                "MO": "MO_THEBARKEEP",
                "action": "COMPLENGTH",
            },
            ValidationError,
            id="Invalid Enum value",
        ),
        pytest.param(
            {
                "field": "IP6_LEN",
                "MO_param_length": 0,
                "field_length": 16,
                "field_pos": 1,
                "dir": "BI",
                "target_value": b"\x00\x00\x00",
                "MO": "MO_IGNORE",
                "action": "COMPLENGTH",
            },
            ValidationError,
            id="target_value bytes longer than field_length bits",
        ),
        pytest.param(
            {
                "field": "IP6_V",
                "MO_param_length": 0,
                "field_length": 4,
                "field_pos": 1,
                "dir": "BI",
                "target_value": 0b00011111,  # 0b0001|1111
                "MO": "MO_IGNORE",
                "action": "NOTSENT",
            },
            ValidationError,
            id="target_value int overflows field_length bits",
        ),
        pytest.param(
            {
                "field": "IP6_V",
                "MO_param_length": 0,
                "field_length": 4,
                "field_pos": 1,
                "dir": "BI",
                "target_value": 0x10F,
                "MO": "MO_IGNORE",
                "action": "NOTSENT",
            },
            ValidationError,
            id="target_value int in bytes longer than field_length bits",
        ),
        pytest.param(
            {
                "field": "IP6_NH",
                "MO_param_length": 1,
                "field_length": 8,
                "field_pos": 1,
                "dir": "BI",
                "target_value": [17, 58],
                "MO": "MATCHMAP",
                "action": "MAPPINGSENT",
            },
            ValidationError,
            id="MO_param_length < target_value list with MATCHMAP/MAPPINGSENT",
        ),
        pytest.param(
            {
                "field": "IP6_NH",
                "MO_param_length": 3,
                "field_length": 8,
                "field_pos": 1,
                "dir": "BI",
                "target_value": [17, 58],
                "MO": "MATCHMAP",
                "action": "MAPPINGSENT",
            },
            ValidationError,
            id="MO_param_length > target_value list with MATCHMAP/MAPPINGSENT",
        ),
        pytest.param(
            {
                "field": "UDP_DEV",
                "MO_param_length": 18,
                "field_length": 16,
                "field_pos": 1,
                "dir": "BI",
                "target_value": 0xF0B0,
                "MO": "MSB",
                "action": "LSB",
            },
            ValidationError,
            id="MO_param_length > field_length with MSB/LSB",
        ),
        pytest.param(
            {
                "field": "Ip6_Devpre",
                "MO_param_length": 0,
                "field_length": 16,
                "dir": "Bi",
                "target_value": "fe80:1::",
                "MO": "equal",
                "action": "Notsent",
            },
            ValidationError,
            id=("IPv6 address target_value with prefix too long"),
        ),
        pytest.param(
            {
                "field": "Ip6_Deviid",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": "::1:0:0:0:1",
                "MO": "equal",
                "action": "Notsent",
            },
            ValidationError,
            id=("IPv6 address target_value with suffix bytes too long"),
        ),
        pytest.param(
            {
                "field": "Ip6_Deviid",
                "MO_param_length": 0,
                "field_length": 65,
                "dir": "Bi",
                "target_value": "::3:0:0:0:1",
                "MO": "equal",
                "action": "Notsent",
            },
            ValidationError,
            id=("IPv6 address target_value with suffix bits too long"),
        ),
        pytest.param(
            {
                "field": "Ip6_HL",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": "fe80::",
                "MO": "equal",
                "action": "Notsent",
            },
            ValidationError,
            id=("IPv6 address target_value with no address field identifier"),
        ),
        pytest.param(
            {
                "field": "ip6_Len",
                "field_length": 16,
                "dir": "Bi",
                "MO": "mo_IgNORE",
                "action": "COMPLENGTH",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_LEN,
                "MO_param_length": 0,
                "field_length": 16,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x00\x00",
                "MO": pylibschc.rules.MO.IGNORE,
                "action": pylibschc.rules.CDA.COMPLENGTH,
            },
            id="Success: use defaults",
        ),
        pytest.param(
            {
                "field": "Ip6_DevPre",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": b"\xFE\x80\x00\x00\x00\x00\x00\x00",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVPRE,
                "MO_param_length": 0,
                "field_length": 64,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\xFE\x80\x00\x00\x00\x00\x00\x00",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id="Success: full-byte field_length with bytes target_value",
        ),
        pytest.param(
            {
                "field": "CoAP_URIpath",
                "field_length": 40,
                "dir": "DOWN",
                "target_value": "usage",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.COAP_URIPATH,
                "MO_param_length": 0,
                "field_length": 40,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.DOWN,
                "target_value": b"usage",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id="Success: full-byte field_length with string target_value",
        ),
        pytest.param(
            {
                "field": "IP6_v",
                "MO_param_length": 0,
                "field_length": 4,
                "field_pos": 1,
                "dir": "Bi",
                "target_value": 6,
                "MO": "Ignore",
                "action": "notSent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_V,
                "MO_param_length": 0,
                "field_length": 4,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x06",
                "MO": pylibschc.rules.MO.MO_IGNORE,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id="Success: sub-bits field_length with bytes target_value",
        ),
        pytest.param(
            {
                "field": "Ip6_Devpre",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": "fe80::",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVPRE,
                "MO_param_length": 0,
                "field_length": 64,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\xFE\x80\x00\x00\x00\x00\x00\x00",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id=(
                "Success: full-byte field_length with IPv6 address target_value with "
                "prefix field"
            ),
        ),
        pytest.param(
            {
                "field": "Ip6_DevPRE",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": "fe80::/54",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVPRE,
                "MO_param_length": 0,
                "field_length": 64,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\xFE\x80\x00\x00\x00\x00\x00\x00",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id=(
                "Success: full-byte field_length with IPv6 prefix target_value with "
                "prefix field"
            ),
        ),
        pytest.param(
            {
                "field": "Ip6_Devpre",
                "MO_param_length": 0,
                "field_length": 9,
                "dir": "Bi",
                "target_value": "fe80::",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVPRE,
                "MO_param_length": 0,
                "field_length": 9,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\xFE\x80",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id=(
                "Success: sub-bits field_length with IPv6 address target_value with "
                "prefix field"
            ),
        ),
        pytest.param(
            {
                "field": "Ip6_DevIID",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": "::1",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVIID,
                "MO_param_length": 0,
                "field_length": 64,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x00\x00\x00\x00\x00\x00\x00\x01",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id=(
                "Success: full-byte field_length with IPv6 address target_value with "
                "IID field"
            ),
        ),
        pytest.param(
            {
                "field": "Ip6_DevIID",
                "MO_param_length": 0,
                "field_length": 64,
                "dir": "Bi",
                "target_value": "::1/64",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVIID,
                "MO_param_length": 0,
                "field_length": 64,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x00\x00\x00\x00\x00\x00\x00\x01",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id=(
                "Success: full-byte field_length with IPv6 prefix target_value with "
                "IID field"
            ),
        ),
        pytest.param(
            {
                "field": "Ip6_DevIID",
                "MO_param_length": 0,
                "field_length": 2,
                "dir": "Bi",
                "target_value": "::1",
                "MO": "equal",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_DEVIID,
                "MO_param_length": 0,
                "field_length": 2,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x01",
                "MO": pylibschc.rules.MO.EQUAL,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id=(
                "Success: sub-bits field_length with IPv6 address target_value with "
                "IID field"
            ),
        ),
        pytest.param(
            {
                "field": "udp_app",
                "MO_param_length": 2,
                "field_length": 16,
                "field_pos": 1,
                "dir": "Bi",
                "target_value": [5683, 5684],
                "MO": "MO_MATCHMAP",
                "action": "MAPPINGSENT",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.UDP_APP,
                "MO_param_length": 2,
                "field_length": 16,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x16\x33\x16\x34",
                "MO": pylibschc.rules.MO.MO_MATCHMAP,
                "action": pylibschc.rules.CDA.MAPPINGSENT,
            },
            id="Success: Mapping values as target_value list with MAPPINGSENT",
        ),
        pytest.param(
            {
                "field": "Ip6_nh",
                "MO_param_length": 3,
                "field_length": 8,
                "field_pos": 1,
                "dir": "bi",
                "target_value": b"\x11\x3a\x06",
                "MO": "MO_MATCHMAP",
                "action": "mappingsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_NH,
                "MO_param_length": 3,
                "field_length": 8,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x11\x3a\x06",
                "MO": pylibschc.rules.MO.MO_MATCHMAP,
                "action": pylibschc.rules.CDA.MAPPINGSENT,
            },
            id="Success: Mapping values as bytes target_value with MAPPINGSENT",
        ),
        pytest.param(
            {
                "field": "Ip6_HL",
                "MO_param_length": 2,
                "field_length": 8,
                "field_pos": 1,
                "dir": "Bi",
                "target_value": [b"\x40", b"\xff"],
                "MO": "MO_MATCHMAP",
                "action": "Notsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_HL,
                "MO_param_length": 2,
                "field_length": 8,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\x40\xff",
                "MO": pylibschc.rules.MO.MO_MATCHMAP,
                "action": pylibschc.rules.CDA.NOTSENT,
            },
            id="Success: Mapping values as target_value list with NOTSENT",
        ),
        pytest.param(
            {
                "field": "Ip6_appPre",
                "MO_param_length": 4,
                "field_length": 44,
                "dir": "bi",
                "target_value": [
                    "2001:db8:10::",
                    "2001:db8:20::/64",
                    "2001:db8:30::/44",
                    "2001:db8:40::/48",
                ],
                "MO": pylibschc.rules.MO.MATCHMAP,
                "action": "mappingsent",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.IP6_APPPRE,
                "MO_param_length": 4,
                "field_length": 44,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": bytes(
                    # fmt: off
                    [
                        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x10,
                        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x20,
                        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x30,
                        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x40,
                    ]
                    # fmt: on
                ),
                "MO": pylibschc.rules.MO.MO_MATCHMAP,
                "action": pylibschc.rules.CDA.MAPPINGSENT,
            },
            id="Success: Mapping values as target_value IPv6 list with MAPPINGSENT",
        ),
        pytest.param(
            {
                "field": "udp_dev",
                "MO_param_length": 12,
                "field_length": 16,
                "field_pos": 1,
                "dir": "Bi",
                "target_value": 0xF0B0,
                "MO": "MSB",
                "action": "LSB",
            },
            {
                "field": pylibschc.rules.HeaderFieldID.UDP_DEV,
                "MO_param_length": 12,
                "field_length": 16,
                "field_pos": 1,
                "dir": pylibschc.rules.Direction.BI,
                "target_value": b"\xF0\xB0",
                "MO": pylibschc.rules.MO.MO_MSB,
                "action": pylibschc.rules.CDA.LSB,
            },
            id="Success: MSB/LSB MO_param_length",
        ),
    ],
)
def test_compression_rule_field(input_dict: dict, exp: typing.Union[dict, Exception]):
    check_model(pylibschc.rules.CompressionRuleField, input_dict, exp)


@pytest.mark.parametrize(
    "field, decl_str",
    [
        # pylint: disable=line-too-long
        pytest.param(
            pylibschc.rules.CompressionRuleField(
                field="IP6_V",
                field_length=4,
                dir="BI",
                target_value=6,
                MO="IGNORE",
                action="NOTSENT",
            ),
            "{ IP6_V,             0,   4,   1, BI,   {0x06},             &mo_ignore,     NOTSENT     }",  # noqa: E501
        ),
        pytest.param(
            pylibschc.rules.CompressionRuleField(
                field="IP6_FL",
                field_length=20,
                dir="BI",
                MO="IGNORE",
                action="NOTSENT",
            ),
            "{ IP6_FL,            0,  20,   1, BI,   {0x00, 0x00, 0x00}, &mo_ignore,     NOTSENT     }",  # noqa: E501
        ),
        pytest.param(
            pylibschc.rules.CompressionRuleField(
                field="IP6_DEVPRE",
                MO_param_length=44,
                field_length=104,
                dir="BI",
                target_value="2001:db8:1::/64",
                MO="MSB",
                action="LSB",
            ),
            """{ IP6_DEVPRE,       44, 104,   1, BI,   {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    },                                                      &mo_MSB,        LSB         }""",  # noqa: E501
        ),
        pytest.param(
            pylibschc.rules.CompressionRuleField(
                field="IP6_DEVPRE",
                MO_param_length=4,
                field_length=44,
                dir="BI",
                target_value=[
                    "2001:db8:10::",
                    "2001:db8:20::",
                    "2001:db8:30::",
                    "2001:db8:40::",
                ],
                MO="MATCHMAP",
                action="MAPPINGSENT",
            ),
            """{ IP6_DEVPRE,        4,  44,   1, BI,   {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x20,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x30,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x40
    },                                                      &mo_matchmap,   MAPPINGSENT }""",  # noqa: E501
        ),
    ],
)
def test_compression_rule_field_c_schc_field_declaration(field, decl_str):
    assert field.c_schc_field_declaration() == decl_str


@pytest.mark.parametrize(
    "input_dict, exp",
    [
        pytest.param({}, ValidationError, id="No Rule-ID"),
        pytest.param(
            {
                "rule_id": 0x1F,
                "rule_id_size_bits": 4,
            },
            ValidationError,
            id="Rule-ID does not fit Rule-ID size bits",
        ),
        pytest.param(
            {
                "rule_id": 2,
                "rule_id_size_bits": 4,
                "ipv6_rule": [
                    {
                        "field": "COAP_V",
                        "MO_param_length": 0,
                        "field_length": 16,
                        "field_pos": 1,
                        "dir": "BI",
                        "MO": "IGNORE",
                        "action": "COMPLENGTH",
                    },
                ],
            },
            ValidationError,
            id="CoAP field in IPv6 rule",
        ),
        pytest.param(
            {
                "rule_id": 2,
                "rule_id_size_bits": 4,
                "udp_rule": [
                    {
                        "field": "IP6_V",
                        "MO_param_length": 0,
                        "field_length": 4,
                        "field_pos": 1,
                        "dir": "BI",
                        "target_value": 6,
                        "MO": "IGNORE",
                        "action": "NOTSENT",
                    },
                ],
            },
            ValidationError,
            id="IPv6 field in UDP rule",
        ),
        pytest.param(
            {
                "rule_id": 2,
                "rule_id_size_bits": 4,
                "coap_rule": [
                    {
                        "field": "udp_app",
                        "MO_param_length": 2,
                        "field_length": 16,
                        "field_pos": 1,
                        "dir": "Bi",
                        "target_value": [5683, 5684],
                        "MO": "MO_MATCHMAP",
                        "action": "MAPPINGSENT",
                    },
                ],
            },
            ValidationError,
            id="UDP field in CoAP rule",
        ),
        pytest.param(
            {
                "rule_id": 2,
                "rule_id_size_bits": 4,
                "coap_rule": [],
                "ipv6_rule": [
                    {
                        "field": "IP6_LEN",
                        "MO_param_length": 0,
                        "field_length": 16,
                        "field_pos": 1,
                        "dir": "BI",
                        "MO": "IGNORE",
                        "action": "COMPLENGTH",
                    },
                ],
            },
            {
                "rule_id": 2,
                "rule_id_size_bits": 4,
                "ipv6_rule": [
                    {
                        "field": pylibschc.rules.HeaderFieldID.IP6_LEN,
                        "MO_param_length": 0,
                        "field_length": 16,
                        "field_pos": 1,
                        "dir": pylibschc.rules.Direction.BI,
                        "target_value": b"\x00\x00",
                        "MO": pylibschc.rules.MO.IGNORE,
                        "action": pylibschc.rules.CDA.COMPLENGTH,
                    },
                ],
                "udp_rule": None,
                "coap_rule": None,
            },
            id="Success",
        ),
    ],
)
def test_compression_rule(input_dict, exp):
    check_model(pylibschc.rules.CompressionRule, input_dict, exp)


def check_rule_declaration_output(c_decl, exp_decl_str):
    assert c_decl == exp_decl_str


def test_compression_rule_c_schc_layer_rule_declaration_no_layer_rule():
    rule = pylibschc.rules.CompressionRule(
        rule_id=1,
        rule_id_size_bits=2,
    )
    exp_decl_str = ""
    check_rule_declaration_output(rule.c_schc_ipv6_rule_declaration(), exp_decl_str)
    check_rule_declaration_output(rule.c_schc_udp_rule_declaration(), exp_decl_str)
    check_rule_declaration_output(rule.c_schc_coap_rule_declaration(), exp_decl_str)


def test_compression_rule_c_schc_ipv6_rule_declaration():
    rule = pylibschc.rules.CompressionRule(
        rule_id=1,
        rule_id_size_bits=2,
        ipv6_rule=[
            pylibschc.rules.CompressionRuleField(
                field="IP6_V",
                field_length=4,
                dir="BI",
                target_value=6,
                MO="mo_equal",
                action="NOTSENT",
            ),
            pylibschc.rules.CompressionRuleField(
                field="IP6_LEN",
                field_length=16,
                dir="BI",
                MO="mo_ignore",
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
                target_value="fe80::/64",
                MO="mo_equal",
                action="NOTSENT",
            ),
        ],
    )
    # pylint: disable=line-too-long
    exp_decl_str = """{
    .up = 4, .down = 4, .length = 5,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { IP6_V,             0,   4,   1, BI,   {0x06},             &mo_equal,      NOTSENT     },
        { IP6_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     NOTSENT     },
        { IP6_HL,            0,   8,   1, UP,   {0x40},             &mo_equal,      NOTSENT     },
        { IP6_HL,            0,   8,   1, DOWN, {0x00},             &mo_ignore,     VALUESENT   },
        { IP6_DEVPRE,        0,  64,   1, BI,   {
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            },                                                      &mo_equal,      NOTSENT     }
    }
}"""  # noqa: E501
    check_rule_declaration_output(rule.c_schc_ipv6_rule_declaration(), exp_decl_str)


def test_compression_rule_c_schc_udp_rule_declaration():
    rule = pylibschc.rules.CompressionRule(
        rule_id=1,
        rule_id_size_bits=2,
        udp_rule=[
            pylibschc.rules.CompressionRuleField(
                field="UDP_DEV",
                MO_param_length=12,
                field_length=16,
                dir="BI",
                target_value=61616,
                MO="mo_MSB",
                action="LSB",
            ),
            pylibschc.rules.CompressionRuleField(
                field="UDP_APP",
                MO_param_length=12,
                field_length=16,
                dir="BI",
                target_value=61616,
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
        ],
    )
    # pylint: disable=line-too-long
    exp_decl_str = """{
    .up = 4, .down = 4, .length = 4,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { UDP_DEV,          12,  16,   1, BI,   {0xf0, 0xb0},       &mo_MSB,        LSB         },
        { UDP_APP,          12,  16,   1, BI,   {0xf0, 0xb0},       &mo_MSB,        LSB         },
        { UDP_LEN,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPLENGTH  },
        { UDP_CHK,           0,  16,   1, BI,   {0x00, 0x00},       &mo_ignore,     COMPCHK     }
    }
}"""  # noqa: E501
    check_rule_declaration_output(rule.c_schc_udp_rule_declaration(), exp_decl_str)


def test_compression_rule_c_schc_coap_rule_declaration():
    rule = pylibschc.rules.CompressionRule(
        rule_id=1,
        rule_id_size_bits=2,
        coap_rule=[
            pylibschc.rules.CompressionRuleField(
                field="COAP_V",
                field_length=2,
                dir="BI",
                target_value=1,
                MO="mo_equal",
                action="NOTSENT",
            ),
        ],
    )
    # pylint: disable=line-too-long
    exp_decl_str = """{
    .up = 1, .down = 1, .length = 1,
    {
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
        { COAP_V,            0,   2,   1, BI,   {0x01},             &mo_equal,      NOTSENT     }
    }
}"""  # noqa: E501
    check_rule_declaration_output(rule.c_schc_coap_rule_declaration(), exp_decl_str)


def test_compression_rule_c_schc_declaration():
    rule = pylibschc.rules.CompressionRule(
        rule_id=1,
        rule_id_size_bits=3,
        ipv6_rule=[
            pylibschc.rules.CompressionRuleField(
                field="IP6_TC",
                field_length=8,
                dir="BI",
                MO="mo_equal",
                action="NOTSENT",
            )
        ],
        udp_rule=[
            pylibschc.rules.CompressionRuleField(
                field="UDP_LEN",
                field_length=16,
                dir="BI",
                MO="mo_ignore",
                action="COMPLENGTH",
            ),
        ],
    )
    ipv6_rule_name = "ipv6_rule01"
    udp_rule_name = "udp_rule01"
    coap_rule_name = "coap_rule01"
    exp_decl_str = """{
    .rule_id = 1U,
    .rule_id_size_bits = 3U,
#if USE_IP6
    .ipv6_rule = &ipv6_rule01,
#endif
#if USE_UDP
    .udp_rule = &udp_rule01,
#endif
#if USE_COAP
    .coap_rule = NULL,
#endif
}"""
    assert (
        rule.c_schc_compression_rule_declaration(
            ipv6_rule_name, udp_rule_name, coap_rule_name
        )
        == exp_decl_str
    )


def test_fragmentation_rule_c_schc_declaration():
    rule = pylibschc.rules.FragmentationRule(
        rule_id=21,
        rule_id_size_bits=8,
        mode="NO_ACK",
        dir="UP",
    )
    exp_decl_str = """{
    .rule_id = 21U,
    .rule_id_size_bits = 8U,
    .mode = NO_ACK,
    .dir = UP,
    .FCN_SIZE =      1U,    /* FCN field size (N in RFC) */
    .MAX_WND_FCN =   0U,    /* Maximum fragments per window (WINDOW_SIZE in RFC) */
    .WINDOW_SIZE =   0U,    /* W field size (M in RFC) */
    .DTAG_SIZE =     0U     /* DTAG field size (T in RFC) */
}"""
    assert rule.c_schc_fragmentation_rule_declaration() == exp_decl_str


def test_device_rule_id_duplicates():
    with pytest.raises(ValidationError):
        pylibschc.rules.Device(
            device_id=1,
            mtu=500,
            duty_cycle=5000,
            uncompressed_rule=pylibschc.rules.UncompressedRule(
                rule_id=20, rule_id_size_bits=8
            ),
            compression_rules=[
                pylibschc.rules.CompressionRule(rule_id=20, rule_id_size_bits=8),
            ],
        )


def test_device_uncompressed_rule_none():
    device = pylibschc.rules.Device(
        device_id=1,
        mtu=500,
        duty_cycle=5000,
        uncompressed_rule=None,
    )
    assert device.uncompressed_rule is None


def test_device_c_schc_declaration():
    device = pylibschc.rules.Device(
        device_id=1,
        mtu=500,
        duty_cycle=5000,
        uncompressed_rule=pylibschc.rules.UncompressedRule(
            rule_id=20, rule_id_size_bits=8
        ),
        fragmentation_rules=[
            pylibschc.rules.FragmentationRule(
                rule_id=22,
                rule_id_size_bits=8,
                mode="ACK_ON_ERROR",
                dir="BI",
                FCN_SIZE=6,
                MAX_WND_FCN=63,
                WINDOW_SIZE=2,
                DTAG_SIZE=0,
            ),
        ],
    )
    compression_rules_name = "compression_rules01"
    fragmentation_rules_name = "fragmentation_rules01"
    exp_decl_str = """{
    .device_id = 1U,
    .uncomp_rule_id = 20U,
    .uncomp_rule_id_size_bits = 8U,
    .compression_rule_count = 0U,
    .compression_context = NULL,
    .fragmentation_rule_count = sizeof(fragmentation_rules01) / sizeof(fragmentation_rules01[0]),
    .fragmentation_context = &fragmentation_rules01,
}"""  # noqa: E501
    assert (
        device.c_schc_device_declaration(
            compression_rules_name, fragmentation_rules_name
        )
        == exp_decl_str
    )


def test_config_duplicate_device():
    with pytest.raises(ValidationError):
        pylibschc.rules.Config(
            devices=[
                pylibschc.rules.Device(
                    device_id=1,
                    mtu=500,
                    duty_cycle=5000,
                    uncompressed_rule=pylibschc.rules.UncompressedRule(
                        rule_id=20, rule_id_size_bits=8
                    ),
                ),
                pylibschc.rules.Device(
                    device_id=1,
                    mtu=500,
                    duty_cycle=5000,
                    uncompressed_rule=pylibschc.rules.UncompressedRule(
                        rule_id=20, rule_id_size_bits=8
                    ),
                ),
            ],
        )


@pytest.fixture
def exp_rules_config(request):
    test_dir = os.path.dirname(request.module.__file__)
    with open(
        os.path.join(test_dir, "artifacts", "exp_rules_config.h"), encoding="utf-8"
    ) as rules_config:
        yield rules_config


def test_config_to_c_header(test_rules, exp_rules_config):
    # pylint: disable=redefined-outer-name
    assert test_rules.to_c_header() == exp_rules_config.read()


def test_config_to_c_header_compilable(test_rules, tmp_path, schc_config, libschc_repo):
    include_dir = tmp_path / "include"
    rules_dir = include_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(str(schc_config), str(include_dir))
    with open(rules_dir / "rule_config.h", "w", encoding="utf-8") as rules_config:
        rules_config.write(test_rules.to_c_header())
    env = os.environ
    env.update({"CFLAGS": (f"-I'{include_dir}' -I'{libschc_repo}' -DNLOGGING=1")})
    for target in ["compress", "fragment", "icmpv6"]:
        subprocess.check_call(
            [
                "make",
                "-BC",
                str(libschc_repo / "examples"),
                target,
            ],
            env=env,
        )

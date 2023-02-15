# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import pytest
from scapy.all import (  # pylint: disable=no-name-in-module
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    IPv6,
    UDP,
)
from scapy.contrib.coap import CoAP

import pylibschc.compressor

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


@pytest.fixture(autouse=True)
def reset_compressor_reassembler():
    del pylibschc.compressor.CompressorDecompressor._inner
    # pylint: disable=protected-access
    pylibschc.compressor.CompressorDecompressor._inner = None


def test_compressor_reassembler_no_uncompressed_rule(test_rules):
    test_rules.devices[0].uncompressed_rule = None
    config = test_rules.deploy()
    device = config.devices[0]
    direction = pylibschc.compressor.Direction.UP
    cr = pylibschc.compressor.CompressorDecompressor(  # pylint: disable=invalid-name
        device=device, direction=direction
    )
    bit_array = pylibschc.compressor.BitArray(bytes(IPv6()))
    res, not_compressed = cr.output(bit_array)
    assert res == pylibschc.compressor.CompressionResult.UNCOMPRESSED
    assert bytes(IPv6()) == not_compressed.buffer


@pytest.fixture()
def exp_rules(request, test_rules):
    config = test_rules.deploy()
    device = config.devices[0]
    rule = getattr(device, request.param[0])
    result = pylibschc.compressor.CompressionResult.UNCOMPRESSED
    if len(request.param) > 1:
        rule = rule[request.param[1]]
        result = pylibschc.compressor.CompressionResult.COMPRESSED
    assert rule.rule_id_size_bits == 8
    return {
        "device": device,
        "rule_id": rule.rule_id,
        "result": result,
    }


def test_compressor_reassembler_init_error(test_rules):
    config = test_rules.deploy()
    device = config.devices[0]
    with pytest.raises(ValueError):
        pylibschc.compressor.CompressorDecompressor(
            device, pylibschc.compressor.Direction.BI
        )


def test_compressor_reassembler_io_type_error(test_rules):
    config = test_rules.deploy()
    device = config.devices[0]
    cr = pylibschc.compressor.CompressorDecompressor(  # pylint: disable=invalid-name
        device, pylibschc.compressor.Direction.UP
    )
    with pytest.raises(TypeError):
        cr.output(12356)
    with pytest.raises(TypeError):
        cr.input(12356)


@pytest.mark.parametrize(
    "pkt, direction, exp_rules, exp_payload",
    [
        pytest.param(
            IPv6(),
            pylibschc.compressor.Direction.UP,
            ("uncompressed_rule",),
            bytes(IPv6()),
            id="uncompressed rule, UP",
        ),
        pytest.param(
            IPv6(),
            pylibschc.compressor.Direction.DOWN,
            ("uncompressed_rule",),
            bytes(IPv6()),
            id="uncompressed rule, DOWN",
        ),
        pytest.param(
            IPv6(hlim=64, src="2001:db8:1::2", dst="2001:db8::1")
            / UDP(
                sport=8001,
                dport=8000,
            )
            / CoAP(
                ver=1,
                code="GET",
                type="NON",
                msg_id=0x23B0,
                token=b"\x12\x34\x56\x78",
                options=[("Uri-Path", b"temp")],
                paymark=b"\xff",
            )
            / b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam",
            pylibschc.compressor.Direction.DOWN,
            ("compression_rules", 1),
            (
                b"\x40\x00\x48\xec\x04\x8d\x15\x9e\x13\x1b\xdc\x99\x5b\x48\x1a\x5c\x1c"
                b"\xdd\x5b\x48\x19\x1b\xdb\x1b\xdc\x88\x1c\xda\x5d\x08\x18\x5b\x59\x5d"
                b"\x0b\x08\x18\xdb\xdb\x9c\xd9\x5d\x19\x5d\x1d\x5c\x88\x1c\xd8\x59\x1a"
                b"\x5c\x1c\xd8\xda\x5b\x99\xc8\x19\x5b\x1a\x5d\x1c\x8b\x08\x1c\xd9\x59"
                b"\x08\x19\x1a\x58\x5b\x40"
            ),
            id="2nd rule, CoAP, DOWN",
        ),
        pytest.param(
            IPv6(hlim=64, src="fe80::1", dst="fe80::2")
            / ICMPv6EchoRequest(id=57428, seq=32838, data="Hello World!"),
            pylibschc.compressor.Direction.UP,
            ("compression_rules", 2),
            b"\xb4\x00\x06\x81\x0f\x02\xa4\x022C+ccy\x02\xbb{\x93c!\x08",
            id="3rd rule, ICMPv6, UP",
        ),
        pytest.param(
            IPv6(hlim=64, src="fe80::2", dst="fe80::1")
            / ICMPv6EchoReply(id=57428, seq=32838, data="Hello World!"),
            pylibschc.compressor.Direction.DOWN,
            ("compression_rules", 2),
            b"\xb4\x08\x06y\x0f\x02\xa4\x022C+ccy\x02\xbb{\x93c!\x08",
            id="3rd rule, ICMPv6, DOWN",
        ),
        pytest.param(
            IPv6(hlim=64, src="fe80::1", dst="fe80::2")
            / UDP(
                sport=5001,
                dport=5000,
            )
            / CoAP(),
            pylibschc.compressor.Direction.UP,
            ("compression_rules", 2),
            b"0",
            id="3rd rule, CoAP, UP",
        ),
        pytest.param(
            IPv6(hlim=64, src="fe80::2", dst="fe80::1")
            / UDP(
                sport=5000,
                dport=5001,
            )
            / CoAP(),
            pylibschc.compressor.Direction.DOWN,
            ("compression_rules", 2),
            b"0",
            id="3rd rule, CoAP, DOWN",
        ),
    ],
    indirect=["exp_rules"],
)
def test_compressor_reassembler(
    pkt, direction, exp_rules, exp_payload  # pylint: disable=redefined-outer-name
):
    device = exp_rules["device"]
    rule_id = exp_rules["rule_id"]
    exp_result = exp_rules["result"]
    pylibschc.compressor.CompressorDecompressor(device=device, direction=direction)
    # check __new__ if
    cr = pylibschc.compressor.CompressorDecompressor(  # pylint: disable=invalid-name
        device=device, direction=direction
    )
    bit_array = pylibschc.compressor.BitArray(bytes(pkt))
    comp_res = cr.output(bit_array)
    assert comp_res == cr.output(bytes(pkt))  # bytes input has same effect as BitArray
    assert comp_res[0] == exp_result
    assert comp_res[1].buffer == bytes([rule_id]) + exp_payload

    uncomp_res = cr.input(comp_res[1])
    # bytes input has same effect as BitArray
    assert uncomp_res == cr.input(comp_res[1].buffer)
    assert uncomp_res == bytes(pkt)  # decompression results in packet again

# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

"""Representation and configuration of rules."""

import argparse
import ipaddress
import struct
import typing

from pydantic import BaseModel as PydanticBaseModel  # pylint: disable=no-name-in-module
from pydantic import (
    conbytes,
    conint,
    conlist,
    validator,
)

import pylibschc.device
from ._pydantic import EnumByName  # noqa: F401 pylint: disable=unused-import
from .libschc import (  # pylint: disable=import-error
    HeaderFieldID,
    Direction,
    MO,
    CDA,
    FragmentationMode,
    MAX_FIELD_LENGTH,
    IP6_FIELDS,
    UDP_FIELDS,
    COAP_FIELDS,
    MAX_MTU_LENGTH,
    FCN_SIZE_BITS,
    DTAG_SIZE_BITS,
    BITMAP_SIZE_BITS,
)

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


# pylint: disable=too-many-lines
class BaseModel(PydanticBaseModel):
    """Overrides pydantic to default to case-insensitivity."""

    # pylint: disable=too-few-public-methods
    class Config:
        """Config meta-class for :class:`BaseModel`."""

        case_sensitive = False


class BaseRule(BaseModel):
    """Base Rule definition."""

    # pylint: disable=too-few-public-methods
    rule_id: int
    """The Rule ID. Must fit into :attr:`BaseRule.rule_id_size_bits`."""
    rule_id_size_bits: conint(gt=0, le=32)
    """Size of Rule ID in bits. Must be 0 < :attr:`BaseRule.rule_id_size_bits` ≤ 32"""

    @validator("rule_id_size_bits", allow_reuse=True)
    @classmethod
    def check_rule_id_size_bits(cls, value, values):
        # pylint: disable=missing-function-docstring
        if values.get("rule_id", 1 << 32) >= (1 << value):
            raise ValueError(
                f"rule_id={values.get('rule_id')} does not fit into "
                f"rule_id_size_bits={value}"
            )
        return value


class CompressionRuleField(BaseModel):
    """Field descriptor for a compression rule."""

    # order is different from C-definition to ensure validation order
    field: HeaderFieldID
    """Field identifier."""
    field_length: conint(ge=0x00, le=MAX_FIELD_LENGTH * 8)
    """Field length in bits. Must be 0 ≤ :attr:`field_length`
    ≤ :const:`pylibschc.libschc.MAX_FIELD_LENGTH`.
    """
    field_pos: conint(ge=0x00, le=0xFF) = 1
    """Field position, i.e., when there are multiple occurrences of this field, which
    occurrence this field descriptor applies to (default: 1). Must be
    0 ≤ :attr:`CompressionRuleField.field_pos` ≤ 255."""
    dir: Direction
    """Direction indicator for this field descriptor."""
    MO: MO
    """Matching operator for this field."""
    action: CDA
    """Compression/decompression action for this field."""
    MO_param_length: conint(ge=0x00, le=0xFF) = 0
    """Parameter length for the matching operator (default: 0). Must be
    0 ≤ :attr:`CompressionRuleField.MO_param_length` ≤ 255. When being a parameter for
    :attr:`pylibschc.libschc.MO.MSB` it must be lesser or equal to
    :attr:`CompressionRuleField.field_length`."""
    target_value: typing.Union[
        typing.List[
            typing.Union[
                conint(ge=0x0000000000000000, le=0xFFFFFFFFFFFFFFFF),
                ipaddress.IPv6Interface,
                conbytes(max_length=MAX_FIELD_LENGTH),
            ],
        ],
        conint(ge=0x0000000000000000, le=0xFFFFFFFFFFFFFFFF),
        ipaddress.IPv6Interface,
        conbytes(max_length=MAX_FIELD_LENGTH),
    ] = b""
    """Target value for the matching operator (default: b""). Any integers in
    :attr:`CompressionRuleField.target_value` are restricted to 64 bits of width. The
    length of this must fit :attr:`CompressionRuleField.field_length` and, depending on
    :attr:`CompressionRuleField.MO`, :attr:`CompressionRuleField.MO_param_length`. Will
    be converted to :class:`bytes` after validation.
    """

    @validator("MO_param_length", allow_reuse=True, always=True, pre=False)
    @classmethod
    def check_mo_param_length(cls, value, values):
        # pylint: disable=missing-function-docstring
        if values.get("MO") == MO.MSB or values.get("action") == CDA.LSB:
            if value > values.get("field_length", 0):
                raise ValueError(
                    f"MO_param_length={value} must not be greater than "
                    f"field_length={values.get('field_length')} elements with "
                    f"MO={values.get('MO')} or action={values.get('action')}"
                )
        return value

    @staticmethod
    def _check_bits_overflow(bytes_value, values, field_length_mod):
        if (
            (len(bytes_value) > 0)
            and (field_length_mod > 0)
            and ((0xFF << field_length_mod) & int(bytes_value[0]))
        ):
            raise ValueError(
                f"target_value={bytes_value} does not fit into "
                f"field_length={values.get('field_length')} bits"
            )

    @classmethod
    def _check_overflow(  # pylint: disable=too-many-arguments
        cls, orig_value, value, values, field_length_bytes, field_length_mod
    ):
        if any(b for b in value[:-field_length_bytes]):
            raise ValueError(
                f"target_value={orig_value} does not fit into "
                f"field_length={values.get('field_length')} bits"
            )
        value = value[-field_length_bytes:]
        cls._check_bits_overflow(value, values, field_length_mod)
        return value

    @classmethod
    def _int_target_value_to_bytes(
        cls, int_value, values, field_length_bytes, field_length_mod
    ):
        value = struct.pack("!Q", int_value)
        return cls._check_overflow(
            int_value, value, values, field_length_bytes, field_length_mod
        )

    @classmethod
    def _addr_target_value_to_bytes(
        cls, addr_value, values, field_length_bytes, field_length_mod
    ):
        address_fields = [
            HeaderFieldID.IP6_DEVPRE,
            HeaderFieldID.IP6_DEVIID,
            HeaderFieldID.IP6_APPPRE,
            HeaderFieldID.IP6_APPIID,
        ]
        if values.get("field") not in address_fields:
            raise ValueError(
                "target_value={addr_value.compressed} but field {values.get('field')} "
                "not in {address_fields}"
            )
        if values.get("field") in [HeaderFieldID.IP6_DEVPRE, HeaderFieldID.IP6_APPPRE]:
            try:
                # only used to checked, that's why exception raises immediately
                ipaddress.IPv6Network(
                    f"{addr_value.with_prefixlen.split('/')[0]}/"
                    f"{values.get('field_length')}"
                )
            except ValueError:  # pylint: disable=try-except-raise
                raise
            return addr_value.ip.packed[:field_length_bytes]
        # else IID, treat like 64-bit integer
        return cls._check_overflow(
            addr_value.compressed,
            addr_value.ip.packed,
            values,
            field_length_bytes,
            field_length_mod,
        )

    @classmethod
    def _pad_bytes_to_field_length(
        cls, bytes_value, values, field_length_bytes, field_length_mod
    ):
        cls._check_bits_overflow(bytes_value, values, field_length_mod)
        if field_length_bytes > len(bytes_value):
            padding = b"\x00" * (field_length_bytes - len(bytes_value))
            return padding + bytes_value
        return bytes_value

    @staticmethod
    def _field_length_bytes(field_length_bits):
        field_length_bytes = field_length_bits // 8
        field_length_mod = field_length_bits % 8
        if field_length_mod:
            field_length_bytes += 1
        return field_length_bytes, field_length_mod

    @validator("target_value", allow_reuse=True, always=True, pre=False)
    @classmethod
    def check_field_length_for_target_value(cls, value, values):
        # pylint: disable=missing-function-docstring
        bytes_value = None
        field_length_bytes, field_length_mod = cls._field_length_bytes(
            values.get("field_length")
        )
        if values.get("MO") == MO.MATCHMAP or values.get("action") == CDA.MAPPINGSENT:
            mapping_vals = values.get("MO_param_length", 0)
        else:
            mapping_vals = 1
        # TBD check byte order?
        if isinstance(value, int):
            bytes_value = cls._int_target_value_to_bytes(
                value, values, field_length_bytes, field_length_mod
            )
        elif isinstance(value, ipaddress.IPv6Interface):
            bytes_value = cls._addr_target_value_to_bytes(
                value, values, field_length_bytes, field_length_mod
            )
        elif isinstance(value, typing.List):
            if len(value) != mapping_vals:
                raise ValueError(
                    f"target_value={value} is must not be longer than "
                    f"MO_param_length={mapping_vals} elements with "
                    f"MO={values.get('MO')} or action={values.get('action')}"
                )
            bytes_value = b"".join(
                cls._int_target_value_to_bytes(
                    v, values, field_length_bytes, field_length_mod
                )
                if isinstance(v, int)
                else (
                    cls._addr_target_value_to_bytes(
                        v, values, field_length_bytes, field_length_mod
                    )
                    if isinstance(v, ipaddress.IPv6Interface)
                    else cls._pad_bytes_to_field_length(
                        v, values, field_length_bytes, field_length_mod
                    )
                )
                for v in value
            )
        else:  # bytes
            bytes_value = cls._pad_bytes_to_field_length(
                value, values, field_length_bytes, field_length_mod
            )
        if (field_length_bytes * mapping_vals) < len(bytes_value):
            raise ValueError(
                f"target_value={value} does not fit into "
                f"field_length={values.get('field_length')} bits"
            )
        return bytes_value

    @property
    def c_MO(self) -> str:  # pylint: disable=invalid-name
        # pylint: disable=missing-function-docstring
        if self.MO == MO.MSB:
            return "&mo_MSB"
        return f"&mo_{self.MO.name.lower()}"

    def c_schc_field_declaration(self):
        # pylint: disable=missing-function-docstring
        def bytes_to_hex_list(byts: bytes):
            return ", ".join(f"0x{int(b):02x}" for b in byts)

        def chunk_bytes(byts: bytes, chunk_size: int = 8):
            res = "{\n        "
            for i in range(0, len(byts), chunk_size):
                res += bytes_to_hex_list(byts[i : (i + chunk_size)])  # noqa: E203
                if (i + chunk_size) < len(byts):
                    res += ",\n        "
            res += "\n    },"
            return res + "                                                      "

        res = "{ " f"{self.field.name},"
        res += (16 - len(self.field.name)) * " "
        res += (
            f"{self.MO_param_length:3d},"
            f"{self.field_length:4d},"
            f"{self.field_pos:4d}, "
        )
        res += f"{self.dir.name},"
        res += (5 - len(self.dir.name)) * " "
        if self.MO == MO.MATCHMAP and len(self.target_value) > 3:
            field_length_bytes, _ = self._field_length_bytes(self.field_length)
            res += chunk_bytes(self.target_value, field_length_bytes)
        elif len(self.target_value) > 3:
            res += chunk_bytes(self.target_value)
        else:
            hex_str = "{" f"{bytes_to_hex_list(self.target_value)}" "},"
            res += hex_str
            res += (20 - len(hex_str)) * " "
        res += f"{self.c_MO},"
        res += (15 - len(self.c_MO)) * " "
        res += f"{self.action.name}"
        res += (12 - len(self.action.name)) * " "
        return res + "}"


class CompressionRule(BaseRule):
    """A compression rule."""

    ipv6_rule: conlist(CompressionRuleField, max_items=IP6_FIELDS) = None
    """The field descriptors for the IPv6 layer (default: None). Must at most be
    :const:`pylibschc.libschc.IP6_FIELDS` long and only contain field descriptors for
    which the name of :attr:`CompressionRuleField.field` starts with `IP6_`."""
    udp_rule: conlist(CompressionRuleField, max_items=UDP_FIELDS) = None
    """The field descriptors for the UDP layer (default: None). Must at most be
    :const:`pylibschc.libschc.UDP_FIELDS` long and only contain field descriptors for
    which the name of :attr:`CompressionRuleField.field` starts with `UDP_`."""
    coap_rule: conlist(CompressionRuleField, max_items=COAP_FIELDS) = None
    """The field descriptors for the CoAP layer (default: None). Must at most be
    :const:`pylibschc.libschc.COAP_FIELDS` long and only contain field descriptors for
    which the name of :attr:`CompressionRuleField.field` starts with `COAP_`."""

    @staticmethod
    def _check_field_identifiers(value, expected_start, rule_type):
        if not value:
            return None
        for field in value:
            if not field.field.name.startswith(expected_start):
                raise ValueError(f"{field} is not a valid {rule_type} field")
        return value

    @validator("ipv6_rule", allow_reuse=True)
    @classmethod
    def check_ipv6_rule(cls, value) -> conlist:
        # pylint: disable=missing-function-docstring
        return cls._check_field_identifiers(value, "IP6_", "ipv6_rule")

    @validator("udp_rule", allow_reuse=True)
    @classmethod
    def check_udp_rule(cls, value) -> conlist:
        # pylint: disable=missing-function-docstring
        return cls._check_field_identifiers(value, "UDP_", "udp_rule")

    @validator("coap_rule", allow_reuse=True)
    @classmethod
    def check_coap_rule(cls, value) -> conlist:
        # pylint: disable=missing-function-docstring
        return cls._check_field_identifiers(value, "COAP_", "coap_rule")

    def _c_schc_layer_rule_declaration(self, layer_fields):
        if not layer_fields:
            return ""
        up = 0  # pylint: disable=invalid-name
        down = 0
        field_declarations = """{
        /* field,           ML, len, pos, dir,  val,                MO,             CDA         */
"""  # noqa: E501
        for i, field in enumerate(layer_fields):
            if field.dir == Direction.UP:
                up += 1  # pylint: disable=invalid-name
            elif field.dir == Direction.DOWN:
                down += 1
            else:  # field.dir == Direction.BI
                up += 1  # pylint: disable=invalid-name
                down += 1
            field_declarations += "        "
            field_declarations += field.c_schc_field_declaration().replace(
                "\n", "\n        "
            )
            if (i + 1) < len(layer_fields):
                field_declarations += ",\n"
        field_declarations += "\n    }"
        i = 1  # pylint: disable=invalid-name
        res = "{\n"
        res += f"    .up = {up}, .down = {down}, .length = {len(layer_fields)},\n"
        res += f"    {field_declarations}\n"
        res += "}"
        return res

    def c_schc_ipv6_rule_declaration(self) -> str:
        # pylint: disable=missing-function-docstring
        return self._c_schc_layer_rule_declaration(self.ipv6_rule)

    def c_schc_udp_rule_declaration(self) -> str:
        # pylint: disable=missing-function-docstring
        return self._c_schc_layer_rule_declaration(self.udp_rule)

    def c_schc_coap_rule_declaration(self) -> str:
        # pylint: disable=missing-function-docstring
        return self._c_schc_layer_rule_declaration(self.coap_rule)

    def c_schc_compression_rule_declaration(
        self, ipv6_rule_name: str, udp_rule_name: str, coap_rule_name: str
    ) -> str:
        # pylint: disable=missing-function-docstring
        ipv6_rule_ptr = f"&{ipv6_rule_name}" if self.ipv6_rule else "NULL"
        udp_rule_ptr = f"&{udp_rule_name}" if self.udp_rule else "NULL"
        coap_rule_ptr = f"&{coap_rule_name}" if self.coap_rule else "NULL"
        return (
            "{\n"
            f"    .rule_id = {self.rule_id}U,\n"
            f"    .rule_id_size_bits = {self.rule_id_size_bits}U,\n"
            "#if USE_IP6\n"
            f"    .ipv6_rule = {ipv6_rule_ptr},\n"
            "#endif\n"
            "#if USE_UDP\n"
            f"    .udp_rule = {udp_rule_ptr},\n"
            "#endif\n"
            "#if USE_COAP\n"
            f"    .coap_rule = {coap_rule_ptr},\n"
            "#endif\n"
            "}"
        )


class UncompressedRule(BaseRule):
    # pylint: disable=too-few-public-methods
    """The rule for an uncompressed packet."""


class FragmentationRule(BaseRule):
    # pylint: disable=too-few-public-methods
    """A fragmentation rule."""

    mode: FragmentationMode
    """The reliability mode for this rule."""
    dir: Direction
    """The direction for which this rule applies."""
    FCN_SIZE: conint(ge=0x00, le=FCN_SIZE_BITS) = 1
    """The FCN field length of the SCHC fragmentation header in bits (default: 1). Must
    be 0 ≤ :attr:`BaseRule.FCN_SIZE` ≤ :attr:`pylibschc.libschc.FCN_SIZE_BITS`."""
    MAX_WND_FCN: conint(ge=0x00, lt=BITMAP_SIZE_BITS) = 0
    """The maximum number of fragments per window (default: 0). Must be
    0 ≤ :attr:`BaseRule.MAX_WND_FCN` ≤ :attr:`pylibschc.libschc.FCN_SIZE_BITS`."""
    WINDOW_SIZE: conint(ge=0x00, le=0xFF) = 0
    """The window size field length of the SCHC fragmentation header in bits
    (default: 0). Must be 0 ≤ :attr:`BaseRule.MAX_WND_FCN`
    ≤ :attr:`pylibschc.libschc.FCN_SIZE_BITS`."""
    DTAG_SIZE: conint(ge=0x00, le=DTAG_SIZE_BITS) = 0
    """The DTAG field length of the SCHC fragmentation header in bits (default: 0). Must
    be 0 ≤ :attr:`BaseRule.MAX_WND_FCN` ≤ :attr:`pylibschc.libschc.FCN_SIZE_BITS`."""

    def c_schc_fragmentation_rule_declaration(self):
        # pylint: disable=missing-function-docstring
        return (
            "{\n"
            f"    .rule_id = {self.rule_id}U,\n"
            f"    .rule_id_size_bits = {self.rule_id_size_bits}U,\n"
            f"    .mode = {self.mode.name},\n"
            f"    .dir = {self.dir.name},\n"
            f"    .FCN_SIZE = {self.FCN_SIZE:6d}U,    "
            "/* FCN field size (N in RFC) */\n"
            f"    .MAX_WND_FCN = {self.MAX_WND_FCN:3d}U,    "
            "/* Maximum fragments per window (WINDOW_SIZE in RFC) */\n"
            f"    .WINDOW_SIZE = {self.WINDOW_SIZE:3d}U,    "
            "/* W field size (M in RFC) */\n"
            f"    .DTAG_SIZE = {self.DTAG_SIZE:5d}U     "
            "/* DTAG field size (T in RFC) */\n"
            "}"
        )


class Device(BaseModel):
    # pylint: disable=too-few-public-methods
    """The device for which to configure the rules for."""
    device_id: conint(gt=0x00000000, le=0xFFFFFFFF)
    """The libSCHC-internal identifier for the device. Must be 0
    < :attr:`Device.device_id` ≤ :math:`(2^{32} - 1)`."""
    mtu: conint(ge=0x0000, le=MAX_MTU_LENGTH)
    """The maximum transmission unit of the link layer of the device. Must be 0
    < :attr:`Device.mtu` ≤ :attr:`pylibschc.libschc.MAX_MTU_LENGTH`."""
    duty_cycle: conint(ge=0x00000000, le=0xFFFFFFFF)
    """The duty cycle in milliseconds of the device. Must be 0
    < :attr:`Device.duty_cycle` ≤ :math:`(2^{32} - 1)`."""
    uncompressed_rule: UncompressedRule = None
    """The rule for an uncompressed packet on this device. Must not contain any
    duplicate rule IDs (i.e., same value of same bit width) with
    :attr:`Device.compression_rules` or :attr:`Device.fragmentation_rules`."""
    compression_rules: typing.List[CompressionRule] = []
    """The compression rules on this device (default: []). Must not contain any
    duplicate rule IDs (i.e., same value of same bit width) with
    :attr:`Device.uncompressed_rule` or :attr:`Device.fragmentation_rules`."""
    fragmentation_rules: typing.List[FragmentationRule] = []
    """The fragmentation rules on this device (default: []). Must not contain any
    duplicate rule IDs (i.e., same value of same bit width) with
    :attr:`Device.uncompressed_rule` or :attr:`Device.compression_rules`."""

    @validator("fragmentation_rules", always=True, pre=False)
    @classmethod
    def check_rule_id_duplicates(cls, fragmentation_rules, values):
        # pylint: disable=missing-function-docstring
        uncompressed_rule = values.get("uncompressed_rule")
        compression_rules = values.get("compression_rules", [])
        rule_ids = set()

        if uncompressed_rule:
            rule_ids.add(
                (uncompressed_rule.rule_id, uncompressed_rule.rule_id_size_bits)
            )

        for rule in compression_rules + fragmentation_rules:
            if (rule.rule_id, rule.rule_id_size_bits) in rule_ids:
                raise ValueError(
                    "Duplicate rule ID "
                    f"rule_id={rule.rule_id}/rule_id_size_bits={rule.rule_id_size_bits}"
                )
            rule_ids.add((rule.rule_id, rule.rule_id_size_bits))
        return fragmentation_rules

    def c_schc_device_declaration(
        self, compression_rules_name, fragmentation_rules_name
    ):
        # pylint: disable=missing-function-docstring
        compression_rules_ptr = (
            f"&{compression_rules_name}" if self.compression_rules else "NULL"
        )
        compression_rules_count = (
            f"sizeof({compression_rules_name}) / sizeof({compression_rules_name}[0])"
            if self.compression_rules
            else "0U"
        )
        fragmentation_rules_ptr = (
            f"&{fragmentation_rules_name}" if self.fragmentation_rules else "NULL"
        )
        fragmentation_rules_count = (
            f"sizeof({fragmentation_rules_name}) / "
            f"sizeof({fragmentation_rules_name}[0])"
            if self.fragmentation_rules
            else "0U"
        )
        if self.uncompressed_rule:
            uncomp_rule_id = self.uncompressed_rule.rule_id
            uncomp_rule_id_size_bits = self.uncompressed_rule.rule_id_size_bits
        else:
            uncomp_rule_id = 0
            uncomp_rule_id_size_bits = 0
        return (
            "{\n"
            f"    .device_id = {self.device_id}U,\n"
            f"    .uncomp_rule_id = {uncomp_rule_id}U,\n"
            f"    .uncomp_rule_id_size_bits = {uncomp_rule_id_size_bits}U,\n"
            f"    .compression_rule_count = {compression_rules_count},\n"
            f"    .compression_context = {compression_rules_ptr},\n"
            f"    .fragmentation_rule_count = {fragmentation_rules_count},\n"
            f"    .fragmentation_context = {fragmentation_rules_ptr},\n"
            "}"
        )


class Config(BaseModel):
    """The overall rule configuration for libSCHC."""

    # pylint: disable=too-few-public-methods
    devices: typing.List[Device]
    """The devices for libSCHC. Must not contain any devices with duplicate
    :attr:`Device`.device_id."""

    @validator("devices")
    @classmethod
    def device_ids_unique(cls, devices):
        # pylint: disable=missing-function-docstring
        device_ids = set()
        for device in devices:
            if device.device_id in device_ids:
                raise ValueError(f"device_id={device.device_id} is not unique")
            device_ids.add(device.device_id)
        return devices

    @staticmethod
    def _layer_rule_to_c(visited_layer_rules, layer_name, rule, decl_func):
        if not rule:
            return None
        for rule_name, (visited_rule, _) in visited_layer_rules.items():
            if rule == visited_rule:
                return rule_name
        rule_name = f"{layer_name}_rule_{len(visited_layer_rules):02d}"
        visited_layer_rules[rule_name] = (rule, decl_func())
        return rule_name

    def deploy(self) -> argparse.Namespace:
        """Deploys the rule configuration with the binary libSCHC.

        .. warning::
            This method **must** be called whenever a rule or device is changed.
            Otherwise, libSCHC will not register this change.

        :return: A :class:`argparse.Namespace` with the following attributes:

            - ``devices``: The devices modeled with :class:`Device` as
              :class:`pylibschc.device.Device`.
        :rtype: :class:`argparse.Namespace`"""
        devices = []
        for device_config in self.devices:
            device = pylibschc.device.Device(
                device_id=device_config.device_id,
                mtu=device_config.mtu,
                duty_cycle_ms=device_config.duty_cycle,
            )
            device.compression_rules = device_config.compression_rules
            device.fragmentation_rules = device_config.fragmentation_rules
            device.uncompressed_rule = device_config.uncompressed_rule
            devices.append(device)
        return argparse.Namespace(devices=devices)

    def to_c_header(self) -> str:  # noqa: C901
        # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        """Provides the C header file for this rules configuration as a string.

        :return: The C header file for libSCHC representing this rules configuration.
        :rtype: str"""
        visited_compression_layer_rules = {
            "ipv6": {},
            "udp": {},
            "coap": {},
        }
        visited_compression_array = {}
        visited_compression_rules = {}
        visited_fragmentation_array = {}
        visited_fragmentation_rules = {}
        device_decls = {}

        for device in self.devices:
            compr_array_name = ""
            array_visited = False
            for compr_array_name, (
                visited_array,
                _,
            ) in visited_compression_array.items():
                if device.compression_rules == visited_array:  # pragma: no cover
                    array_visited = True
                    break
            if device.compression_rules and not array_visited:
                compr_array_name = (
                    f"compression_rules_{len(visited_compression_array):02d}"
                )
                array_decl = (
                    "static const struct schc_compression_rule_t "
                    f"*{compr_array_name}[] = {{\n"
                )
                for rule in device.compression_rules:
                    rule_visited = False
                    for rule_name, (
                        visited_rule,
                        _,
                    ) in visited_compression_rules.items():
                        if rule == visited_rule:
                            rule_visited = True
                            array_decl += f"    &{rule_name},\n"
                            break
                    if rule_visited:
                        continue
                    ipv6_rule_name = self._layer_rule_to_c(
                        visited_compression_layer_rules["ipv6"],
                        "ipv6",
                        rule.ipv6_rule,
                        rule.c_schc_ipv6_rule_declaration,
                    )
                    udp_rule_name = self._layer_rule_to_c(
                        visited_compression_layer_rules["udp"],
                        "udp",
                        rule.udp_rule,
                        rule.c_schc_udp_rule_declaration,
                    )
                    coap_rule_name = self._layer_rule_to_c(
                        visited_compression_layer_rules["coap"],
                        "coap",
                        rule.coap_rule,
                        rule.c_schc_coap_rule_declaration,
                    )
                    rule_name = ""
                    for i in range(  # pragma: no cover
                        len(visited_compression_rules) + 1
                    ):
                        rule_name = (
                            f"comp_rule_{rule.rule_id:03d}_"
                            f"{rule.rule_id_size_bits:02d}_{i:02d}"
                        )
                        if (  # pragma: no cover
                            rule_name not in visited_compression_rules
                        ):
                            break
                    visited_compression_rules[rule_name] = (
                        rule,
                        rule.c_schc_compression_rule_declaration(
                            ipv6_rule_name,
                            udp_rule_name,
                            coap_rule_name,
                        ),
                    )
                    array_decl += f"    &{rule_name},\n"
                array_decl += "}"
                visited_compression_array[compr_array_name] = (
                    device.compression_rules,
                    array_decl,
                )
            frag_array_name = ""
            array_visited = False
            for frag_array_name, (
                visited_array,
                _,
            ) in visited_fragmentation_array.items():
                if device.fragmentation_rules == visited_array:  # pragma: no cover
                    array_visited = True
                    break
            if device.fragmentation_rules and not array_visited:
                frag_array_name = (
                    f"fragmentation_rules_{len(visited_fragmentation_array):02d}"
                )
                array_decl = (
                    "static const struct schc_fragmentation_rule_t "
                    f"*{frag_array_name}[] = {{\n"
                )
                for rule in device.fragmentation_rules:
                    rule_visited = False
                    for rule_name, (
                        visited_rule,
                        _,
                    ) in visited_fragmentation_rules.items():
                        if rule == visited_rule:
                            rule_visited = True
                            array_decl += f"    &{rule_name},\n"
                            break
                    if rule_visited:
                        continue
                    rule_name = ""
                    for i in range(  # pragma: no cover
                        len(visited_fragmentation_rules) + 1
                    ):
                        rule_name = (
                            f"frag_rule_{rule.rule_id:03d}_"
                            f"{rule.rule_id_size_bits:02d}_{i:02d}"
                        )
                        if (  # pragma: no cover
                            rule_name not in visited_fragmentation_rules
                        ):
                            break
                    visited_fragmentation_rules[rule_name] = (
                        rule,
                        rule.c_schc_fragmentation_rule_declaration(),
                    )
                    array_decl += f"    &{rule_name},\n"
                array_decl += "}"
                visited_fragmentation_array[frag_array_name] = (
                    device.fragmentation_rules,
                    array_decl,
                )
            device_decls[
                f"device{device.device_id}"
            ] = device.c_schc_device_declaration(
                compr_array_name,
                frag_array_name,
            )
        res = """/*
 * generated by pylibschc with schc_config.h
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * #define USE_IP6              1
 * #define USE_UDP              1
 * #define USE_COAP             1
"""
        res += (
            " * #define MAX_FIELD_LENGTH     "
            f"{MAX_FIELD_LENGTH}\n"
            " * #define IP6_FIELDS           "
            f"{IP6_FIELDS}\n"
            " * #define UDP_FIELDS           "
            f"{UDP_FIELDS}\n"
            " * #define COAP_FIELDS          "
            f"{COAP_FIELDS}\n"
            " * #define FCN_SIZE_BITS        "
            f"{FCN_SIZE_BITS}\n"
            " * #define DTAG_SIZE_BITS       "
            f"{DTAG_SIZE_BITS}\n"
            " * #define BITMAP_SIZE_BITS     "
            f"{BITMAP_SIZE_BITS}\n"
        )
        res += """ * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef RULES_RULE_CONFIG_H
#define RULES_RULE_CONFIG_H

#include "schc.h"

#ifdef __cplusplus
extern "C" {
#endif
"""
        for layer_define, layer_name in [
            ("USE_IP6", "ipv6"),
            ("USE_UDP", "udp"),
            ("USE_COAP", "coap"),
        ]:
            if visited_compression_layer_rules[layer_name]:  # pragma: no cover
                res += f"\n#if {layer_define}"
                for rule_name, rule_decl in sorted(
                    visited_compression_layer_rules[layer_name].items()
                ):
                    res += (
                        f"\nstatic const struct schc_{layer_name}_rule_t "
                        f"{rule_name} = {rule_decl[1]};\n"
                    )
                res += f"#endif /* {layer_define} */\n"
        for rule_name, rule_decl in sorted(visited_compression_rules.items()):
            res += (
                f"\nstatic const struct schc_compression_rule_t "
                f"{rule_name} = {rule_decl[1]};\n"
            )
        for rule_name, rule_decl in sorted(visited_fragmentation_rules.items()):
            res += (
                f"\nstatic const struct schc_fragmentation_rule_t "
                f"{rule_name} = {rule_decl[1]};\n"
            )
        for _, array_decl in sorted(visited_compression_array.items()):
            res += f"\n{array_decl[1]};\n"

        for _, array_decl in sorted(visited_fragmentation_array.items()):
            res += f"\n{array_decl[1]};\n"

        for device_name, device_decl in device_decls.items():
            res += f"\nstatic const struct schc_device {device_name} = {device_decl};\n"
        if device_decls:
            res += "\nstatic const struct schc_device* devices[] = {\n"
            res += ",\n".join(f"    &{device_name}" for device_name in device_decls)
            res += "\n};\n"
            device_count = "(sizeof(devices) / sizeof(devices[0]))"
        else:
            device_count = "0"  # pragma: no cover
        res += f"\n#define DEVICE_COUNT    ((int){device_count})"
        res += """

#ifdef __cplusplus
}
#endif

#endif /* RULES_RULE_CONFIG_H */
"""
        return res

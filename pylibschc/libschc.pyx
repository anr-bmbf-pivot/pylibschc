# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

import enum
import logging
import typing

from cpython.ref cimport Py_INCREF, Py_DECREF
from cpython.bool cimport bool
from cpython.object cimport PyObject
from cython.operator cimport postincrement as inc, postdecrement as dec
from libc.stddef cimport size_t
from libc.stdint cimport int8_t, uint8_t, uint16_t, uint32_t, intptr_t
from libc.stdlib cimport free, malloc
from libc.string cimport memcmp, memcpy, memset

from . cimport clibschc
from ._pydantic import EnumByName

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


MAX_FIELD_LENGTH = clibschc.MAX_FIELD_LENGTH
IP6_FIELDS = clibschc.IP6_FIELDS
UDP_FIELDS = clibschc.UDP_FIELDS
COAP_FIELDS = clibschc.COAP_FIELDS
MAX_MTU_LENGTH = clibschc.MAX_MTU_LENGTH
FCN_SIZE_BITS = clibschc.FCN_SIZE_BITS
DTAG_SIZE_BITS = clibschc.DTAG_SIZE_BITS
BITMAP_SIZE_BITS = clibschc.BITMAP_SIZE_BYTES * 8

logger = logging.getLogger(__name__)
clibschc.pylog_init(<PyObject *>logger)


cdef class BitArray:
    cdef clibschc.schc_bitarray_t _bit_array
    cdef size_t size

    def __cinit__(self, n: typing.Union[bytes, int]):
        self.size = len(n) if isinstance(n, bytes) else n
        self._bit_array.ptr = <uint8_t *>malloc(self.size)
        if self._bit_array.ptr is NULL:
            raise MemoryError("Unable to allocate bit array")
        if self.size > 0:
            if isinstance(n, bytes):
                memcpy(<void *>self._bit_array.ptr, <char *>n, self.size)
            else:
                memset(<void *>self._bit_array.ptr, 0, self.size)
        else:
            self._bit_array.ptr = NULL
        self._bit_array.offset = 0
        self._bit_array.padding = 0
        self._bit_array.len = self.size
        if isinstance(n, bytes):
            self._bit_array.bit_len = self.size * 8
        else:
            self._bit_array.bit_len = 0

    def __dealloc__(self):
        free(<void *>self._bit_array.ptr)

    cdef int _eq(self, BitArray other):
        return (
            self._bit_array.offset == other._bit_array.offset
            and self._bit_array.padding == other._bit_array.padding
            and self._bit_array.bit_len == other._bit_array.bit_len
            and self._bit_array.len == other._bit_array.len
            and (
                memcmp(
                    <void *>self._bit_array.ptr,
                    <void *>other._bit_array.ptr,
                    self._bit_array.len,
                ) == 0
            )
        )

    def __eq__(self, other: BitArray) -> bool:
        try:
            return bool(self._eq(other))
        except Exception:
            raise

    def __ne__(self, other: BitArray) -> bool:
        return not (self == other)

    property buffer:
        def __get__(self) -> bytes:
            if self._bit_array.ptr is NULL:
                return b""
            return <bytes> self._bit_array.ptr[:self._bit_array.len]

        def __set__(self, buffer: bytes):
            if len(buffer) > self.size:
                self.size = len(buffer)
                free(<void *>self._bit_array.ptr)
                self._bit_array.ptr = <uint8_t *>malloc(self.size)
                if self._bit_array.ptr is NULL:
                    raise MemoryError("Unable to allocate bit array")
            elif len(buffer) == 0:
                self.size = 0
                free(<void *>self._bit_array.ptr)
                self._bit_array.ptr = NULL
            if self.size > 0:
                memcpy(
                    <void *>self._bit_array.ptr, <void *>(<char *>buffer), len(buffer)
                )
            self._bit_array.len = len(buffer)
            self._bit_array.bit_len = len(buffer) * 8

        def __del__(self):
            memset(<void *>self._bit_array.ptr, 0, self.size)
            self._bit_array.offset = 0
            self._bit_array.padding = 0
            self._bit_array.len = 0
            self._bit_array.bit_len = 0

    property offset:
        def __get__(self) -> int:
            return self._bit_array.offset

    property padding:
        def __get__(self) -> int:
            return self._bit_array.padding

    property length:
        def __get__(self) -> int:
            return self._bit_array.len

    property bit_length:
        def __get__(self) -> int:
            return self._bit_array.bit_len

    def get_bits(self, pos: int, length: int) -> int:
        if length > 32:
            raise ValueError("`length` must be lesser or equal to 32")
        if (<uint32_t>pos + <uint8_t>length) > self._bit_array.bit_len:
            raise ValueError(
                f"`pos + length` overflows buffer size ({self._bit_array.bit_len})"
            )
        return clibschc.get_bits(self._bit_array.ptr, pos, length)

    def copy_bits(self, pos: int, data: bytes, length: int) -> int:
        if (<uint32_t>pos + <uint8_t>length) > self._bit_array.bit_len:
            raise ValueError(
                f"`pos + length` overflows buffer size ({self._bit_array.bit_len})"
            )
        clibschc.clear_bits(self._bit_array.ptr, pos, length)
        return clibschc.copy_bits(
            self._bit_array.ptr, pos, <uint8_t *>(<char *>data), 0, length
        )


cdef char *_bit_array_ptr(BitArray bit_array):
    return <char *>bit_array._bit_array.ptr


class HeaderFieldID(EnumByName):
    IP6_V = clibschc.IP6_V
    IP6_TC = clibschc.IP6_TC
    IP6_FL = clibschc.IP6_FL
    IP6_LEN = clibschc.IP6_LEN
    IP6_NH = clibschc.IP6_NH
    IP6_HL = clibschc.IP6_HL
    IP6_DEVPRE = clibschc.IP6_DEVPRE
    IP6_DEVIID = clibschc.IP6_DEVIID
    IP6_APPPRE = clibschc.IP6_APPPRE
    IP6_APPIID = clibschc.IP6_APPIID
    UDP_DEV = clibschc.UDP_DEV
    UDP_APP = clibschc.UDP_APP
    UDP_LEN = clibschc.UDP_LEN
    UDP_CHK = clibschc.UDP_CHK
    COAP_V = clibschc.COAP_V
    COAP_T = clibschc.COAP_T
    COAP_TKL = clibschc.COAP_TKL
    COAP_C = clibschc.COAP_C
    COAP_MID = clibschc.COAP_MID
    COAP_TKN = clibschc.COAP_TKN
    COAP_PAYLOAD = clibschc.COAP_PAYLOAD
    COAP_IFMATCH = clibschc.COAP_IFMATCH
    COAP_URIHOST = clibschc.COAP_URIHOST
    COAP_ETAG = clibschc.COAP_ETAG
    COAP_IFNOMATCH = clibschc.COAP_IFNOMATCH
    COAP_URIPORT = clibschc.COAP_URIPORT
    COAP_LOCPATH = clibschc.COAP_LOCPATH
    COAP_URIPATH = clibschc.COAP_URIPATH
    COAP_CONTENTF = clibschc.COAP_CONTENTF
    COAP_MAXAGE = clibschc.COAP_MAXAGE
    COAP_URIQUERY = clibschc.COAP_URIQUERY
    COAP_ACCEPT = clibschc.COAP_ACCEPT
    COAP_LOCQUERY = clibschc.COAP_LOCQUERY
    COAP_PROXYURI = clibschc.COAP_PROXYURI
    COAP_PROXYSCH = clibschc.COAP_PROXYSCH
    COAP_SIZE1 = clibschc.COAP_SIZE1
    COAP_NORESP = clibschc.COAP_NORESP


class Direction(EnumByName):
    UP = clibschc.UP
    DOWN = clibschc.DOWN
    BI = clibschc.BI


class MO(EnumByName):
    EQUAL = 0
    MO_EQUAL = 0
    IGNORE = 1
    MO_IGNORE = 1
    MSB = 2
    MO_MSB = 2
    MATCHMAP = 3
    MO_MATCHMAP = 3


cdef void _set_mo_op(clibschc.schc_field *field, int mo):
    if mo == <int>MO.EQUAL.value:
        field.MO = clibschc.mo_equal
    elif mo == <int>MO.IGNORE.value:
        field.MO = clibschc.mo_ignore
    elif mo == <int>MO.MSB.value:
        field.MO = clibschc.mo_MSB
    elif mo == <int>MO.MATCHMAP.value:
        field.MO = clibschc.mo_matchmap
    else:
        raise ValueError(f"unknown match operator {mo}")


class CDA(EnumByName):
    NOTSENT = clibschc.NOTSENT
    VALUESENT = clibschc.VALUESENT
    MAPPINGSENT = clibschc.MAPPINGSENT
    LSB = clibschc.LSB
    COMPLENGTH = clibschc.COMPLENGTH
    COMPCHK = clibschc.COMPCHK
    DEVIID = clibschc.DEVIID
    APPIID = clibschc.APPIID


class FragmentationMode(EnumByName):
    ACK_ALWAYS = clibschc.ACK_ALWAYS
    ACK_ON_ERROR = clibschc.ACK_ON_ERROR
    NO_ACK = clibschc.NO_ACK
    NOT_FRAGMENTED = clibschc.NOT_FRAGMENTED


cdef class Device:
    _devices = {}

    cdef clibschc.schc_device _dev

    def __cinit__(self, device_id):
        self._dev.device_id = device_id
        self._register()

    def __dealloc__(self):
        self._unregister()

    cdef _register(self):
        for i in range(clibschc.DEVICE_COUNT):
            if clibschc.devices[i] == &self._dev:
                return
            if clibschc.devices[i].device_id == self._dev.device_id:
                raise ValueError(
                    f"There is already a device with ID #{self._dev.device_id}"
                )
        cdef clibschc.schc_device **new_devices = <clibschc.schc_device **>malloc(
            (clibschc.DEVICE_COUNT + 1) * sizeof(clibschc.schc_device *)
        )
        if new_devices is NULL:
            raise MemoryError("Error allocating new device #{self._dev.device_id}")
        if clibschc.devices is not NULL:
            for i in range(clibschc.DEVICE_COUNT):
                new_devices[i] = clibschc.devices[i]
            free(clibschc.devices)
        new_devices[clibschc.DEVICE_COUNT] = &self._dev
        inc(clibschc.DEVICE_COUNT)
        clibschc.devices = new_devices
        self._devices[self._dev.device_id] = self

    cdef _unregister(self):
        if clibschc.devices is NULL:
            return
        del self.compression_rules
        for i in range(clibschc.DEVICE_COUNT):
            if clibschc.devices[i].device_id == self._dev.device_id:
                for j in range(i, clibschc.DEVICE_COUNT - 1):
                    clibschc.devices[j] = clibschc.devices[j + 1]
                dec(clibschc.DEVICE_COUNT)
                break
        if clibschc.DEVICE_COUNT == 0 and clibschc.devices is not NULL:
            free(clibschc.devices)
            clibschc.devices = NULL
        if self._dev.device_id in self._devices:
            del self._devices[self._dev.device_id]

    @staticmethod
    def get(device_id: int):
        try:
            return Device._devices[device_id]
        except KeyError as exc:
            raise KeyError(exc) from exc

    @staticmethod
    cdef _set_mo(dict field, void *mo):
        if mo == <void *>clibschc.mo_equal:
            field["MO"] = MO.MO_EQUAL
        elif mo == <void *>clibschc.mo_ignore:
            field["MO"] = MO.MO_IGNORE
        elif mo == <void *>clibschc.mo_MSB:
            field["MO"] = MO.MO_MSB
        elif mo == <void *>clibschc.mo_matchmap:
            field["MO"] = MO.MO_MATCHMAP
        else:
            raise ValueError("undefined match operator")

    @staticmethod
    cdef _comp_layer_to_dict(clibschc.schc_layer_rule_t *layer_rule):
        rule = []
        for j in range(layer_rule.length):
            c_field = &layer_rule.content[j]
            py_field = {
                "field": HeaderFieldID(<int>c_field.field),
                "MO_param_length": c_field.MO_param_length,
                "field_length": c_field.field_length,
                "field_pos": c_field.field_pos,
                "dir": Direction(<int>c_field.dir),
                "action": CDA(<int>c_field.action)
            }
            Device._set_mo(py_field, c_field.MO),
            target_value_len = clibschc.BITS_TO_BYTES(c_field.field_length)
            if (
                <int>c_field.action == <int>clibschc.MAPPINGSENT
                or py_field["MO"] == MO.MATCHMAP
            ):
                target_value_len *= c_field.MO_param_length
            py_field["target_value"] = <bytes>c_field.target_value[:target_value_len]
            rule.append(py_field)
        return rule

    @staticmethod
    cdef _comp_ctx_to_dict(const clibschc.schc_compression_rule_t **ctx, int i):
        cdef clibschc.schc_compression_rule_t *c_rule = ctx[i]
        py_rule = {}
        py_rule["rule_id"] = c_rule.rule_id
        py_rule["rule_id_size_bits"] = c_rule.rule_id_size_bits
        try:
            if c_rule.ipv6_rule:
                py_rule["ipv6_rule"] = Device._comp_layer_to_dict(
                    <clibschc.schc_layer_rule_t *>c_rule.ipv6_rule
                )
            if c_rule.udp_rule:
                py_rule["udp_rule"] = Device._comp_layer_to_dict(
                    <clibschc.schc_layer_rule_t *>c_rule.udp_rule
                )
            if c_rule.coap_rule:
                py_rule["coap_rule"] = Device._comp_layer_to_dict(
                    <clibschc.schc_layer_rule_t *>c_rule.coap_rule
                )
        except ValueError as exc:
            raise ValueError(
                f"Error on partially constructed rule {py_rule}: {exc}"
            ) from exc
        return py_rule

    @staticmethod
    cdef _set_field(clibschc.schc_field *c_field, dict py_field):
        target_value = py_field["target_value"]

        if len(target_value) > clibschc.MAX_FIELD_LENGTH:
            raise ValueError(
                f"{target_value} is longer than MAX_FIELD_LENGTH "
                f"({clibschc.MAX_FIELD_LENGTH})"
            )
        c_field.field = <uint16_t>py_field["field"].value
        c_field.field = <uint16_t>py_field["field"].value
        c_field.MO_param_length = <uint8_t>py_field["MO_param_length"]
        c_field.field_length = <uint8_t>py_field["field_length"]
        c_field.field_pos = <uint8_t>py_field["field_pos"]
        c_field.dir = <clibschc.direction>(<int>py_field["dir"].value)
        c_field.action = <clibschc.CDA>(<int>py_field["action"].value)
        target_value_len = clibschc.BITS_TO_BYTES(c_field.field_length)
        if (
            <int>c_field.action == <int>clibschc.MAPPINGSENT
            or py_field["MO"] == MO.MATCHMAP
        ):
            target_value_len *= c_field.MO_param_length
        memcpy(c_field.target_value, <void *>(<char *>target_value), target_value_len)
        _set_mo_op(c_field, <int>py_field["MO"].value)

    @staticmethod
    cdef _set_layer_rule(
        clibschc.schc_layer_rule_t *c_layer_rule, list fields, int max_fields
    ):
        cdef uint8_t length = len(fields)
        cdef uint8_t up = 0
        cdef uint8_t down = 0

        if length > <unsigned>max_fields:
            raise ValueError(f"{fields} contains more than {max_fields} fields")

        for i, field in enumerate(fields):
            try:
                Device._set_field(&c_layer_rule.content[i], field)
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(f"{fields}: {exc}") from exc
            if field["dir"] == Direction.UP:
                inc(up)
            elif field["dir"] == Direction.DOWN:
                inc(down)
            else:  # field["dir"] == Direction.BI
                inc(up)
                inc(down)
        c_layer_rule.up = up
        c_layer_rule.down = down
        c_layer_rule.length = length

    @staticmethod
    cdef _set_compression_rule(
        dict layer_rules, clibschc.schc_compression_rule_t *c_rule, dict py_rule
    ):
        c_rule.rule_id = py_rule["rule_id"]
        c_rule.rule_id_size_bits = py_rule["rule_id_size_bits"]
        try:
            if py_rule.get("ipv6_rule"):
                for ptr, rule in layer_rules.items():
                    if rule == py_rule["ipv6_rule"]:
                        c_rule.ipv6_rule = <clibschc.schc_ipv6_rule_t *>(<intptr_t>ptr)
                if not c_rule.ipv6_rule:
                    c_rule.ipv6_rule = clibschc.schc_rules_create_ipv6_rule()
                    Device._set_layer_rule(
                        <clibschc.schc_layer_rule_t *>c_rule.ipv6_rule,
                        py_rule["ipv6_rule"],
                        clibschc.IP6_FIELDS
                    )
                    layer_rules[<intptr_t>c_rule.ipv6_rule] = py_rule["ipv6_rule"]
            if py_rule.get("udp_rule"):
                for ptr, rule in layer_rules.items():
                    if rule == py_rule["udp_rule"]:
                        c_rule.udp_rule = <clibschc.schc_udp_rule_t *>(<intptr_t>ptr)
                if not c_rule.udp_rule:
                    c_rule.udp_rule = clibschc.schc_rules_create_udp_rule()
                    Device._set_layer_rule(
                        <clibschc.schc_layer_rule_t *>c_rule.udp_rule,
                        py_rule["udp_rule"],
                        clibschc.UDP_FIELDS
                    )
                    layer_rules[<intptr_t>c_rule.udp_rule] = py_rule["udp_rule"]
            if py_rule.get("coap_rule"):
                for ptr, rule in layer_rules.items():
                    if rule == py_rule["coap_rule"]:
                        c_rule.coap_rule = <clibschc.schc_coap_rule_t *>(<intptr_t>ptr)
                if not c_rule.coap_rule:
                    c_rule.coap_rule = clibschc.schc_rules_create_coap_rule()
                    Device._set_layer_rule(
                        <clibschc.schc_layer_rule_t *>c_rule.coap_rule,
                        py_rule["coap_rule"],
                        clibschc.COAP_FIELDS
                    )
                    layer_rules[<intptr_t>c_rule.coap_rule] = py_rule["coap_rule"]
        except ValueError as exc:
            raise ValueError(f"Error on rule {py_rule['rule_id']}: {exc}") from exc

    @staticmethod
    cdef _frag_ctx_to_dict(const clibschc.schc_fragmentation_rule_t **ctx, int i):
        cdef clibschc.schc_fragmentation_rule_t *c_rule = ctx[i]
        py_rule = {
            "rule_id": c_rule.rule_id,
            "rule_id_size_bits": c_rule.rule_id_size_bits,
            "FCN_SIZE": c_rule.FCN_SIZE,
            "MAX_WND_FCN": c_rule.MAX_WND_FCN,
            "WINDOW_SIZE": c_rule.WINDOW_SIZE,
            "DTAG_SIZE": c_rule.DTAG_SIZE,
        }
        try:
            py_rule["mode"] = FragmentationMode(<int>c_rule.mode)
            py_rule["dir"] = Direction(<int>c_rule.dir)
        except ValueError as exc:
            raise ValueError(
                f"Error on partially constructed rule {py_rule}: {exc}"
            ) from exc
        return py_rule

    @staticmethod
    cdef _set_fragmentation_rule(
        clibschc.schc_fragmentation_rule_t *c_rule,
        dict py_rule
    ):
        c_rule.rule_id = py_rule["rule_id"]
        c_rule.rule_id_size_bits = py_rule["rule_id_size_bits"]
        c_rule.mode = <clibschc.reliability_mode>(<int>py_rule["mode"].value)
        c_rule.dir = <clibschc.direction>(<int>py_rule["dir"].value)
        c_rule.FCN_SIZE = py_rule["FCN_SIZE"]
        c_rule.MAX_WND_FCN = py_rule["MAX_WND_FCN"]
        c_rule.WINDOW_SIZE = py_rule["WINDOW_SIZE"]
        c_rule.DTAG_SIZE = py_rule["DTAG_SIZE"]
    property compression_rules:
        def __get__(self):
            res = []
            for i in range(self._dev.compression_rule_count):
                py_rule = Device._comp_ctx_to_dict(
                    self._dev.compression_context, <int>i
                )
                res.append(py_rule)
            return res

        def __set__(self, rules: typing.Optional[typing.Sequence[dict]]):
            if self._dev.compression_context:
                clibschc.schc_rules_free_compr_ctx(
                    <clibschc.schc_compression_rule_t **>self._dev.compression_context,
                    self._dev.compression_rule_count
                )
            if rules:
                rule_count = len(rules)
                context = clibschc.schc_rules_create_compr_ctx(<unsigned>len(rules))
                try:
                    layer_rules = {}
                    for i, py_rule in enumerate(rules):
                        Device._set_compression_rule(layer_rules, context[i], py_rule)
                except ValueError:
                    clibschc.schc_rules_free_compr_ctx(context, rule_count)
                    raise
                else:
                    self._dev.compression_context = context
                    self._dev.compression_rule_count = rule_count
            else:
                self._dev.compression_context = NULL
                self._dev.compression_rule_count = 0

        def __del__(self):
            clibschc.schc_rules_free_compr_ctx(
                <clibschc.schc_compression_rule_t **>self._dev.compression_context,
                self._dev.compression_rule_count
            )
            self._dev.compression_context = NULL
            self._dev.compression_rule_count = 0

    property device_id:
        def __get__(self):
            return self._dev.device_id

    property fragmentation_rules:
        def __get__(self):
            res = []
            for i in range(self._dev.fragmentation_rule_count):
                py_rule = Device._frag_ctx_to_dict(
                    self._dev.fragmentation_context, <int>i
                )
                res.append(py_rule)
            return res

        def __set__(self, rules: typing.Optional[typing.Sequence[dict]]):
            if self._dev.fragmentation_context:
                clibschc.schc_rules_free_frag_ctx(
                    <clibschc.schc_fragmentation_rule_t **>
                    self._dev.fragmentation_context,
                    self._dev.fragmentation_rule_count
                )
            if rules:
                rule_count = len(rules)
                context = clibschc.schc_rules_create_frag_ctx(<unsigned>len(rules))
                try:
                    for i, py_rule in enumerate(rules):
                        Device._set_fragmentation_rule(context[i], py_rule)
                except ValueError:
                    clibschc.schc_rules_free_frag_ctx(context, rule_count)
                    raise
                else:
                    self._dev.fragmentation_context = context
                    self._dev.fragmentation_rule_count = rule_count
            else:
                self._dev.fragmentation_context = NULL
                self._dev.fragmentation_rule_count = 0

        def __del__(self):
            clibschc.schc_rules_free_frag_ctx(
                <clibschc.schc_fragmentation_rule_t **>self._dev.fragmentation_context,
                self._dev.fragmentation_rule_count
            )
            self._dev.fragmentation_context = NULL
            self._dev.fragmentation_rule_count = 0

    property uncompressed_rule_id:
        def __get__(self):
            return self._dev.uncomp_rule_id

        def __set__(self, uncompressed_rule_id):
            self._dev.uncomp_rule_id = uncompressed_rule_id

    property uncompressed_rule_id_size_bits:
        def __get__(self):
            return self._dev.uncomp_rule_id_size_bits

        def __set__(self, uncompressed_rule_id_size_bits):
            self._dev.uncomp_rule_id_size_bits = uncompressed_rule_id_size_bits

    def unregister(self):
        self._unregister()


class CompressionResult(enum.Enum):
    UNCOMPRESSED = 0
    COMPRESSED = 1


cdef class CompressorDecompressor:
    @staticmethod
    def init():
        clibschc.schc_compressor_init()

    @staticmethod
    def compress(data: bytes, device: Device, dir: Direction) -> tuple[
        CompressionResult,
        BitArray
    ]:
        cdef clibschc.schc_compression_rule_t *rule
        # need at minimum length + 1
        bit_arr = BitArray(
            len(data) + clibschc.BITS_TO_BYTES(device.uncompressed_rule_id_size_bits)
        )
        rule = clibschc.schc_compress(
            <uint8_t *>(<char *>data),
            len(data),
            &bit_arr._bit_array,
            device.device_id,
            <clibschc.direction>dir.value
        )
        if rule == NULL:
            if bit_arr.length == 0:
                raise ValueError(
                    f"Unable to compress (maybe wrong device #{device.device_id}?)"
                )
            return CompressionResult.UNCOMPRESSED, bit_arr
        return CompressionResult.COMPRESSED, bit_arr

    @staticmethod
    def decompress(bit_arr: BitArray, device: Device, dir: Direction) -> bytes:
        buf = b"\0" * clibschc.MAX_MTU_LENGTH
        cdef uint16_t length = clibschc.schc_decompress(
            &bit_arr._bit_array,
            <uint8_t *>(<char *>buf),
            device.device_id,
            bit_arr.length,
            <clibschc.direction>dir.value
        )
        return buf[:length]


class FragmentationResult(enum.Enum):
    NO_FRAGMENTATION = clibschc.SCHC_NO_FRAGMENTATION
    SUCCESS = clibschc.SCHC_SUCCESS
    ACK_INPUT = clibschc.SCHC_ACK_INPUT
    FRAG_INPUT = clibschc.SCHC_FRAG_INPUT
    END = clibschc.SCHC_END


cdef class _TimerArgWrapper:
    cdef intptr_t _ptr

    def __cinit__(self, ptr):
        self._ptr = <intptr_t>ptr

    property ptr_int:
        def __get__(self) -> int:
            return self._ptr

    def __str__(self):
        return "<_TimerArgWrapper: 0x%x>" % (<intptr_t>self._ptr)


cdef class FragmentationConnection:
    cdef public bool fragmented
    cdef public int _in_timer
    cdef object _py_post_timer_task
    cdef object _py_end_rx
    cdef object _py_end_tx
    cdef object _py_remove_timer_entry
    cdef object _bit_arr
    cdef clibschc.schc_fragmentation_t *_frag_conn
    cdef uint8_t _malloced
    _device_sends = {}

    def __cinit__(
        self,
        post_timer_task: typing.Callable[
            [
                'FragmentationConnection',
                typing.Callable[[_TimerArgWrapper], None],
                float,
                _TimerArgWrapper,
            ],
            None
        ] = None,
        end_rx: typing.Callable[['FragmentationConnection'], None] = None,
        end_tx: typing.Callable[['FragmentationConnection'], None] = None,
        remove_timer_entry: typing.Callable[['FragmentationConnection'], None] = None,
        _malloc_inner: bool = True
    ):
        self._bit_arr = None
        self._in_timer = 0

        self._py_post_timer_task = post_timer_task
        self._py_end_rx = end_rx
        self._py_end_tx = end_tx
        self._py_remove_timer_entry = remove_timer_entry
        self.fragmented = False
        self._malloced = _malloc_inner
        if _malloc_inner:
            try:
                self._frag_conn = <clibschc.schc_fragmentation_t *>malloc(
                    sizeof(clibschc.schc_fragmentation_t)
                )
                if not self._frag_conn:
                    raise MemoryError(
                        "Unable to allocate inner fragmentation connection"
                    )
                memset(self._frag_conn, 0, sizeof(self._frag_conn[0]))
                self._init_ops()
            except Exception:
                free(self._frag_conn)
                raise MemoryError("Unable to allocate inner fragmentation connection")
        else:
            self._frag_conn = NULL

    def _init_ops(self):
        self._frag_conn.timer_ctx = <void *>self
        self._frag_conn.send = self._send
        self._frag_conn.post_timer_task = self._c_post_timer_task
        self._frag_conn.end_rx = self._c_end_rx
        self._frag_conn.end_tx = self._c_end_tx
        self._frag_conn.remove_timer_entry = self._c_remove_timer_entry

    def __dealloc__(self):
        if self._frag_conn and self._malloced:
            self._frag_conn.timer_ctx = NULL
            free(self._frag_conn)
            self._malloced = False
            self._frag_conn = NULL

    def __hash__(self):
        return <intptr_t>(<void *>(self._frag_conn))

    def __eq__(self, other: FragmentationConnection) -> bool:
        return hash(self) == hash(other)

    def __ne__(self, other: FragmentationConnection) -> bool:
        return not (self == other)

    property post_timer_task:
        def __get__(self) -> typing.Callable[
            [
                'FragmentationConnection',
                typing.Callable[[_TimerArgWrapper], None],
                float,
                _TimerArgWrapper
            ],
            None
        ]:
            if self._py_post_timer_task is not None:
                return self._py_post_timer_task
            return None

        def __set__(
            self,
            post_timer_task: typing.Optional[
                typing.Callable[
                    [
                        'FragmentationConnection',
                        typing.Callable[[_TimerArgWrapper], None],
                        float,
                        _TimerArgWrapper
                    ],
                    None
                ]
            ]
        ):
            self._py_post_timer_task = post_timer_task

        def __del__(self):
            self._py_post_timer_task = None

    property end_rx:
        def __get__(self) -> typing.Optional[
            typing.Callable[['FragmentationConnection'], None]
        ]:
            if self._py_end_rx is not None:
                return self._py_end_rx
            return None

        def __set__(
            self,
            end_rx: typing.Optional[typing.Callable[['FragmentationConnection'], None]]
        ):
            self._py_end_rx = end_rx

        def __del__(self):
            self._py_end_rx = None

    property end_tx:
        def __get__(self) -> typing.Optional[
            typing.Callable[['FragmentationConnection'], None]
        ]:
            if self._py_end_tx is not None:
                return self._py_end_tx
            return None

        def __set__(
            self,
            end_tx: typing.Optional[typing.Callable[['FragmentationConnection'], None]]
        ):
            self._py_end_tx = end_tx

        def __del__(self):
            self._py_end_tx = None

    property remove_timer_entry:
        def __get__(self) -> typing.Optional[
            typing.Callable[['FragmentationConnection'], None]
        ]:
            if self._py_remove_timer_entry is not None:
                return self._py_remove_timer_entry
            return None

        def __set__(
            self,
            remove_timer_entry: typing.Optional[
                typing.Callable[['FragmentationConnection'], None]
            ]
        ):
            self._py_remove_timer_entry = remove_timer_entry

        def __del__(self):
            self._py_remove_timer_entry = None

    property bit_arr:
        def __get__(self) -> BitArray:
            return self._bit_arr

        def __set__(self, bit_arr: BitArray):
            self._bit_arr = bit_arr
            self._frag_conn.bit_arr = &bit_arr._bit_array

        def __del__(self):
            self._bit_arr = None
            self._frag_conn.bit_arr = NULL

    property mbuf:
        def __get__(self) -> bytes:
            return self._get_mbuf()

    cdef _get_mbuf(self):
        cdef clibschc.schc_fragmentation_t *conn = self._frag_conn
        cdef size_t size = clibschc.get_mbuf_len(conn)
        buf = b"\0" * size
        clibschc.mbuf_copy(conn, <uint8_t *>(<char *>buf))
        return buf

    def _allocated(self):
        return self._frag_conn is not NULL and self._frag_conn.timer_ctx is not NULL

    @staticmethod
    cdef _outer_from_struct(clibschc.schc_fragmentation_t *conn):
        if conn.timer_ctx:
            obj = <FragmentationConnection>conn.timer_ctx
            if not obj._allocated():
                for _ in range(obj._in_timer):
                    Py_DECREF(obj)
                    obj._in_timer -= 1
                return None
            return obj
        return None

    @staticmethod
    cdef uint8_t _send(uint8_t *data, uint16_t length, uint32_t device_id):
        if device_id in FragmentationConnection._device_sends:
            try:
                return <uint8_t>FragmentationConnection._device_sends[
                    device_id
                ](<bytes>data[:length])
            except Exception:
                raise
        else:
            raise ProcessLookupError(f"No send registered for device #{device_id}")

    @staticmethod
    cdef void _c_end_rx(clibschc.schc_fragmentation_t *conn):
        try:
            obj = FragmentationConnection._outer_from_struct(conn)
            if obj and obj.end_rx:
                obj.end_rx(obj)
        except Exception:
            raise

    @staticmethod
    cdef void _c_end_tx(clibschc.schc_fragmentation_t *conn):
        try:
            obj = FragmentationConnection._outer_from_struct(conn)
            if obj and obj.end_tx:
                obj.end_tx(obj)
        except Exception:
            raise

    @staticmethod
    cdef void _c_remove_timer_entry(clibschc.schc_fragmentation_t *conn):
        try:
            obj = FragmentationConnection._outer_from_struct(conn)
            if obj:
                if obj.remove_timer_entry:
                    obj.remove_timer_entry(obj)
                if obj._in_timer:
                    Py_DECREF(obj)
                    obj._in_timer -= 1
        except Exception:
            raise

    @staticmethod
    cdef void _c_post_timer_task(
        clibschc.schc_fragmentation_t *conn,
        void (*timer_task)(void *arg),
        uint32_t time_ms,
        void *arg
    ):
        obj = FragmentationConnection._outer_from_struct(conn)
        if obj and obj.post_timer_task:
            def _timer_task_wrapper(arg: _TimerArgWrapper):
                if obj._allocated():
                    # only call if schc_fragmentation_schc_t is still allocated
                    timer_task(<void *>(<intptr_t>arg.ptr_int))
                else:
                    logger.info(
                        "Timer fired with an unallocated fragmentation connection"
                    )
                if obj._in_timer:
                    Py_DECREF(obj)
                    obj._in_timer -= 1

            Py_INCREF(obj)
            obj._in_timer += 1
            obj.post_timer_task(
                obj,
                _timer_task_wrapper,
                time_ms / 1000,
                _TimerArgWrapper(<intptr_t>arg)
            )

    @staticmethod
    def register_send(device_id: int, send: typing.Callable[[bytes], int]):
        FragmentationConnection._device_sends[device_id] = send

    @staticmethod
    def unregister_send(device_id: int):
        del FragmentationConnection._device_sends[device_id]

    def init_rx(
        self,
        device_id: uint32_t,
        bit_arr: BitArray,
        dc: uint32_t,
    ):
        assert self._frag_conn, "FragmentationConnection not properly initialized"
        assert device_id in FragmentationConnection._device_sends, (
            f"No send registered for device #{device_id}"
        )
        assert self.end_rx is not None
        assert self.remove_timer_entry is not None
        self._frag_conn.device_id = device_id
        self.bit_arr = bit_arr
        self._frag_conn.dc = dc

    def init_tx(
        self,
        device_id: uint32_t,
        bit_arr: BitArray,
        mtu: uint16_t,
        dc: uint32_t,
        mode: clibschc.reliability_mode
    ):
        assert self._frag_conn, "FragmentationConnection not properly initialized"
        assert device_id in FragmentationConnection._device_sends, (
            f"No send registered for device #{device_id}"
        )
        assert self.end_rx is not None
        assert self.remove_timer_entry is not None
        if clibschc.schc_fragmenter_init(
            self._frag_conn, self._send, self._c_end_rx, self._c_remove_timer_entry
        ) != 1:
            raise MemoryError("Unable to initialize FragmentationConnection")
        self._init_ops()
        self._frag_conn.fragmentation_rule = (
            clibschc.get_fragmentation_rule_by_reliability_mode(mode, device_id)
        )
        if self._frag_conn.fragmentation_rule is NULL:
            raise ValueError(
                "Unable to find fragmentation rule for mode "
                f"{FragmentationMode(mode)} on device #{device_id}"
            )
        self._frag_conn.device_id = device_id
        self.bit_arr = bit_arr
        self._frag_conn.mtu = mtu
        self._frag_conn.dc = dc

    cdef int8_t _fragment(self):
        cdef int8_t res
        try:
            assert self._frag_conn, (
                f"FragmentationConnection {self} not properly initialized"
            )
            res = <int8_t>clibschc.schc_fragment(self._frag_conn)
            if res == clibschc.SCHC_FAILURE:
                raise MemoryError(f"Unable to fragment on {self} due to resource issue")
            return res
        except Exception:
            raise

    def fragment(self) -> FragmentationResult:
        return FragmentationResult(self._fragment())

    @staticmethod
    cdef _set_frag_conn(
        FragmentationConnection obj, clibschc.schc_fragmentation_t *conn
    ):
        obj._frag_conn = conn
        obj._init_ops()

    cdef _input(self, char *buf, uint16_t length):
        cdef clibschc.schc_fragmentation_t *conn_ptr
        try:
            assert self._frag_conn, "FragmentationConnection not properly initialized"
            if not self._frag_conn.device_id:
                logger.info(
                    "%s (0x%x) has no device_id. This may happen if last ACK was "
                    "received as a duplicate.",
                    self,
                    <intptr_t>self._frag_conn
                )
                return None
            conn_ptr = clibschc.schc_input(
                <uint8_t *>buf, length, self._frag_conn, self._frag_conn.device_id
            )
            if conn_ptr == NULL:
                buffer = <bytes>buf[:length]
                raise MemoryError(
                    f"Unable to allocate a RX connection for {buffer.hex()}"
                )
            elif self._frag_conn != conn_ptr:
                res = FragmentationConnection(_malloc_inner=False)
                conn_ptr.post_timer_task = self._c_post_timer_task
                conn_ptr.dc = self._frag_conn.dc
                res.post_timer_task = self._py_post_timer_task
                res.end_rx = self._py_end_rx
                res.remove_timer_entry = self._py_remove_timer_entry
                FragmentationConnection._set_frag_conn(res, conn_ptr)
                if (
                    not conn_ptr.fragmentation_rule
                    or conn_ptr.fragmentation_rule.mode == clibschc.NOT_FRAGMENTED
                ):
                    res.fragmented = False
                else:
                    res.fragmented = True
            else:  # buf was an ACK
                res = self
                self.fragmented = False
            return res
        except Exception:
            raise

    def input(self, buffer: [bytes, BitArray]):
        try:
            if isinstance(buffer, BitArray):
                return self._input(_bit_array_ptr(buffer), buffer.length)
            return self._input(<char *>buffer, len(buffer))
        except Exception:
            raise

    cdef int8_t _reassemble(self):
        try:
            assert self._frag_conn, "FragmentationConnection not properly initialized"
            assert self._frag_conn.fragmentation_rule, (
                f"No fragmentation rule found for {self}"
            )
            res = clibschc.schc_reassemble(self._frag_conn)
            if (  # last fragment received with NO_ACK
                res
                and self._frag_conn.fragmentation_rule != NULL
                and self._frag_conn.fragmentation_rule.mode == clibschc.NO_ACK
            ):
                if self._py_end_rx:
                    self._py_end_rx(self)
                self.reset()
            return res
        except Exception:
            raise

    def reassemble(self) -> int:
        return self._reassemble()

    def reset(self):
        if (self._frag_conn):
            clibschc.schc_reset(self._frag_conn)
            if self._malloced:
                self._frag_conn.timer_ctx = <void *>self
            else:  # was allocated by libschc => discard
                self._frag_conn = NULL


PYLOG_BUFFER_SIZE = clibschc.PYLOG_BUFFER_SIZE


def test_pylog_debug(fmt: bytes, str_arg: bytes, int_arg: int):
    clibschc.pylog_debug(fmt, <char *>str_arg, <int>int_arg)

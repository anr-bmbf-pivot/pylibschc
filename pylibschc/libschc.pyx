# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

import typing

from cpython.bool cimport bool
from cython.operator cimport postincrement as inc, postdecrement as dec
from libc.stddef cimport size_t
from libc.stdint cimport uint8_t, uint16_t, uint32_t
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
        except:
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

    cdef clibschc.schc_device _dev;

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
            raise ValueError(f"undefined match operator")

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
        clibschc.schc_compression_rule_t *c_rule, dict py_rule
    ):
        cdef uint8_t *test = <uint8_t *>malloc(6)
        c_rule.rule_id = py_rule["rule_id"]
        c_rule.rule_id_size_bits = py_rule["rule_id_size_bits"]
        try:
            if py_rule.get("ipv6_rule"):
                c_rule.ipv6_rule = clibschc.schc_rules_create_ipv6_rule()
                Device._set_layer_rule(
                    <clibschc.schc_layer_rule_t *>c_rule.ipv6_rule,
                    py_rule["ipv6_rule"],
                    clibschc.IP6_FIELDS
                )
            if py_rule.get("udp_rule"):
                c_rule.udp_rule = clibschc.schc_rules_create_udp_rule()
                Device._set_layer_rule(
                    <clibschc.schc_layer_rule_t *>c_rule.udp_rule,
                    py_rule["udp_rule"],
                    clibschc.UDP_FIELDS
                )
            if py_rule.get("coap_rule"):
                c_rule.coap_rule = clibschc.schc_rules_create_coap_rule()
                Device._set_layer_rule(
                    <clibschc.schc_layer_rule_t *>c_rule.coap_rule,
                    py_rule["coap_rule"],
                    clibschc.COAP_FIELDS
                )
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
    cdef _set_fragmentation_rule(clibschc.schc_fragmentation_rule_t *c_rule,
                                      dict py_rule):
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
                    for i, py_rule in enumerate(rules):
                        Device._set_compression_rule(context[i], py_rule)
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

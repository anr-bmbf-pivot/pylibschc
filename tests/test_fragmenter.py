# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import asyncio
import queue
import threading
import typing

import pytest

from scapy.all import (  # pylint: disable=no-name-in-module
    IPv6,
    UDP,
)
from scapy.contrib.coap import CoAP

import pylibschc.compressor
import pylibschc.fragmenter
import pylibschc.rules

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


MTU = 60
DUTY_CYCLE_MS = 100

TEST_PARAMS = [
    (
        pylibschc.fragmenter.FragmentationMode.NO_ACK,
        bytes,
        b"foobar",
        False,
        pylibschc.fragmenter.FragmentationResult.NO_FRAGMENTATION,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.NO_ACK,
        bytes,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.NO_ACK,
        pylibschc.fragmenter.BitArray,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.NO_ACK,
        bytes,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy "
        b"eirmod tempor invidunt ut labore et dolore magna aliquyam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.NO_ACK,
        bytes,
        bytes(
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
            / b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam"
        ),
        True,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ALWAYS,
        bytes,
        b"foobar",
        False,
        pylibschc.fragmenter.FragmentationResult.NO_FRAGMENTATION,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ALWAYS,
        bytes,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ALWAYS,
        pylibschc.fragmenter.BitArray,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ALWAYS,
        bytes,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy "
        b"eirmod tempor invidunt ut labore et dolore magna aliquyam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ALWAYS,
        bytes,
        bytes(
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
            / b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam"
        ),
        True,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ON_ERROR,
        bytes,
        b"foobar",
        False,
        pylibschc.fragmenter.FragmentationResult.NO_FRAGMENTATION,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ON_ERROR,
        bytes,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ON_ERROR,
        bytes,
        b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy "
        b"eirmod tempor invidunt ut labore et dolore magna aliquyam",
        False,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
    (
        pylibschc.fragmenter.FragmentationMode.ACK_ON_ERROR,
        bytes,
        bytes(
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
            / b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam"
        ),
        True,
        pylibschc.fragmenter.FragmentationResult.SUCCESS,
    ),
]


class TestFragmenterReassemblerThreaded:  # pylint: disable=too-many-instance-attributes
    # pylint: disable=attribute-defined-outside-init
    def setup_method(self, method):  # pylint: disable=unused-argument
        self.timers = {}
        self.fragmenter_queue = queue.Queue()
        self.end_tx_called = False
        self.reassembler_queue = queue.Queue()
        self.timer_lock = threading.Lock()

    def teardown_method(self, method):  # pylint: disable=unused-argument
        for timer in list(self.timers.values()):
            # wait for threads to finish to free all resources
            if timer.is_alive():  # pragma: no cover
                timer.cancel()
                timer.join()
        # cleanup removed but still running Timer threads
        for timer in [t for t in threading.enumerate() if t.name.startswith("Timer-")]:
            if timer.is_alive():  # pragma: no cover
                timer.cancel()
                timer.join()

    def send(self, buffer: bytes) -> int:
        assert len(buffer) <= MTU
        self.fragmenter_queue.put_nowait(buffer)
        return len(buffer)

    def post_timer_task(
        self,
        conn: pylibschc.fragmenter.FragmentationConnection,
        timer_task: typing.Callable[[object], None],
        delay_sec: float,
        arg: object,
    ) -> None:
        def _timer_task(the_arg):
            with self.timer_lock:
                return timer_task(the_arg)

        if conn in self.timers:
            self.timers[conn].cancel()
        self.timers[conn] = threading.Timer(delay_sec, _timer_task, args=(arg,))
        self.timers[conn].name = f"Timer-{conn}"
        self.timers[conn].start()

    def end_rx(self, conn: pylibschc.fragmenter.FragmentationConnection):
        self.reassembler_queue.put_nowait(conn.mbuf)

    def end_tx(self, conn: pylibschc.fragmenter.FragmentationConnection):
        # pylint: disable=unused-argument
        self.end_tx_called = True

    def remove_timer_entry(self, conn: pylibschc.fragmenter.FragmentationConnection):
        if conn in self.timers:
            self.timers[conn].cancel()
            del self.timers[conn]

    def reassemble(self):
        try:
            while True:
                buffer = self.fragmenter_queue.get(timeout=5 * (DUTY_CYCLE_MS / 1000))
                is_fragmented = False
                for rule in self.fragmenter.device.fragmentation_rules:
                    assert rule.rule_id_size_bits == 8
                    if rule.rule_id == buffer[0]:
                        is_fragmented = True
                if is_fragmented:
                    if len(buffer) <= 2:
                        with self.timer_lock:
                            # is an ACK, handle at fragmenter
                            assert self.fragmenter.input(self.input_type(buffer)) == (
                                pylibschc.fragmenter.ReassemblyStatus.ACK_HANDLED
                            )
                    else:
                        with self.timer_lock:
                            # otherwise handle at reassembler
                            res = self.reassembler.input(self.input_type(buffer))
                        assert res in (
                            pylibschc.fragmenter.ReassemblyStatus.STAY_ALIVE,
                            pylibschc.fragmenter.ReassemblyStatus.COMPLETED,
                            pylibschc.fragmenter.ReassemblyStatus.ONGOING,
                        )
                else:
                    with self.timer_lock:
                        # otherwise handle at reassembler
                        assert (
                            self.reassembler.input(self.input_type(buffer))
                            == pylibschc.fragmenter.ReassemblyStatus.COMPLETED
                        )
        except queue.Empty:
            assert self.end_tx_called

    @pytest.mark.parametrize(
        "mode, input_type, data, compress_data, exp_result", TEST_PARAMS
    )
    def test_fragmenter_reassembler_threaded(  # pylint: disable=too-many-arguments
        self, test_rules, mode, input_type, data, compress_data, exp_result
    ):
        config = test_rules.deploy()
        device = config.devices[0]
        assert device.mtu == MTU
        assert device.duty_cycle_ms == DUTY_CYCLE_MS
        self.input_type = input_type
        cr = (  # pylint: disable=invalid-name
            pylibschc.compressor.CompressorDecompressor(
                device, direction=pylibschc.rules.Direction.DOWN
            )
        )
        self.fragmenter = pylibschc.fragmenter.Fragmenter(
            device=device,
            mode=mode,
            post_timer_task=self.post_timer_task,
            end_tx=self.end_tx,
            remove_timer_entry=self.remove_timer_entry,
        )
        with pytest.raises(RuntimeError):
            self.fragmenter.input(b"\x03\x03")
        self.reassembler = pylibschc.fragmenter.Reassembler(
            device=device,
            post_timer_task=self.post_timer_task,
            end_rx=self.end_rx,
            remove_timer_entry=self.remove_timer_entry,
        )
        self.fragmenter.register_send(device, self.send)
        with self.timer_lock:
            if compress_data:
                res, pkt = cr.output(self.input_type(data))
                assert res == pylibschc.compressor.CompressionResult.COMPRESSED
                assert self.fragmenter.output(pkt) == exp_result
            else:
                assert self.fragmenter.output(self.input_type(data)) == exp_result
        self.reassemble()
        pkt = self.reassembler_queue.get(timeout=(DUTY_CYCLE_MS / 1000) * 10)
        if compress_data:
            assert cr.input(pkt) == data
        else:
            assert pkt == data
        self.fragmenter.unregister_send(device)


class TestFragmenterReassemblerAsync:  # pylint: disable=too-many-instance-attributes
    # pylint: disable=attribute-defined-outside-init
    def setup_method(self, method):  # pylint: disable=unused-argument
        self.timer_tasks = {}
        self.fragmenter_queue = asyncio.Queue()

    def teardown_method(self, method):  # pylint: disable=unused-argument
        for timer_task in list(self.timer_tasks.values()):
            timer_task.cancel()  # pragma: no cover

    def send(self, buffer: bytes) -> int:
        assert len(buffer) <= MTU
        self.fragmenter_queue.put_nowait({"cmd": "send", "data": buffer})
        return len(buffer)

    def post_timer_task(
        self,
        conn: pylibschc.fragmenter.FragmentationConnection,
        timer_task: typing.Callable[[object], None],
        delay_sec: float,
        arg: object,
    ) -> None:
        def _timer_task(the_arg):
            return timer_task(the_arg)

        if conn in self.timer_tasks:
            self.timer_tasks[conn].cancel()
        self.timer_tasks[conn] = self.loop.call_later(delay_sec, _timer_task, arg)

    def end_rx(self, conn: pylibschc.fragmenter.FragmentationConnection):
        self.reassembly_buffer.set_result(conn.mbuf)

    def end_tx(self, conn: pylibschc.fragmenter.FragmentationConnection):
        # pylint: disable=unused-argument
        self.fragmenter_queue.put_nowait({"cmd": "end_rx"})

    def remove_timer_entry(self, conn: pylibschc.fragmenter.FragmentationConnection):
        if conn in self.timer_tasks:
            self.timer_tasks[conn].cancel()
            self.timer_tasks.pop(conn)

    async def reassemble(self):
        async def inp(handler, buffer):
            return handler.input(buffer)

        while True:
            cmd = await asyncio.wait_for(
                self.fragmenter_queue.get(), timeout=5 * (DUTY_CYCLE_MS / 1000)
            )
            if cmd["cmd"] == "end_rx":
                break
            assert cmd["cmd"] == "send"
            buffer = cmd["data"]
            is_fragmented = False
            for rule in self.fragmenter.device.fragmentation_rules:
                assert rule.rule_id_size_bits == 8
                if rule.rule_id == buffer[0]:
                    is_fragmented = True
            if is_fragmented:
                if len(buffer) <= 2:
                    # is an ACK, handle at fragmenter
                    res = await inp(self.fragmenter, self.input_type(buffer))
                    assert res == pylibschc.fragmenter.ReassemblyStatus.ACK_HANDLED
                else:
                    # otherwise handle at reassembler
                    res = await inp(self.reassembler, self.input_type(buffer))
                    assert res in (
                        pylibschc.fragmenter.ReassemblyStatus.STAY_ALIVE,
                        pylibschc.fragmenter.ReassemblyStatus.COMPLETED,
                        pylibschc.fragmenter.ReassemblyStatus.ONGOING,
                    )
            else:
                # otherwise handle at reassembler
                res = await inp(self.reassembler, self.input_type(buffer))
                assert res == pylibschc.fragmenter.ReassemblyStatus.COMPLETED

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "mode, input_type, data, compress_data, exp_result", TEST_PARAMS
    )
    async def test_fragmenter_reassembler_async(  # pylint: disable=too-many-arguments
        self, test_rules, mode, input_type, data, compress_data, exp_result
    ):
        async def output(buffer):
            return self.fragmenter.output(buffer)

        self.loop = asyncio.get_running_loop()
        self.reassembly_buffer = self.loop.create_future()
        config = test_rules.deploy()
        device = config.devices[0]
        assert device.mtu == MTU
        assert device.duty_cycle_ms == DUTY_CYCLE_MS
        self.input_type = input_type
        cr = (  # pylint: disable=invalid-name
            pylibschc.compressor.CompressorDecompressor(
                device, direction=pylibschc.rules.Direction.DOWN
            )
        )
        self.fragmenter = pylibschc.fragmenter.Fragmenter(
            device=device,
            mode=mode,
            post_timer_task=self.post_timer_task,
            end_tx=self.end_tx,
            remove_timer_entry=self.remove_timer_entry,
        )
        with pytest.raises(RuntimeError):
            self.fragmenter.input(b"\x03\x03")
        self.reassembler = pylibschc.fragmenter.Reassembler(
            device=device,
            post_timer_task=self.post_timer_task,
            end_rx=self.end_rx,
            remove_timer_entry=self.remove_timer_entry,
        )
        self.fragmenter.register_send(device, self.send)
        if compress_data:
            res, pkt = cr.output(self.input_type(data))
            assert res == pylibschc.compressor.CompressionResult.COMPRESSED
            assert await output(pkt) == exp_result
        else:
            assert await output(self.input_type(data)) == exp_result
        await self.reassemble()
        pkt = await asyncio.wait_for(
            self.reassembly_buffer, timeout=(DUTY_CYCLE_MS / 1000) * 10
        )
        if compress_data:
            assert cr.input(pkt) == data
        else:
            assert pkt == data
        self.fragmenter.unregister_send(device)

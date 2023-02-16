# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

"""User-facing fragmenter/reassembler functionality"""

import abc
import threading
import typing

import pylibschc.device

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


# pylint: disable=import-error
from .libschc import (
    BitArray,
    FragmenterOps,
    FragmentationConnection,
    FragmentationMode,
    FragmentationResult,
    ReassemblyStatus,
)


class BaseFragmenterReassembler(FragmenterOps):
    """Base class for both fragmenters and reassemblers."""

    # pylint: disable=too-few-public-methods
    conn_cls = FragmentationConnection

    def __init__(  # pylint: disable=too-many-arguments
        self,
        device: pylibschc.device.Device,
        mode: FragmentationMode = None,
        end_rx: typing.Callable[[FragmentationConnection], None] = None,
        end_tx: typing.Callable[[FragmentationConnection], None] = None,
        post_timer_task: typing.Callable[
            [FragmentationConnection, typing.Callable[[object], None], float, object],
            None,
        ] = None,
        remove_timer_entry: typing.Callable[[FragmentationConnection], None] = None,
    ):
        """
        :param device: The device to use for fragmentation/reassembly.
        :param mode: (optional) The :class:`pylibschc.libschc.FragmentationMode` to use.
        :param end_rx: (optional) The callback that is called when the reception of a
            packet is complete.
        :param end_tx: (optional) Callback that is called when the transmission of a
            packet is complete.
        :param post_timer_task: (optional) Callback that is called when a timer task
            needs to be scheduled.
        :param remove_timer_entry: (optional) Callback that is called when a timer task
            needs to be canceled. May be None.
        """
        super().__init__(
            end_rx=end_rx,
            end_tx=end_tx,
            post_timer_task=post_timer_task,
            remove_timer_entry=remove_timer_entry,
        )
        self.device = device
        self.mode = mode

    @abc.abstractmethod
    def input(self, data: typing.Union[bytes, BitArray]) -> ReassemblyStatus:
        """Handle incoming data.

        :param data: Either an ACK, a fragment, or an unfragmented packet.
        :return: Status of reassembly or if ACK was handled.
        """
        pass  # pragma: no cover pylint: disable=unnecessary-pass


class Fragmenter(BaseFragmenterReassembler):
    """A fragmenter."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tx_conn = None
        self._tx_conn_lock = threading.Lock()

    def _tx_conn_release(self):
        del self._tx_conn
        self._tx_conn = None
        self._tx_conn_lock.release()

    def _end_fragmentation_tx(self, conn: object):
        if self.end_tx:  # pragma: no cover
            self.end_tx(conn)
        self._tx_conn_release()

    def input(self, data: typing.Union[bytes, BitArray]) -> ReassemblyStatus:
        """Handle incoming an ACK.

        :param data: An ACK.
        :raise RuntimeError: if ``data`` was not an ACK or if the fragmenter never sent
            a fragment for which the ACK should be handled.
        :retval ACK_HANDLED: when the ACK was handled."""
        if not self._tx_conn:
            raise RuntimeError("Unexpected state, you did not send a fragment yet")
        if isinstance(data, BitArray):
            bit_array = data
        else:
            bit_array = BitArray(data)
        self._tx_conn.bit_arr = bit_array
        new_conn = self._tx_conn.input(data)
        if new_conn is None:
            return ReassemblyStatus.ACK_HANDLED  # pragma: no cover
        if new_conn != self._tx_conn:  # pragma: no cover
            # is equal when acknowledgment was received
            if not new_conn.fragmented:
                if self.end_rx:
                    self.end_rx(new_conn)
                new_conn.reset()
            assert RuntimeError(
                f"Unexpected state, input {data.hex()} should be an ACK"
            )
        return ReassemblyStatus.ACK_HANDLED  # pragma: no cover

    def output(self, data: typing.Union[bytes, BitArray]) -> FragmentationResult:
        """Send ``data``, fragmented if necessary.

        :param data: The data to send.
        :retval NO_FRAGMENTATION: If the packet was not fragmented.
        :retval SUCCESS: If the packet was fragmented.
        """
        if isinstance(data, BitArray):
            bit_array = data
        else:
            bit_array = BitArray(data)
        self._tx_conn_lock.acquire()  # pylint: disable=consider-using-with
        assert self._tx_conn is None
        self._tx_conn = self.conn_cls(ops=self)
        self._tx_conn.init_tx(
            self.device.device_id,
            bit_array,
            self.device.mtu,
            self.device.duty_cycle_ms,
            self.mode.value,
        )
        try:
            res = self._tx_conn.fragment()
            if res == FragmentationResult.NO_FRAGMENTATION:
                self._end_fragmentation_tx(self._tx_conn)
            return res
        except Exception:  # pragma: no cover
            self._tx_conn_release()
            raise

    @classmethod
    def register_send(
        cls, device: pylibschc.device.Device, send: typing.Callable[[bytes], int]
    ):
        """Register a send function for a device.

        :param device: A device,
        :param send: The send function for ``device``.
        """
        return cls.conn_cls.register_send(device.device_id, send)

    @classmethod
    def unregister_send(cls, device: pylibschc.device.Device):
        """Remove a send function for a device.

        :param device: A device,
        """
        return cls.conn_cls.unregister_send(device.device_id)


class Reassembler(BaseFragmenterReassembler):  # pylint: disable=too-few-public-methods
    """A reassembler."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rx_conn = None
        self._rx_conn_lock = threading.Lock()

    def input(self, data: typing.Union[bytes, BitArray]) -> ReassemblyStatus:
        """Handle incoming data.

        :param data: Either a fragment or an unfragmented packet.
        :raise RuntimeError: if ``data`` was an ACK.
        :retval ONGOING: If reassembly is still missing fragments.
        :retval COMPLETED: If the fragment handled was the last missing fragment (or if
            the data was not fragmented).
        :retval STAY_ALIVE: If reassembly was completed, but the connection still is
            kept open, e.g., in case another ACK needs to be sent.
        """
        if isinstance(data, BitArray):
            bit_array = data
        else:
            bit_array = BitArray(data)
        with self._rx_conn_lock:
            if self._rx_conn is None:
                self._rx_conn = self.conn_cls(ops=self)
                self._rx_conn.init_rx(
                    self.device.device_id, bit_array, self.device.duty_cycle_ms
                )
            else:
                self._rx_conn.bit_arr = bit_array
            new_conn = self._rx_conn.input(data)
            if new_conn is None:
                return ReassemblyStatus.COMPLETED  # pragma: no cover
            if new_conn == self._rx_conn:  # is equal when acknowledgment was received
                assert RuntimeError(  # pragma: no cover
                    b"Unexpected state, input {data.hex()} should not be an ACK"
                )
            if not new_conn.fragmented:
                if self.end_rx:  # pragma: no cover
                    self.end_rx(new_conn)
                new_conn.reset()
                return ReassemblyStatus.COMPLETED
            return new_conn.reassemble()

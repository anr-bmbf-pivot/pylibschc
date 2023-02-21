# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

"""User-facing fragmenter/reassembler functionality"""

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
    RXState,
    TXState,
)


class FragmenterReassembler(FragmenterOps):
    """A handler for fragmentation and reassembly.

    .. warning::
       If you fragment and reassemble a packet on the same device, you need two objects
       of this type."""

    _AWAITING_ACK_TXSTATES = {TXState.WAIT_BITMAP, TXState.RESEND}
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

        .. py:attribute:: device
           :type: pylibschc.device.Device

           Device to be used for fragmentation/reassembly.

        .. py:attribute:: mode
           :type: pylibschc.libschc.FragmentationMode

           The :class:`pylibschc.libschc.FragmentationMode` to use. May be None.

        .. py:attribute:: end_rx
           :type: typing.Callable[[FragmentationConnection], None]

           The callback that is called when the reception of a packet is complete. May
           be None

        .. py:attribute:: end_tx
           :type: typing.Callable[[FragmentationConnection], None]

           Callback that is called when the transmission of a packet is complete. May be
           None.

        .. py:attribute:: post_timer_task
           :type: typing.Callable[
                    [
                        FragmentationConnection,
                        typing.Callable[[object], None],
                        float, object,
                    ],
                    None,
                ]

           Callback that is called when a timer task needs to be scheduled. May be None.

        .. py:attribute:: remove_timer_entry
           :type: typing.Callable[[FragmentationConnection], None]

           Callback that is called when a timer task needs to be canceled. May be None.
        """
        super().__init__(
            end_rx=end_rx,
            end_tx=self._end_fragmentation_tx,
            post_timer_task=post_timer_task,
            remove_timer_entry=remove_timer_entry,
        )
        self._real_end_tx = end_tx
        self.device = device
        self.mode = mode
        self._conn = self.conn_cls(ops=self)
        self._init_tx = False
        self._tx_conn_lock = threading.RLock()
        self._rx_conn_lock = threading.Lock()

    def _tx_conn_release(self):
        self._init_tx = False
        self._conn.reset()
        try:
            self._tx_conn_lock.release()
        except RuntimeError:
            pass

    def _end_fragmentation_tx(self, conn: FragmentationConnection):
        if self._real_end_tx:  # pragma: no cover
            self._real_end_tx(conn)
        self._tx_conn_release()

    @property
    def rx_state(self) -> RXState:
        """The transmission state of the FragmenterReassembler."""
        return self._conn.rx_state

    @property
    def tx_state(self) -> TXState:
        """The transmission state of the FragmenterReassembler."""
        return self._conn.tx_state

    def is_awaiting_ack(self) -> bool:
        """Check if we are currently waiting for ACKs.

        :retval True: when the :py:class:FragmenterReassembler is waiting for an ACK.
        :retval False: when the :py:class:FragmentationResult is not waiting for an ACK.
        """
        return self._conn.tx_state in self._AWAITING_ACK_TXSTATES

    def input(self, data: typing.Union[bytes, BitArray]) -> ReassemblyStatus:
        """Handle incoming data.

        :param data: Either an ACK, a fragment, or an unfragmented packet.
        :return: Status of reassembly or an ACK was handled.
        :raises MemoryError: If memory for fragment reception could not be allocated.
        :retval MIC_INCORRECT: when MIC was incorrect in received fragment.
        :retval ACK_HANDLED: when the ACK was handled.
        :retval ONGOING: If reassembly is still missing fragments.
        :retval COMPLETED: If the fragment handled was the last missing fragment (or if
            the data was not fragmented).
        :retval STAY_ALIVE: If reassembly was completed, but the connection still is
            kept open, e.g., in case another ACK needs to be sent.
        """
        with self._rx_conn_lock:
            if self.end_rx:
                with self._tx_conn_lock:
                    self._conn.init_rx(
                        self.device.device_id,
                        self.device.duty_cycle_ms,
                    )
            new_conn = self._conn.input(data)
            if new_conn is None:
                # duplicate ACK received
                return ReassemblyStatus.COMPLETED  # pragma: no cover
            if new_conn == self._conn:
                return ReassemblyStatus.ACK_HANDLED
            if not new_conn.fragmented:
                if self.end_rx:  # pragma: no cover
                    self.end_rx(new_conn)
                new_conn.reset()
                return ReassemblyStatus.COMPLETED
            return new_conn.reassemble()

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
        self._init_tx = True
        self._conn.init_tx(
            self.device.device_id,
            bit_array,
            self.device.mtu,
            self.device.duty_cycle_ms,
            self.mode.value,
        )
        try:
            res = self._conn.fragment()
            if res == FragmentationResult.NO_FRAGMENTATION:
                self._end_fragmentation_tx(self._conn)
            return res
        except Exception:  # pragma: no cover
            self._tx_conn_release()
            raise

    def register_send(self, send: typing.Callable[[bytes], int]):
        """Register a send function for the device of this fragmenter.

        :param send: The send function for ``device``.
        """
        return self.conn_cls.register_send(self.device.device_id, send)

    def unregister_send(self):
        """Remove a send function for the device of this fragmenter."""
        return self.conn_cls.unregister_send(self.device.device_id)

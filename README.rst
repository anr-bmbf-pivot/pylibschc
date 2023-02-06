=======================================
pylibschc: A python wrapper for libSCHC
=======================================

This provides a pythonic wrapper for `libSCHC`_.

Installation
============

You can use ``pip`` to install the package once you cloned this repo:

.. code:: bash

   git clone https://github.com/anr-bmbf-pivot/pylibschc.git
   cd pylibschc
   pip install .

Usage
=====

Rules
-----
Rules are managed using a `pydantic`_ model, i.e., they can be loaded from a correctly typed
dictionary (e.g. generated from a JSON or YAML file):

    >>> import json
    >>> from pylibschc.rules import Config
    >>>
    >>> with open("tests/artifacts/rules_example.json", encoding="utf-8") as f:
    ...    rules = Config(**json.load(f))
    ...    config = rules.deploy()

**Do not forget** to call ``rules.deploy()`` if you change any rules to re-deploy the rules with
libSCHC.

The header file for the rules, so they can be used with libSCHC on an embedded device, can be
generated using

    >>> with open("rule_config.h", "w", encoding="utf-8") as f:
    ...     written = f.write(rules.to_c_header())

An example for such a dictionary is provided in
`./tests/artifacts/rules_example.json <./tests/artifacts/rules_example.json>`_ as JSON, the
concrete `pydantic`_ model you can find `./pylibschc/rules.py <./pylibschc/rules.py>`_.

Compression/Decompression
-------------------------

Both compression and decompression can be achieved by using the `CompressorDecompressor` class from
the submodule `pylibschc.compressor <./pylibschc/compressor.py>`_. We use `scapy`_ in our example
to construct a valid CoAP over IPv6 packet for compression for which the ``output()`` method is
called:

    >>> from scapy.all import IPv6, UDP, raw
    >>> from scapy.contrib.coap import CoAP
    >>> import pylibschc.compressor
    >>>
    >>> comp_dec = pylibschc.compressor.CompressorDecompressor(
    ...     device=config.devices[0],
    ...     direction=pylibschc.rules.Direction.UP
    ... )
    >>> pkt = raw(
    ...     IPv6(hlim=64, src="2001:db8::1", dst="2001:db8:1::2")
    ...     / UDP(
    ...         sport=5683,
    ...         dport=61618,
    ...     )
    ...     / CoAP(
    ...         ver=1,
    ...         code="2.05 Content",
    ...         type="NON",
    ...         msg_id=0x23B3,
    ...         token=b"\x32\x3a\xf3\xa3",
    ...         paymark=b"\xff",
    ...     )
    ...     / (
    ...         b'[{"id":1, "name":"CJ.H.L.(Joe) Lecomte) Heliport","code":"YOY","country":"CA"}]'
    ...     )
    ... )
    >>> res, bit_array = comp_dec.output(pkt)
    >>> res
    <CompressionResult.COMPRESSED: 1>
    >>> bit_array.buffer
    b'\x01\t3#\xaf:5\xb7\xb2&\x96B#\xa3\x12\xc2\x02&\xe6\x16\xd6R#\xa2$4\xa2\xe4\x82\xe4\xc2\xe2\x84\xa6\xf6R\x92\x04\xc6V6\xf6\xd7FR\x92\x04\x86V\xc6\x97\x06\xf7\'B"\xc2&6\xf6FR#\xa2%\x94\xf5\x92"\xc2&6\xf7V\xe7G\'\x92#\xa2$4\x12\'\xd5\xd0'

For decompression, the `input()` method is called:

    >>> comp_dec.input(bit_array)
    b'`\x00\x00\x00\x00`\x11@ \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x163\xf0\xb2\x00`r\xf2TE#\xb32:\xf3\xa3\xff[{"id":1, "name":"CJ.H.L.(Joe) Lecomte) Heliport","code":"YOY","country":"CA"}]'
    >>> pkt == comp_dec.input(bit_array)
    True

Both ``input()`` and ``output()`` take either ``BitArray``- or ``bytes``-typed variables as input.

Fragmentation/Reassembly
------------------------

For fragmentation, call the ``output()`` method of a ``pylibschc.fragmenter.Fragmenter`` object.
To actually send then from the, a send function needs to be registered for the device of the
fragmenter.
For reassembly, call the ``input()`` method of a ``pylibschc.fragmenter.Reassembler`` object.
Acknowledgements can be handled by the ``input()`` method of the ``pylibschc.fragmenter.Fragmenter``
object. Again, both ``input()`` and ``output()`` take either ``BitArray``- or ``bytes``-typed
variables as input.

    >>> import asyncio
    >>> import logging
    >>> import pylibschc.fragmenter
    >>>
    >>> fragmenter_queue = None
    >>> loop = None
    >>> timer_tasks = {}
    >>> reassembly_buffer = None
    >>>
    >>> def send(buffer):
    ...     fragmenter_queue.put_nowait({"cmd": "send", "data": buffer})
    ...     return len(buffer)
    ...
    >>> def post_timer_task(conn, timer_task, delay_sec, arg):
    ...     if conn in timer_tasks:
    ...         remove_timer_entry(conn)
    ...     timer_tasks[conn] = loop.call_later(delay_sec, timer_task, arg)
    ...
    >>> def remove_timer_entry(conn):
    ...     if conn in timer_tasks:
    ...         timer_tasks[conn].cancel()
    ...         del timer_tasks[conn]
    ...
    >>> def end_rx(conn):
    ...     reassembly_buffer.set_result(conn.mbuf)
    ...
    >>> def end_tx(conn):
    ...     fragmenter_queue.put_nowait({"cmd": "end_tx"})
    ...
    >>> async def asyncized_input(reassembler, buffer):
    ...     return reassembler.input(buffer)
    ...
    >>> async def fragment_and_reassemble():
    ...     # just making sure these variables are initialized in the same loop
    ...     global fragmenter_queue
    ...     global loop
    ...     global reassembly_buffer
    ...
    ...     fragmenter_queue = asyncio.Queue()
    ...     loop = asyncio.get_running_loop()
    ...     reassembly_buffer = loop.create_future()
    ...     fragmenter = pylibschc.fragmenter.Fragmenter(
    ...         device=config.devices[0],
    ...         mtu=60,
    ...         duty_cycle_ms=500,
    ...         mode=pylibschc.fragmenter.FragmentationMode.NO_ACK,
    ...         post_timer_task=post_timer_task,
    ...         end_tx=end_tx,
    ...         remove_timer_entry=remove_timer_entry,
    ...     )
    ...     fragmenter.register_send(config.devices[0], send)
    ...     reassembler = pylibschc.fragmenter.Reassembler(
    ...         device=config.devices[0],
    ...         duty_cycle_ms=500,
    ...         post_timer_task=post_timer_task,
    ...         end_rx=end_rx,
    ...         remove_timer_entry=remove_timer_entry,
    ...     )
    ...     print("fragmenter.output ->", fragmenter.output(bit_array))
    ...     cmd = {}
    ...     while cmd.get("cmd") != "end_tx":
    ...         cmd = await asyncio.wait_for(fragmenter_queue.get(), timeout=2)
    ...         if cmd["cmd"] == "send":
    ...             print(
    ...                 "reassembler.input ->",
    ...                 await asyncized_input(reassembler, cmd["data"])
    ...             )
    ...     return await asyncio.wait_for(reassembly_buffer, timeout=5)
    ...
    >>> asyncio.run(fragment_and_reassemble()) == bit_array.buffer
    fragmenter.output -> FragmentationResult.SUCCESS
    reassembler.input -> ReassemblyStatus.ONGOING
    reassembler.input -> ReassemblyStatus.COMPLETED
    True

While this example uses `asyncio` to parallelize timer calls, any method to establish concurrency
can be used (see `./tests/test_fragmenter.py <./tests/test_fragmenter.py>`_ for an example using the
`threading` module) as long as the access to libSCHC (including calls to timer tasks) is
synchronized.

.. _`libSCHC`: https://github.com/imec-idlab/libschc
.. _`pydantic`: https://pydantic.dev
.. _`scapy`: https://scapy.net/

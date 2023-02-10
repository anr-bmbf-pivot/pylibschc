=======================================
pylibschc: A python wrapper for libSCHC
=======================================

.. image:: https://github.com/anr-bmbf-pivot/pylibschc/actions/workflows/test.yml/badge.svg
   :target: https://github.com/anr-bmbf-pivot/pylibschc/actions/workflows/test.yml

.. image:: https://codecov.io/gh/anr-bmbf-pivot/pylibschc/branch/main/graph/badge.svg?token=KPOQ0ERP9H
   :target: https://codecov.io/gh/anr-bmbf-pivot/pylibschc

.. image:: https://img.shields.io/pypi/status/pylibschc
   :alt: PyPI - Status
   :target: https://pypi.org/project/pylibschc/

.. image:: https://img.shields.io/pypi/pyversions/pylibschc
   :alt: PyPI - Python Version
   :target: https://pypi.org/project/pylibschc/

This provides a pythonic wrapper for `libSCHC`_.

Installation
============

You can use ``pip`` to install the package once from `PyPI`_:

.. code:: bash

   pip install pylibschc

Usage
=====

More documentation can be found `here <https://anr-bmbf-pivot.github.io/pylibschc>`_.

Rules
-----
Rules are managed using a `pydantic`_ model, i.e., they can be loaded from a correctly typed
dictionary (e.g. generated from a JSON or YAML file) using the |pylibschc.rules|_ module:

    >>> import json
    >>> from pylibschc.rules import Config
    >>>
    >>> with open("tests/artifacts/rules_example.json", encoding="utf-8") as f:
    ...    rules = Config(**json.load(f))
    ...    config = rules.deploy()

**Do not forget** to call the |pylibschc.rules.Config.deploy|_ method if you change any rules to
re-deploy the rules with libSCHC.

The header file for the rules, so they can be used with libSCHC on an embedded device, can be
generated using

    >>> with open("rule_config.h", "w", encoding="utf-8") as f:
    ...     written = f.write(rules.to_c_header())

An example for such a dictionary is provided in `rules_example.json`_ as JSON, the documentation of
the concrete `pydantic`_ model you can find its
`API reference <https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/rules.html>`_.

Compression/Decompression
-------------------------

Both compression and decompression can be achieved by using the
|pylibschc.compressor.CompressorDecompressor|_ class. We use `scapy`_ in our example
to construct a valid CoAP over IPv6 packet for compression for which the
|pylibschc.compressor.CompressorDecompressor.output|_ method is
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

For decompression, the |pylibschc.compressor.CompressorDecompressor.input|_ method is called:

    >>> comp_dec.input(bit_array)
    b'`\x00\x00\x00\x00`\x11@ \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x163\xf0\xb2\x00`r\xf2TE#\xb32:\xf3\xa3\xff[{"id":1, "name":"CJ.H.L.(Joe) Lecomte) Heliport","code":"YOY","country":"CA"}]'
    >>> pkt == comp_dec.input(bit_array)
    True

Both |pylibschc.compressor.CompressorDecompressor.input|_ and
|pylibschc.compressor.CompressorDecompressor.output|_ take either |pylibschc.libschc.BitArray|_- or
|bytes|_-typed variables as input.

Fragmentation/Reassembly
------------------------

For fragmentation, call the |pylibschc.fragmenter.Fragmenter.output|_ method of a
|pylibschc.fragmenter.Fragmenter|_ object. To actually send then from the, a send function needs to
be `registered for the device`_ of the fragmenter. For reassembly, call the
|pylibschc.fragmenter.Reassembler.input|_ method of a |pylibschc.fragmenter.Reassembler|_ object.
Acknowledgements can be handled by the |pylibschc.fragmenter.Fragmenter.output|_ method of the
|pylibschc.fragmenter.Fragmenter|_ object. Again, either |pylibschc.fragmenter.Fragmenter.input|_ or
|pylibschc.fragmenter.Reassembler.input|_, and |pylibschc.fragmenter.Fragmenter.output|_ take either
|pylibschc.libschc.BitArray|_- or |bytes|_-typed variables as input.

    >>> import asyncio
    >>> import logging
    >>> import pylibschc.fragmenter
    >>>
    >>> fragmenter_queue = None
    >>> loop = None
    >>> timer_tasks = {}
    >>> reassembly_buffer = None
    >>> # shorten waiting times for this example
    >>> config.devices[0].duty_cycle_ms = 500
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
    ...         mode=pylibschc.fragmenter.FragmentationMode.NO_ACK,
    ...         post_timer_task=post_timer_task,
    ...         end_tx=end_tx,
    ...         remove_timer_entry=remove_timer_entry,
    ...     )
    ...     fragmenter.register_send(config.devices[0], send)
    ...     reassembler = pylibschc.fragmenter.Reassembler(
    ...         device=config.devices[0],
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

While this example uses `asyncio`_ to parallelize timer calls, any method to establish concurrency
can be used (see `test for a threaded fragmenter/reassembler`_ for an example using the
`threading`_ module) as long as the access to libSCHC (including calls to timer tasks) is
synchronized.

License
=======

This code is published under the GNU General Public License Version 3 (GPLv3). Please keep in mind,
that libSCHC is dual licensed for non-open source use. For more, have a look at the
`license information <https://github.com/imec-idlab/libschc/blob/master/README.md#license>`_ over at
libSCHC.

.. _`libSCHC`: https://github.com/imec-idlab/libschc
.. _`PyPI`: https://pypi.org/project/pylibschc
.. _`pydantic`: https://pydantic.dev
.. _`scapy`: https://scapy.net/
.. |pylibschc.rules| replace:: ``pylibschc.rules``
.. _`pylibschc.rules`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/rules.html#pylibschc.rules
.. |pylibschc.rules.Config.deploy| replace:: ``deploy()``
.. _`pylibschc.rules.Config.deploy`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/rules.html#pylibschc.rules.Config.deploy
.. _`rules_example.json`: https://github.com/anr-bmbf-pivot/pylibschc/blob/main/tests/artifacts/rules_example.json
.. |pylibschc.compressor.CompressorDecompressor| replace:: ``pylibschc.compressor.Decompressor``
.. _`pylibschc.compressor.CompressorDecompressor`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/compressor.html#pylibschc.compressor.CompressorDecompressor
.. |pylibschc.compressor.CompressorDecompressor.output| replace:: ``output()``
.. _`pylibschc.compressor.CompressorDecompressor.output`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/compressor.html#pylibschc.compressor.CompressorDecompressor.output
.. |pylibschc.compressor.CompressorDecompressor.input| replace:: ``input()``
.. _`pylibschc.compressor.CompressorDecompressor.input`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/compressor.html#pylibschc.compressor.CompressorDecompressor.input
.. |pylibschc.libschc.BitArray| replace:: ``BitArray``
.. _`pylibschc.libschc.BitArray`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/libschc.html#pylibschc.libschc.BitArray
.. |bytes| replace:: ``bytes``
.. _`bytes`: https://docs.python.org/3/library/stdtypes.html#bytes
.. |pylibschc.fragmenter.Fragmenter| replace:: ``pylibschc.fragmenter.Fragmenter``
.. _`pylibschc.fragmenter.Fragmenter`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Fragmenter
.. |pylibschc.fragmenter.Fragmenter.output| replace:: ``output()``
.. _`pylibschc.fragmenter.Fragmenter.output`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Fragmenter.output
.. _`registered for the device`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Fragmenter.register_send
.. |pylibschc.fragmenter.Fragmenter.input| replace:: ``input()``
.. _`pylibschc.fragmenter.Fragmenter.input`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Fragmenter.input
.. |pylibschc.fragmenter.Reassembler| replace:: ``pylibschc.fragmenter.Reassembler``
.. _`pylibschc.fragmenter.Reassembler`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Reassembler
.. _`pylibschc.fragmenter.Reassembler.output`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Reassembler.output
.. |pylibschc.fragmenter.Reassembler.input| replace:: ``input()``
.. _`pylibschc.fragmenter.Reassembler.input`: https://anr-bmbf-pivot.github.io/pylibschc/pylibschc/fragmenter.html#pylibschc.fragmenter.Reassembler.input
.. _`asyncio`: https://docs.python.org/3/library/asyncio.html
.. _`test for a threaded fragmenter/reassembler`: https://github.com/anr-bmbf-pivot/pylibschc/blob/main/tests/test_fragmenter.py
.. _`threading`: https://docs.python.org/3/library/threading.html

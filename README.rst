=======================================
pylibschc: A python wrapper for libSCHC
=======================================

This provides a pythonic wrapper for `libSCHC`_.

Installation
============

.. code:: bash
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

TBD

.. _`libSCHC`: https://github.com/imec-idlab/libschc
.. _`pydantic`: https://pydantic.dev
.. _`scapy`: https://scapy.net/

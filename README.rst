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
concrete `pydantic`_ model you can find `./pylibschc/rules.py <./pylibschc/rules>`_.

Compression/Decompression
-------------------------

Both compression and decompression can be achieved by using the `CompressorDecompressor` class from
the submodule _`pylibschc.compressor <./pylibschc/compressor.py>`_. We use `scapy`_ in our example
to construct a valid CoAP over IPv6 packet for compression  for which the ``output()`` method is
called:

    >>> from scapy.all import IPv6, UDP, raw
    >>> from scapy.contrib.coap import CoAP
    >>> import pylibschc.compressor
    >>>
    >>> comp_dec = pylibschc.compressor.CompressorDecompressor(
    ...     device=config.devices[0],
    ...     direction=pylibschc.rules.Direction.DOWN
    ... )
    >>> pkt = raw(
    ...     IPv6(hlim=64, src="2001:db8:1::2", dst="2001:db8::1")
    ...     / UDP(
    ...         sport=61618,
    ...         dport=5683,
    ...     )
    ...     / CoAP(
    ...         ver=1,
    ...         code="GET",
    ...         type="NON",
    ...         msg_id=0x23B3,
    ...         token=b"\x32\x3a\xf3\xa3",
    ...         options=[("Uri-Path", b"temp")],
    ...         paymark=b"\xff",
    ...     )
    ...     / (
    ...         b'[{"id":1, "name":"CJ.H.L.(Joe) Lecomte) Heliport","gps":"CYOY","code":"YOY",'
    ...         b'"country":"CA"}]'
    ...     )
    ... )
    >>> res, bit_array = comp_dec.output(pkt)
    >>> res
    <CompressionResult.COMPRESSED: 1>
    >>> bit_array.buffer
    b'\x01@\tm\xec\x89\xa5\x90\x88\xe8\xc4\xb0\x80\x89\xb9\x85\xb5\x94\x88\xe8\x89\r(\xb9 \xb90\xb8\xa1)\xbd\x94\xa4\x811\x95\x8d\xbd\xb5\xd1\x94\xa4\x81!\x95\xb1\xa5\xc1\xbd\xc9\xd0\x88\xb0\x89\x9d\xc1\xcc\x88\xe8\x89\re=d\x88\xb0\x89\x8d\xbd\x91\x94\x88\xe8\x89e=d\x88\xb0\x89\x8d\xbd\xd5\xb9\xd1\xc9\xe4\x88\xe8\x89\r\x04\x89\xf5t'

For decompression, the `input()` method is called:

    >>> comp_dec.input(bit_array)
    b'`\x00\x00\x00\x00k\x11@ \x01\r\xb8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xf0\xb2\x163\x00kz\xc9T\x01m\xec\x89\xa5\x90\x88\xb4temp\xe8\xc4\xb0\x80\x89\xb9\x85\xb5\x94\x88\xe8\x89\r(\xb9 \xb90\xb8\xa1)\xbd\x94\xa4\x811\x95\x8d\xbd\xb5\xd1\x94\xa4\x81!\x95\xb1\xa5\xc1\xbd\xc9\xd0\x88\xb0\x89\x9d\xc1\xcc\x88\xe8\x89\re=d\x88\xb0\x89\x8d\xbd\x91\x94\x88\xe8\x89e=d\x88\xb0\x89\x8d\xbd\xd5\xb9\xd1\xc9\xe4\x88\xe8\x89\r\x04\x89\xf5t'

Both ``input()`` and ``output()`` take either ``BitArray``- or ``bytes``-typed variables as input.

Fragmentation/Reassembly
------------------------

TBD

.. _`libSCHC`: https://github.com/imec-idlab/libschc
.. _`pydantic`: https://pydantic.dev
.. _`scapy`: https://scapy.net/

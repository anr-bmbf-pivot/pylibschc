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


.. _`libSCHC`: https://github.com/imec-idlab/libschc
.. _`pydantic`: https://pydantic.dev

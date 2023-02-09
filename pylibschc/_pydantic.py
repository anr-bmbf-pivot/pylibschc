# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

# pylint: disable=missing-module-docstring

import enum

import pydantic.json

__author__ = "Martine S. Lenders"
__copyright__ = "Copyright 2023 Freie Universität Berlin"
__license__ = "GPLv3"
__email__ = "m.lenders@fu-berlin.de"


class EnumByName(enum.Enum):
    """A custom Enum type for pydantic to validate by case-insensitive name.

    Source: https://github.com/pydantic/pydantic/discussions/2980
    """

    # The reason for this class is there is a disconnect between how
    # SQLAlchemy stores Enum references (by name, not value; which is
    # also how we want our REST API to exchange enum references, by
    # name) and Pydantic which validates Enums by value.  We create a
    # Pydantic custom type which will validate an Enum reference by
    # name.

    # Ugliness: we need to monkeypatch pydantic's jsonification of Enums
    # pylint: disable=no-member
    pydantic.json.ENCODERS_BY_TYPE[enum.Enum] = lambda e: e.name

    @classmethod
    def __get_validators__(cls):
        # yield our validator
        yield cls._validate

    @classmethod
    def __modify_schema__(cls, schema):
        """Override pydantic using Enum.name for schema enum values"""
        schema["enum"] = list(cls.__members__.keys())

    @classmethod
    def _validate(cls, value):
        """Validate enum reference, `value`.

        We check:
          1. If it is in uppercase a member of this Enum
          2. If we can find it by name.
        """
        # is the value an enum member?
        if isinstance(value, enum.Enum) and value in cls:
            return value

        # not a member...look up by name
        try:
            return cls[value.upper()]
        except KeyError as exc:
            name = cls.__name__
            expected = list(cls.__members__.keys())
            raise ValueError(
                f"{value} not found for enum {name}. Expected one of: {expected}"
            ) from exc

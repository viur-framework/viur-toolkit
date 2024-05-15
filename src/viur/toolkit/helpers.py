import functools
import operator

import typing as t

__all__ = [
    "vars_full",
    "freeze_dict",
]


def vars_full(
    obj: t.Any,
    *,
    include_properties: bool = True,
) -> dict[str, t.Any]:
    """
    A better version of the builtin `vars()`.

    This method is designed for debugging.
    It returns the members of an instance, regardless of whether it uses
    `__dict__` or `__slots__`.
    It also adds the values of properties.
    """
    res = {}
    if hasattr(obj, "__slots__"):
        for slot in obj.__slots__:
            res[slot] = getattr(obj, slot)
    elif hasattr(obj, "__dict__"):
        res |= vars(obj)
    if not include_properties:
        return res
    for attr, value in vars(type(obj)).items():
        if isinstance(value, (property, functools.cached_property)):
            res[attr] = getattr(obj, attr)
    return res


def freeze_dict(value: dict[str, t.Any]) -> list:
    """Sort a dict recursively by keys and return as list"""
    return sorted(
        [
            (pair[0], freeze_dict(pair[1])) if isinstance(pair[1], dict) else pair
            for pair in value.items()
        ],
        key=operator.itemgetter(0),
    )

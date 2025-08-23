import functools
import operator
import typing as t

from viur.core.skeleton import SkeletonInstance

__all__ = [
    "NOT_SET",
    "vars_full",
    "freeze_dict",
    "resolve_nested_path",
]


class NotSet:
    def __repr__(self) -> str:
        return "<NOT_SET>"

    def __bool__(self) -> bool:
        return False


NOT_SET: t.Final[NotSet] = NotSet()


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
            res[slot] = getattr(obj, slot, NOT_SET)
    elif hasattr(obj, "__dict__"):
        res |= vars(obj)
    if not include_properties:
        return res
    for attr, value in vars(type(obj)).items():
        if isinstance(value, (property, functools.cached_property)):
            res[attr] = getattr(obj, attr, NOT_SET)
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


def resolve_nested_path(
    value: t.Mapping[str, t.Any] | t.Sequence[t.Any] | SkeletonInstance,
    path: t.Sequence[str] | str,
    fail: bool = False,
    default: t.Any = None,
) -> t.Any:
    """
    Resolve a value from a deeply nested structure (dicts, lists, tuples, or SkeletonInstance)
    using a dot-separated path or a list of keys/indices.

    Supports:
    - **Dotted path strings** (e.g., ``"user.address.street"``)
    - **Index-based access** for lists/tuples (e.g., ``"items.0"``)
    - **Wildcard operator ``*``** for iterating over all elements in a list, tuple, or dict values
      (e.g., ``"users.*.name"`` will return a list of all ``name`` values in ``users``)

    :param value: The initial object (dict, list, tuple, or SkeletonInstance) to resolve the path from.
    :param path: Either a dot-separated string (``"a.b.c"``) or a sequence of keys (``["a", "b", "c"]``).
    :param fail: If ``True``, raises an exception on failure with detailed context.
        If ``False``, returns ``default`` when the path cannot be resolved.
    :param default: Value to return if the path cannot be resolved and ``fail`` is ``False`` (soft-fail).
    :return: The resolved value or ``default`` if the path does not exist and ``fail`` is ``False``.

    :raises KeyError: If a dictionary key is missing and ``fail=True``.
    :raises IndexError: If a list index is out of range and ``fail=True``.
    :raises TypeError: If the path cannot be applied to the current value type and ``fail=True``.

    **Wildcard Behavior:**
        If the path contains ``*``, the function will:
        - For lists or tuples: iterate over all items.
        - For dicts: iterate over all values.
        It then continues resolving the remaining path for each element and returns a list.

    **Examples:**

    .. code-block:: python

        >>> data = {
        >>>     "users": [
        >>>         {"name": "Alice", "address": {"city": "Berlin"}},
        >>>         {"name": "Bob", "address": {"city": "Paris"}},
        >>>     ]
        >>> }

        >>> resolve_nested_path(data, "users.0.name")
        # Output: "Alice"

        >>> resolve_nested_path(data, "users.*.name")
        # Output: ["Alice", "Bob"]

        >>> resolve_nested_path(data, "users.*.address.city")
        # Output: ["Berlin", "Paris"]

        # With fail=False (default)
        >>> resolve_nested_path(data, "users.10.name", default="N/A")
        # Output: "N/A"

        # With fail=True (raises IndexError with detailed notes)
        >>> resolve_nested_path(data, "users.10.name", fail=True)
    """
    if isinstance(path, str):
        path = path.split(".")

    for idx, part in enumerate(path):
        if part == "*":
            # iterate over iterable
            value = value.values() if isinstance(value, dict) else value
            remaining_path = path[idx + 1:]
            return [
                resolve_nested_path(val, remaining_path, fail, default) if remaining_path else val
                for val in value
            ]

        elif isinstance(value, list | tuple) and part.lstrip("-").isdigit():
            # access exactly the n-th item of an iterable (supports negative indices)
            part = int(part)  # type: ignore[assignment]

        # access a dict-value by key or iterable by index
        try:
            value = value[part]  # type: ignore[call-overload]
        except (KeyError, AttributeError, TypeError, IndexError) as exc:
            if fail:
                remaining_path_path = ".".join(path[idx:])
                new_exc = exc.__class__(f"{exc.args[0]} (cannot resolve {remaining_path_path!r})")
                new_exc.add_note(f"{value=}")
                new_exc.add_note(f"{path=}")
                raise new_exc from None
            else:
                return default  # soft-fail

    return value

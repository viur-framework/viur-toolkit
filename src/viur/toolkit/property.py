import typing as t  # noqa
from datetime import datetime as dt, timedelta as td, timezone as tz  # noqa

from viur.core import utils

__all__ = ["CachedProperty"]

Seconds: t.TypeAlias = int | float
Args = t.ParamSpec("Args")
Value = t.TypeVar("Value")


class CachedProperty(t.Generic[Value, Args]):
    """Wrapper to Cache the result of a function-call"""

    __slots__ = ("lifetime", "func", "args", "_value", "_lifetime_ends")

    def __init__(
        self,
        lifetime: td | Seconds,
        func: t.Callable[Args, Value],
        args: Args | None = None,
    ):
        """Initiate a new CachedProperty

        :param lifetime: Specifies in seconds how long the cache value should be valid
        :param func: The function that calculates the value
        :param args: Optional Arguments for the function
        """
        if not callable(func):
            raise TypeError("Argument *func* must be a callable function!")
        if args is not None and not isinstance(args, (tuple, list)):
            raise TypeError("Argument *args* must be a tuple, list or None!")
        super(CachedProperty, self).__init__()
        self.lifetime: td = utils.parse.timedelta(lifetime)
        self.func = func
        self.args = tuple() if args is None else args
        self._value = None
        self._lifetime_ends = None

    def get(self) -> Value:
        """Return the value of Property.
        Might be cached or freshly re-calculated."""
        if self._value is not None and utils.utcNow() < self._lifetime_ends:
            return self._value
        self._value = self.func(*self.args)
        self._lifetime_ends = utils.utcNow() + self.lifetime
        return self._value

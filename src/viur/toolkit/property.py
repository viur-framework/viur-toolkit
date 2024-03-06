import datetime

__all__ = ["CachedProperty"]


class CachedProperty(object):
    """Wrapper to Cache the result of a function-call"""

    __slots__ = ("lifetime", "func", "args", "_value", "_lifetimeEnds")

    def __init__(self, lifetime, func, args=None):
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
        self.lifetime = lifetime
        self.func = func
        self.args = tuple() if args is None else args
        self._value = None
        self._lifetimeEnds = None

    def get(self):
        """Return the value of Property.
        Might be cached or freshly re-calculated."""
        if self._value is not None and datetime.datetime.now() < self._lifetimeEnds:
            return self._value
        self._value = self.func(*self.args)
        self._lifetimeEnds = datetime.datetime.now() + datetime.timedelta(seconds=self.lifetime)
        return self._value

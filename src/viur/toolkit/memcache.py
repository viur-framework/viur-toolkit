import logging
import pickle
import typing as t  # noqa
from collections import namedtuple
from datetime import datetime as dt, timedelta as td, timezone as tz  # noqa

from google.appengine.api.memcache import Client
from google.appengine.ext.testbed import Testbed
from viur.core import conf, utils


__all__ = [
    "MemcacheWrapper",
]

logger = logging.getLogger(__name__)

Seconds: t.TypeAlias = int | float
Args = t.ParamSpec("Args")
Value = t.TypeVar("Value")

# FIXME: re-implement

if conf.instance.is_dev_server:
    # On the local dev_appserver, we use Google's memcache stub,
    # originally designed for test cases, as a local emulator.
    logger.debug("Using memcache stub")
    testbed = Testbed()
    testbed.activate()
    testbed.init_memcache_stub()

memcache = Client()

MemcacheElement = namedtuple("MemcacheElement", ("data", "expires"))


class MemcacheDummy:
    def __init__(self):
        super().__init__()
        self.data = {}

    def get(self, name, namespace="default", *args, **kwargs):
        # logger.debug(f"memcache: {self.data = }")
        if (res := self.data.setdefault(namespace, {}).get(name)) and utils.utcNow() <= res.expires:
            return pickle.loads(res.data)
        return None

    def set(self, name, value, cachetime, namespace="default", *args, **kwargs):
        cachetime = utils.parse.timedelta(cachetime)
        expires = utils.utcNow() + cachetime
        value = pickle.dumps(value)
        self.data.setdefault(namespace, {})[name] = MemcacheElement(value, expires)
        # logger.debug(f"memcache: {self.data = }")

    def delete(self, name, namespace="default", *args, **kwargs):
        return self.data.setdefault(namespace, {}).pop(name, None)


# memcache = MemcacheDummy()


class MemcacheWrapper(t.Generic[Value, Args]):
    """Wrapper to store computed values in memcache.

    A value will be recalculated after the cachetime has expired
    or the memcached was flushed.
    """

    __slots__ = ("name", "func", "args", "cachetime", "namespace")

    def __init__(
        self,
        func: t.Callable[Args, Value],
        *,
        name: str = None,
        args: Args.args = tuple(),
        cachetime: td | Seconds = td(hours=1),
        namespace: str=None,
    ):
        """Initialize a new MemcacheWrapper instance.

        :param func: The function to calculate the value.
        :param name: The name under which the value is to be stored in the memcache.
        :param args: Arguments for the function, must be static
        :param cachetime: Optional expiration time in seconds.
        :param namespace: The namespace in the memcache.
        """
        if name is None:
            name = func.__qualname__
        self.name: str = "/".join([name] + list(map(repr, args)))
        self.func: t.Callable[Args, Value] = func
        self.args: Args.args = args
        self.cachetime: td = utils.parse.timedelta(cachetime)
        if namespace is None:
            namespace = f"cache_{conf.instance.app_version}"
        self.namespace: str = namespace

    def get(self) -> Value:
        """Get the value from memcache

        Trigger the recalculation if necessary.
        """
        res = memcache.get(self.name, namespace=self.namespace)
        # logger.debug("res for %r: %r", self, res)
        if res is None:
            res = self.set()
        return res

    def set(self) -> Value:
        """Set the value (force a recalculation) in the memcache"""
        res = self.func(*self.args)
        memcache.set(self.name, res, self.cachetime.total_seconds(), namespace=self.namespace)
        return res

    def clear(self) -> t.Any:
        """Drop the stored value in memcache"""
        return memcache.delete(self.name, namespace=self.namespace)

    def __repr__(self) -> str:
        return "<%s.%s object, name=%r, namespace=%r, func=%r, args=%r, cachetime=%r>" % (
            self.__class__.__module__, self.__class__.__name__,
            self.name, self.namespace, self.func, self.args, self.cachetime,
        )

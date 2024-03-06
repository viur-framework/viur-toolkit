import logging

from viur.core import conf

__all__ = [
    "MemcacheWrapper",
]

logger = logging.getLogger(__name__)


# FIXME: re-implement

class MemcacheDummy:

    def __init__(self):
        super().__init__()
        self.data = {}

    def get(self, name, namespace="default", *args, **kwargs):
        # logger.debug(f"memcache: {self.data = }")
        return self.data.setdefault(namespace, {}).get(name)

    def set(self, name, value, cachetime, namespace="default", *args, **kwargs):
        # TODO: consider cachetime
        self.data.setdefault(namespace, {})[name] = value
        # logger.debug(f"memcache: {self.data = }")

    def delete(self, name, namespace="default", *args, **kwargs):
        return self.data.setdefault(namespace, {}).pop(name, None)


memcache = MemcacheDummy()


class MemcacheWrapper(object):
    """Wrapper to store computed values in memcache.

    A value will be recalculated after the cachetime has expired
    or the memcached was flushed.
    """

    __slots__ = ("name", "func", "args", "cachetime", "namespace")

    def __init__(self, name, func, args=tuple(), cachetime=3600, namespace=None):
        """Initialize a new MemcacheWrapper instance.

        :param name: The name under which the value is to be stored in the memcache.
        :param func: The function to calculate the value.
        :param args: Arguments for the function, must be static
        :param cachetime: Optional expiration time in seconds.
        :param namespace: The namespace in the memcache.
        """
        self.name = "/".join([name] + list(map(repr, args)))
        self.func = func
        self.args = args
        self.cachetime = cachetime
        if namespace is None:
            namespace = "sh_cache_%s" % conf.instance.app_version.split(".")[0]
        self.namespace = namespace

    def get(self):
        """Get the value from memcache

        Trigger the recalculation if necessary.
        """
        res = memcache.get(self.name, namespace=self.namespace)
        # logger.debug("res for %r: %r", self, res)
        if res is None:
            res = self.set()
        return res

    def set(self):
        """Set the value (force a recalculation) in the memcache"""
        res = self.func(*self.args)
        memcache.set(self.name, res, self.cachetime, namespace=self.namespace)
        return res

    def clear(self):
        """Drop the stored value in memcache"""
        return memcache.delete(self.name, namespace=self.namespace)

    def __repr__(self):
        return "<%s.%s object, name=%r, namespace=%r, func=%r, args=%r, cachetime=%r>" % (
            self.__class__.__module__, self.__class__.__name__,
            self.name, self.namespace, self.func, self.args, self.cachetime,
        )

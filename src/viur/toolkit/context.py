import logging
import time
import typing as t
from types import TracebackType

from viur.core import current

__all__ = ["LanguageContext", "TimeMe"]


class LanguageContext:
    """
    Switch the language of the request just for a specific scope.
    """

    def __init__(self, lang: str):
        self.lang = lang
        self.orig_lang = None

    def __enter__(self) -> t.Self:
        self.orig_lang = current.language.get()
        # TODO: Session?
        current.language.set(self.lang)
        return self

    def __exit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]],
        exc_val: t.Optional[BaseException],
        exc_tb: t.Optional[TracebackType],
    ) -> t.Literal[False]:
        current.language.set(self.orig_lang)
        return False


class TimeMe:
    """
    Measures the execution time of the scope.
    """

    def __init__(self, name: str):
        self.name = name

    def __enter__(self) -> t.Self:
        self.start = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]],
        exc_val: t.Optional[BaseException],
        exc_tb: t.Optional[TracebackType],
    ) -> t.Literal[False]:
        self.end = time.perf_counter()
        logging.debug("%s took %.4fs", self.name, self.end - self.start)
        return False

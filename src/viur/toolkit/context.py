import logging
import time
import typing as t

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

    def __exit__(self, exception, value, tb):
        current.language.set(self.orig_lang)


class TimeMe:
    """
    Measures the execution time of the scope.
    """

    def __init__(self, name: str):
        self.name = name

    def __enter__(self) -> t.Self:
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.perf_counter()
        logging.debug("%s took %.4fs", self.name, self.end - self.start)

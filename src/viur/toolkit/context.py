import logging
import typing as t
from time import time

from viur.core import current

__all__ = ["LanguageContext", "TimeMe"]


class LanguageContext:
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

    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self.start = time()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time()
        logging.debug("%s took %.4fs", self.name, self.end - self.start)

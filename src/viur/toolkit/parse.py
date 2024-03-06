import datetime

import viur.core.utils
from deprecated.classic import deprecated


@deprecated("Please use viur-core's parse_bool")
def parseBool(value):
    return viur.core.utils.parse_bool(value)


def datetimeFromIsoFormat(value):
    return datetime.datetime.strptime(value.split(".", 1)[0], "%Y-%m-%dT%H:%M:%S")


__all__ = ["parseBool", "datetimeFromIsoFormat"]

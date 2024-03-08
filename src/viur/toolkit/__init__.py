import logging
import logging as _logging

from .checks import *
from .context import *
from .db import *
from .decorators import *
from .memcache import *
# TODO: needs reimplementation from .property import *
from .report import *
from .viur import *

# By default, the toolkit log level is INFO
if not _logging.getLogger(__name__).level:
    _logging.getLogger(__name__).setLevel(_logging.INFO)
del _logging

import functools
import json
import logging
import types

from viur.core import current, errors, securitykey

__all__ = [
    "asJsonResponse",
    "cache_call_for_request",
    "parseRequestPayload",
    "skeyRequired",
]

logger = logging.getLogger(__name__)


def skeyRequired(func=None, **decoratorKwArgs):
    """Decorator that checks the skey before the method is called.

    Optional callable to pass keyword-arguments for the securitykey.validate-call.

    Example:
        >>> from viur.core import exposed
        >>> @exposed
        >>> @skeyRequired
        >>> def yourMethod(self):
        >>>     return {"foo": "bar"}
    """

    def outerWrapper(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if not securitykey.validate(kwargs.pop("skey", ""), **decoratorKwArgs):
                raise errors.PreconditionFailed("Missing or invalid skey")
            return f(*args, **kwargs)

        return wrapper

    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outerWrapper(func)  # @skeyRequired
    else:
        return outerWrapper  # @skeyRequired() or @skeyRequired(**anyKwargs)


def asJsonResponse(func=None, **decoratorKwArgs):
    """Decorator that returns the method/function response json serialized.

    Optional callable to pass keyword-arguments for the json.dumps-call.

    Example:
        >>> from viur.core import exposed
        >>> @exposed
        >>> @asJsonResponse(default=str)
        >>> def yourMethod(self):
        >>>     return {"foo": "bar"}
    """

    # ATTENTION: name-changes MUST also be made in BetterCache!

    def outerWrapper(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            current.request.get().response.headers["Content-Type"] = "application/json"
            return json.dumps(f(*args, **kwargs), **decoratorKwArgs)

        return wrapper

    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outerWrapper(func)  # @asJsonResponse
    else:
        return outerWrapper  # @asJsonResponse() or @asJsonResponse(**anyKwargs)


def parseRequestPayload(func=None, acceptOnly=None, parseFunc=None):
    """Decorator that parses the payload of the request.

    The payload will be parsed based on the provided content-type header
    by the set parseFunc.
    The wrapped function MUST have the argument *payload* where the
    parsed payload/payload will be passed through.

    Example:
        >>> from viur.core import exposed
        >>> @exposed
        >>> @parseRequestPayload(acceptOnly="application/json")
        >>> def yourMethod(self, payload):
        >>>     # do something with the payload - it's a python object

    :param func: The wrapped function/method when not called
    :type func: None | types.MethodType | types.FunctionType
    :param acceptOnly: The accepted content-types for this ressource.
        As specified in https://tools.ietf.org/html/rfc2045#section-5
        Set to None to accept all (*/*).
    :type acceptOnly: None | str | list[str] | set[str] | tuple[str]
    :param parseFunc: a custom function that parse the payload
    :type parseFunc: types.FunctionType | Callable

    :return: The result of the wrapped function
    :rtype: Any
    """

    def defaultParseFunc(contentType, payload):
        if contentType == "application/json":
            return json.loads(payload)
        raise NotImplementedError("No parser for type '%s' implemented" % contentType)

    def outerWrapper(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            curReq = current.request.get()
            # Set the Accept-header
            if acceptOnly is None:
                curReq.response.headers["Accept"] = "*/*"
            else:
                curReq.response.headers["Accept"] = ";".join(acceptOnly)
            # Check the given content-type
            contentType = curReq.request.headers["Content-Type"].split(";", 1)[0].lower()
            if acceptOnly is not None and contentType not in acceptOnly:
                logger.error("Unsupported format '%s' for payload", contentType)
                raise errors.HTTPException(
                    415, "Unsupported Media Type",
                    "Unsupported format '%s' for payload" % contentType
                )
            # Parse the payload
            try:
                payload = parseFunc(contentType, curReq.request.body)
            except ValueError:  # Thrown by the parser to indicate that the payload is unparsable
                logger.exception("Failed to parse payload of type '%s'", contentType)
                raise errors.HTTPException(
                    400, "Bad Request",
                    "Failed to parse the payload"
                )
            except NotImplementedError:
                logger.exception("Parser does not support the given type '%s'", contentType)
                raise errors.NotImplemented(
                    "Parser does not support the given type '%s'" % contentType
                )
            # Call the wrapped func with the additionally payload-argument
            return f(*args, payload=payload, **kwargs)

        return wrapper

    # Check arguments first
    if isinstance(acceptOnly, str):
        acceptOnly = [acceptOnly]
    elif not (acceptOnly is None or isinstance(acceptOnly, (list, tuple, set))):
        raise TypeError("Argument acceptOnly must be a str or iterable of str.")
    if parseFunc is None:
        parseFunc = defaultParseFunc
    elif not isinstance(parseFunc, (types.MethodType, types.FunctionType)):
        raise TypeError("Invalid parseFunc given")

    # Check whether the decorator was called or not
    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outerWrapper(func)  # @parseRequestPayload
    else:
        return outerWrapper  # @parseRequestPayload() or @parseRequestPayload(**anyKwargs)


def cache_call_for_request(func=None):
    """Cache method calls for the current request

    args, kwargs must be hashhable.
    """

    # TODO: documentation, merge default kwargs into args
    def outerWrapper(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            cache_key = tuple([func.__name__] + list(args) + list(sorted(kwargs.items())))
            cache = current.request_data.get().setdefault("_call_cache", {})

            try:
                res = cache[cache_key]
                logger.debug("Loaded %r from cache (req cache hit)", cache_key)
                return res
            except KeyError:
                res = cache[cache_key] = f(*args, **kwargs)
                logger.debug("Stored %r in cache (req cache miss)", cache_key)
                return res

        return wrapper

    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outerWrapper(func)  # @cache_call_for_request
    else:
        return outerWrapper  # @cache_call_for_request() or @cache_call_for_request(**anyKwargs)

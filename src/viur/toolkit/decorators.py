import functools
import json
import logging
import types
import typing as t

import deprecated

from viur.core import current, errors

__all__ = [
    "as_json_response",
    "cache_call_for_request",
    "debug",
    "parse_request_payload",
]

logger = logging.getLogger(__name__)

P = t.ParamSpec("P")
T = t.TypeVar("T")


def debug(func: t.Callable[P, T]) -> t.Callable[P, T]:
    """Decorator to print the function signature and return value"""

    @functools.wraps(func)
    def wrapper_debug(*args: P.args, **kwargs: P.kwargs) -> T:
        args_repr = list(map(repr, args))
        kwargs_repr = [f"{k!s}={v!r}" for k, v in kwargs.items()]
        signature = ", ".join(args_repr + kwargs_repr)
        logging.info(f"CALLING {func.__name__}({signature})")
        value = func(*args, **kwargs)
        logging.info(f"{func.__name__} RETURNED {value}")
        return value

    return wrapper_debug


def as_json_response(
    func: t.Optional[t.Callable[P, T]] = None,
    **decorator_kw_args: t.Any,
) -> t.Callable[P, str] | t.Callable[[t.Callable[P, T]], t.Callable[P, str]]:
    """Decorator that returns the method/function response json serialized.

    Optional callable to pass keyword-arguments for the json.dumps-call.

    Example:
        >>> from viur.core import exposed
        >>> @exposed
        >>> @as_json_response(default=str)
        >>> def your_method(self):
        >>>     return {"foo": "bar"}
    """

    def outer_wrapper(f: t.Callable[P, T]) -> t.Callable[P, str]:
        @functools.wraps(f)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> str:
            current.request.get().response.headers["Content-Type"] = "application/json"
            return json.dumps(f(*args, **kwargs), **decorator_kw_args)

        return wrapper

    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outer_wrapper(func)  # @as_json_response
    else:
        return outer_wrapper  # @as_json_response() or @as_json_response(**any_kwargs)


asJsonResponse = deprecated.deprecated(as_json_response)


class ParseFunc(t.Protocol):
    def __call__(self, content_type: str, payload: str) -> t.Any:
        ...


def parse_request_payload(
    func: t.Optional[t.Callable[P, T]] = None,
    accept_only: None | str | list[str] | set[str] | tuple[str] = None,
    parse_func: None | ParseFunc = None,
) -> t.Callable[P, T] | t.Callable[[t.Callable[P, T]], t.Callable[P, T]]:
    """Decorator that parses the payload of the request.

    The payload will be parsed based on the provided content-type header
    by the set parseFunc.
    The wrapped function MUST have the argument *payload* where the
    parsed payload/payload will be passed through.

    Example:
        >>> from viur.core import exposed
        >>> @exposed
        >>> @parse_request_payload(accept_only="application/json")
        >>> def your_method(self, payload):
        >>>     # do something with the payload - it's a python object

    :param func: The wrapped function/method when not called
    :param accept_only: The accepted content-types for this ressource.
        As specified in https://tools.ietf.org/html/rfc2045#section-5
        Set to None to accept all (*/*).
    :param parse_func: a custom function that parse the payload

    :return: The result of the wrapped function
    """

    def default_parse_func(content_type: str, payload: str) -> t.Any:
        if content_type == "application/json":
            return json.loads(payload)
        raise NotImplementedError(f"No parser for type '{content_type}' implemented")

    def outer_wrapper(f: t.Callable[P, T]) -> t.Callable[P, T]:
        @functools.wraps(f)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            cur_req = current.request.get()
            # Set the Accept-header
            if accept_only is None:
                cur_req.response.headers["Accept"] = "*/*"
            else:
                cur_req.response.headers["Accept"] = ";".join(accept_only)
            # Check the given content-type
            content_type = cur_req.request.headers["Content-Type"].split(";", 1)[0].lower()
            if accept_only is not None and content_type not in accept_only:
                logger.error("Unsupported format '%s' for payload", content_type)
                raise errors.HTTPException(
                    415, "Unsupported Media Type",
                    "Unsupported format '%s' for payload" % content_type
                )
            # Parse the payload
            try:
                payload = parse_func(content_type, cur_req.request.body)  # type: ignore
            except ValueError:  # Thrown by the parser to indicate that the payload is unparsable
                logger.exception("Failed to parse payload of type '%s'", content_type)
                raise errors.HTTPException(
                    400, "Bad Request",
                    "Failed to parse the payload"
                )
            except NotImplementedError:
                logger.exception("Parser does not support the given type '%s'", content_type)
                raise errors.NotImplemented(
                    "Parser does not support the given type '%s'" % content_type
                )
            # Call the wrapped func with the additionally payload-argument
            return f(*args, payload=payload, **kwargs)

        return wrapper

    # Check arguments first
    if isinstance(accept_only, str):
        accept_only = [accept_only]
    elif not (accept_only is None or isinstance(accept_only, (list, tuple, set))):
        raise TypeError("Argument accept_only must be a str or iterable of str.")
    if parse_func is None:
        parse_func = default_parse_func
    elif not isinstance(parse_func, (types.MethodType, types.FunctionType)):
        raise TypeError("Invalid parse_func given")

    # Check whether the decorator was called or not
    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outer_wrapper(func)  # @parse_request_payload
    else:
        return outer_wrapper  # @parse_request_payload() or @parse_request_payload(**anyKwargs)


parseRequestPayload = deprecated.deprecated(parse_request_payload)


def cache_call_for_request(
    func: t.Optional[t.Callable[P, T]] = None,
) -> t.Callable[P, T] | t.Callable[[t.Callable[P, T]], t.Callable[P, T]]:
    """Cache method calls for the current request

    args, kwargs must be hashhable.
    """

    # TODO: documentation, merge default kwargs into args
    def outer_wrapper(f: t.Callable[P, T]) -> t.Callable[P, T]:
        @functools.wraps(f)
        def inner_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            assert func is not None
            cache_key = tuple([func.__name__] + list(args) + list(sorted(kwargs.items())))
            cache = current.request_data.get().setdefault("_call_cache", {})

            try:
                res = cache[cache_key]
                logger.debug(f"Loaded {cache_key} from cache (req cache hit)")
                return res
            except KeyError:
                res = cache[cache_key] = f(*args, **kwargs)
                logger.debug(f"Stored {cache_key} in cache (req cache miss)")
                return res

        return inner_wrapper

    if isinstance(func, (types.MethodType, types.FunctionType)):
        return outer_wrapper(func)  # @cache_call_for_request
    else:
        return outer_wrapper  # @cache_call_for_request() or @cache_call_for_request(**any_kwargs)

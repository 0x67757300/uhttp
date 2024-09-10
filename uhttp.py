"""ASGI micro framework"""

from __future__ import annotations

import json
import re
from ast import Tuple
from asyncio import to_thread
from enum import Enum, StrEnum
from http import HTTPMethod, HTTPStatus
from http.cookies import CookieError, SimpleCookie
from inspect import iscoroutinefunction
from typing import (
    Annotated,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    TypeVar,
    Union,
)
from urllib.parse import parse_qs, unquote

from typing_extensions import Doc

AppType = TypeVar("AppType", bound="uHTTP")  # type: ignore
RouteHandler = Union[Callable[..., None], Callable[..., Awaitable[None]]]
Routes = Dict[str, Dict[HTTPMethod, RouteHandler]]


# Copied from Litestar. https://github.com/litestar-org/litestar/blob/main/litestar/enums.py
class MediaType(StrEnum):
    """An Enum for ``Content-Type`` header values."""

    JSON = "application/json"
    MESSAGEPACK = "application/x-msgpack"
    HTML = "text/html"
    TEXT = "text/plain"
    CSS = "text/css"
    XML = "application/xml"


class RequestEncodingType(StrEnum):
    """An Enum for request ``Content-Type`` header values designating encoding formats."""

    JSON = "application/json"
    MESSAGEPACK = "application/x-msgpack"
    MULTI_PART = "multipart/form-data"
    URL_ENCODED = "application/x-www-form-urlencoded"


class Application:
    """
    ### Application

    An [ASGI](https://asgi.readthedocs.io/en/latest/) application. Called once per request by the server.

    ```python
    Application(*, routes=None, startup=None, shutdown=None, before=None, after=None, max_content=1048576)
    ```
    E.g.:

    ```python
    app = Application(
        startup=[open_db],
        before=[counter, auth],
        routes={
            '/': {
                'GET': lambda request: 'HI!',
                'POST': new
            },
            '/users/': {
                'GET': users,
                'PUT': users
            }
        },
        after=[logger],
        shutdown=[close_db]
    )
    ```
    """

    def __init__(
        self: AppType,
        routes: Annotated[
            Optional[Routes],
            Doc(
                """ 
            A dictionary of path, methods and functions. 
                E.g.
                ```python
                routes={
                    '/': {
                        'GET': lambda request: 'HI!',
                        'POST': new
                        },
                    '/users/': {
                        'GET': users,
                        'PUT': users
                        }
                    }
                ```
            """
            ),
        ] = None,
        startup: Annotated[
            Optional[List[RouteHandler]],
            Doc(
                """List of functions to be called at the beginning of the Lifespan protocol."""
            ),
        ] = None,
        shutdown: Annotated[
            Optional[List[RouteHandler]],
            Doc(
                """List of functions to be called at the ending of the Lifespan protocol."""
            ),
        ] = None,
        before: Annotated[
            Optional[List[RouteHandler]],
            Doc("""List of functions to be called before a response is made."""),
        ] = None,
        after: Annotated[
            Optional[List[RouteHandler]],
            Doc("""List of functions to be called after a response is made."""),
        ] = None,
        max_content: int = 1048576,
    ) -> None:
        self._routes = routes or {}
        self._startup = startup or []
        self._shutdown = shutdown or []
        self._before = before or []
        self._after = after or []
        self._max_content = max_content

    def mount(self, app: Application, prefix: Optional[str] = "") -> None:
        """
        Mounts another application at the specified prefix.

        ```python
        utils = Application()

        @utils.before
        def incoming(request):
            print(f'Incoming from {request.ip}')

        app.mount(utils, prefix="/utils")
        ```
        """
        self._startup += app._startup
        self._shutdown += app._shutdown
        self._before += app._before
        self._after += app._after
        self._routes.update({prefix + k: v for k, v in app._routes.items()})
        self._max_content = max(self._max_content, app._max_content)

    def startup(self, func: Callable) -> Callable:
        """
        Append the decorated function to the list of functions called at the beginning of the [Lifespan](https://asgi.readthedocs.io/en/latest/specs/lifespan.html) protocol.

        ```python
        @app.startup
        [async] def func(state)
        ```

        E.g.:

        ```python
        @app.startup
        async def open_db(state):
            state['db'] = await aiosqlite.connect('db.sqlite')
        ```
        """
        self._startup.append(func)
        return func

    def shutdown(self, func: Callable) -> Callable:
        """Appends the decorated function to the list of functions called at the end of the Lifespan protocol.

        ```python
        @app.shutdown
        [async] def func(state)
        ```

        E.g.:

        ```python
        @app.shutdown
        async def close_db(state):
            await state['db'].close()
        ```
        """
        self._shutdown.append(func)
        return func

    def before(self, func: Callable) -> Callable:
        """
        Appends the decorated function to the list of functions called before a response is made.

        ```python
        @app.before
        [async] def func(request)
        ```

        E.g.:

        ```python
        @app.before
        def restrict(request):
            user = request.state['session'].get('user')
            if user != 'admin':
                raise Response(401)
        ```
        """
        self._before.append(func)
        return func

    def after(self, func: Callable) -> Callable:
        """
        Appends the decorated function to the list of functions called after a response is made.

        ```python
        @app.after
        [async] def func(request, response)
        ```

        E.g.:

        ```python
        @app.after
        def logger(request, response):
            print(request, '-->', response)
        ```
        """
        self._after.append(func)
        return func

    def route(
        self, path: str, methods: Tuple[HTTPMethod] = (HTTPMethod.GET,)
    ) -> Callable:
        """
        Inserts the decorated function to the routing table.

        ```python
        @app.route(path, methods=('GET',))
        [async] def func(request)
        ```

        Paths are compiled at startup as regular expression patterns. Named groups define path parameters.

        If the request path doesn't match any route pattern, a `404 Not Found` response is returned.

        If the request method isn't in the route methods, a `405 Method Not Allowed` response is returned.

        Decorators for the standard methods (get, post, put, delete, etc) are also available.

        E.g.:

        ```python
        @app.route('/', methods=('GET', 'POST'))
        def index(request):
            return f'{request.method}ing from {request.ip}'

        @app.get(r'/user/(?P<id>\\d+)')
        def profile(request):
            user = request.state['db'].get_or_404(request.params['id'])
            return f'{user.name} has {user.friends} friends!'
        ```
        """

        def decorator(func):
            self._routes.setdefault(path, {}).update(
                {method: func for method in methods}
            )
            return func

        return decorator

    def get(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.GET,))

    def head(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.HEAD,))

    def post(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.POST,))

    def put(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.PUT,))

    def delete(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.DELETE,))

    def connect(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.CONNECT,))

    def options(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.OPTIONS,))

    def trace(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.TRACE,))

    def patch(self, path: str) -> Callable:
        return self.route(path, methods=(HTTPMethod.PATCH,))

    async def __call__(self, scope: Dict, receive, send):
        state = scope.get("state", {})

        if scope["type"] == "lifespan":
            while True:
                event = await receive()

                if event["type"] == "lifespan.startup":
                    try:
                        for func in self._startup:
                            await asyncfy(func, state)
                        self._routes = {
                            re.compile(k): v for k, v in self._routes.items()
                        }
                    except Exception as e:
                        await send(
                            {
                                "type": "lifespan.startup.failed",
                                "message": f"{type(e).__name__}: {e}",
                            }
                        )
                        break
                    await send({"type": "lifespan.startup.complete"})

                elif event["type"] == "lifespan.shutdown":
                    try:
                        for func in self._shutdown:
                            await asyncfy(func, state)
                    except Exception as e:
                        await send(
                            {
                                "type": "lifespan.shutdown.failed",
                                "message": f"{type(e).__name__}: {e}",
                            }
                        )
                        break
                    await send({"type": "lifespan.shutdown.complete"})
                    break

        elif scope["type"] == "http":
            request = Request(
                method=scope["method"],
                path=scope["path"],
                ip=scope.get("client", ("", 0))[0],
                args=parse_qs(unquote(scope["query_string"])),
                state=state.copy(),
            )

            try:
                try:
                    request.headers = MultiDict(
                        [[k.decode(), v.decode()] for k, v in scope["headers"]]
                    )
                except UnicodeDecodeError:
                    raise Response(HTTPStatus.BAD_REQUEST)

                try:
                    request.cookies.load(request.headers.get("cookie", ""))
                except CookieError:
                    raise Response(HTTPStatus.BAD_REQUEST)

                while True:
                    event = await receive()
                    request.body += event["body"]
                    if len(request.body) > self._max_content:
                        raise Response(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                    if not event["more_body"]:
                        break

                content_type = request.headers.get("content-type", "")
                if MediaType.JSON in content_type:
                    try:
                        request.json = await to_thread(
                            json.loads, request.body.decode()
                        )
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        raise Response(HTTPStatus.BAD_REQUEST)
                elif RequestEncodingType.URL_ENCODED in content_type:
                    request.form = MultiDict(
                        await to_thread(parse_qs, unquote(request.body))
                    )

                for func in self._before:
                    if ret := await asyncfy(func, request):
                        raise Response.from_any(ret)

                for route, methods in self._routes.items():
                    if matches := route.fullmatch(request.path):
                        request.params = matches.groupdict()
                        if func := methods.get(request.method):
                            ret = await asyncfy(func, request)
                            response = Response.from_any(ret)
                        else:
                            response = Response(HTTPStatus.METHOD_NOT_ALLOWED)
                            response.headers["allow"] = ", ".join(methods)
                        break
                else:
                    response = Response(HTTPStatus.NOT_FOUND)

            except Response as early_response:
                response = early_response

            try:
                for func in self._after:
                    if ret := await asyncfy(func, request, response):
                        raise Response.from_any(ret)
            except Response as early_response:
                response = early_response

            response.headers.setdefault("content-length", len(response.body))
            response.headers._update(
                {
                    "set-cookie": [
                        header.split(": ", maxsplit=1)[1]
                        for header in response.cookies.output().splitlines()
                    ]
                }
            )

            await send(
                {
                    "type": "http.response.start",
                    "status": response.status,
                    "headers": [
                        [str(k).encode(), str(v).encode()]
                        for k, l in response.headers._items()
                        for v in l
                    ],
                }
            )
            await send({"type": "http.response.body", "body": response.body})

        else:
            raise NotImplementedError(scope["type"], "is not supported")


class Request:
    """An HTTP request. Created every time the application is called on the HTTP protocol with a shallow copy of the state."""

    def __init__(
        self,
        method: Annotated[
            HTTPMethod,
            Doc(
                """Standard HTTP method.
                Read more [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)"""
            ),
        ],
        path: Annotated[
            str,
            Doc(
                "URL path. For example: https://www.example.com/products/12345/details"
            ),
        ],
        *,
        ip: Annotated[
            Optional[str],
            Doc(
                "The IP address of the request. Defaults to an empty string if not provided."
            ),
        ] = "",
        params: Annotated[
            Optional[MultiDict],
            Doc(
                "Query parameters passed with the request. Defaults to an empty dictionary if not provided."
            ),
        ] = None,
        args: Annotated[
            Optional[Dict],
            Doc(
                "Arguments passed with the request, typically in the form of key-value pairs. Defaults to an empty MultiDict if not provided."
            ),
        ] = None,
        headers: Annotated[
            Optional[MultiDict],
            Doc(
                "HTTP headers sent with the request. Defaults to an empty MultiDict if not provided."
            ),
        ] = None,
        cookies: Annotated[
            Optional[SimpleCookie],
            Doc(
                "Cookies sent with the request. Defaults to an empty SimpleCookie if not provided."
            ),
        ] = None,
        body: Annotated[
            Optional[bytes],
            Doc(
                "The body of the request, typically for POST or PUT requests. Defaults to an empty byte string."
            ),
        ] = b"",
        json: Annotated[
            Optional[Dict],
            Doc(
                "Parsed JSON data sent with the request. Defaults to None if not provided."
            ),
        ] = None,
        form: Annotated[
            MultiDict,
            Doc(
                "Form data sent with the request. Defaults to an empty MultiDict if not provided."
            ),
        ] = None,
        state: Annotated[
            Optional[Dict],
            Doc(
                "State associated with the request. Defaults to an empty dictionary if not provided."
            ),
        ] = None,
    ) -> None:
        self.method = method
        self.path = path
        self.ip = ip
        self.params = params or {}
        self.args = MultiDict(args)
        self.headers = MultiDict(headers)
        self.cookies = SimpleCookie(cookies)
        self.body = body
        self.json = json
        self.form = MultiDict(form)
        self.state = state or {}

    def __repr__(self):
        return f"{self.method} {self.path}"


class Response(Exception):
    """An HTTP Response. May be raised or returned at any time in middleware or route functions."""

    def __init__(
        self,
        status: Annotated[
            HTTPStatus,
            Doc(
                "The HTTP status code for the response. For example, `HTTPStatus.OK` for a 200 OK response."
            ),
        ],
        *,
        headers: Annotated[
            Optional[MultiDict],
            Doc(
                "HTTP headers to be included in the response. Defaults to None if not provided."
            ),
        ] = None,
        cookies: Annotated[
            Optional[SimpleCookie],
            Doc("Cookies to be set in the response. Defaults to None if not provided."),
        ] = None,
        body: Annotated[
            Optional[bytes],
            Doc("The body of the response. Defaults to an empty byte string."),
        ] = b"",
    ) -> None:
        self.status: HTTPStatus = status
        try:
            self.description = HTTPStatus(status).phrase
        except ValueError:
            self.description = ""
        super().__init__(f"{self.status} {self.description}")
        self.headers = MultiDict(headers)
        self.headers.setdefault("content-type", "text/html; charset=utf-8")
        self.cookies = SimpleCookie(cookies)
        self.body = body

    @classmethod
    def from_any(cls, any):
        if isinstance(any, int):
            return cls(status=any, body=HTTPStatus(any).phrase.encode())
        elif isinstance(any, str):
            return cls(status=200, body=any.encode())
        elif isinstance(any, bytes):
            return cls(status=200, body=any)
        elif isinstance(any, dict):
            return cls(
                status=200,
                headers={"content-type": MediaType.JSON},
                body=json.dumps(any).encode(),
            )
        elif isinstance(any, cls):
            return any
        elif any is None:
            return cls(status=204)
        else:
            raise TypeError


async def asyncfy(func, /, *args, **kwargs):
    if iscoroutinefunction(func):
        return await func(*args, **kwargs)
    else:
        return await to_thread(func, *args, **kwargs)


class MultiDict(dict):
    """
    Support for multipart forms. Depends on [python-multipart](https://pypi.org/project/python-multipart/).

    E.g.

    ```python
    from multipart.multipart import FormParser, parse_options_header
    from multipart.exceptions import FormParserError
    from uhttp import Application, MultiDict, Response

    app = Application()

    def parse_form(request):
        form = MultiDict()

        def on_field(field):
            form[field.field_name.decode()] = field.value.decode()
        def on_file(file):
            if file.field_name:
                form[file.field_name.decode()] = file.file_object
        content_type, options = parse_options_header(
            request.headers.get('content-type', '')
        )
        try:
            parser = FormParser(
                content_type.decode(),
                on_field,
                on_file,
                boundary=options.get(b'boundary'),
                config={'MAX_MEMORY_FILE_SIZE': float('inf')}  # app._max_content
            )
            parser.write(request.body)
            parser.finalize()
        except FormParserError:
            raise Response(400)
        return form

    @app.before
    def handle_multipart(request):
        if 'multipart/form-data' in request.headers.get('content-type'):
            request.form = parse_form(request)
    ```
    """

    def __init__(
        self,
        mapping: Union[
            None, "MultiDict", Dict[str, Any], Iterable[Tuple[str, Any]]
        ] = None,
    ) -> None:
        if mapping is None:
            super().__init__()
        elif isinstance(mapping, MultiDict):
            super().__init__({k.lower(): v[:] for k, v in mapping.items()})
        elif isinstance(mapping, dict):
            super().__init__(
                {
                    k.lower(): [v] if not isinstance(v, list) else v[:]
                    for k, v in mapping.items()
                }
            )
        elif isinstance(mapping, (tuple, list)):
            super().__init__()
            for key, value in mapping:
                self._setdefault(key.lower(), []).append(value)
        else:
            raise TypeError("Invalid mapping type")

    def __getitem__(self, key: str) -> Any:
        return super().__getitem__(key.lower())[-1]

    def __setitem__(self, key: str, value: Any) -> None:
        super().setdefault(key.lower(), []).append(value)

    def _get(self, key: str, default: Tuple[Any, ...] = (None,)) -> List[Any]:
        return super().get(key.lower(), list(default))

    def get(self, key: str, default: Any = None) -> Any:
        return super().get(key.lower(), [default])[-1]

    def _items(self) -> Iterable[Tuple[str, List[Any]]]:
        return super().items()

    def items(self) -> Iterable[Tuple[str, Any]]:
        return ((k.lower(), v[-1]) for k, v in super().items())

    def _pop(self, key: str, default: Tuple[Any, ...] = (None,)) -> Any:
        return super().pop(key.lower(), list(default))

    def pop(self, key: str, default: Any = None) -> Any:
        values: Optional[List] = super().get(key.lower(), [])
        if len(values) > 1:
            return values.pop()
        else:
            return super().pop(key.lower(), default)

    def _setdefault(self, key: str, default: Tuple[Any, ...] = (None,)) -> List[Any]:
        return super().setdefault(key.lower(), list(default))

    def setdefault(self, key: str, default: Any = None) -> Any:
        return super().setdefault(key.lower(), [default])[-1]

    def _values(self) -> Iterable[List[Any]]:
        return super().values()

    def values(self) -> Iterable[Any]:
        return (v[-1] for v in super().values())

    def _update(self, *args: Any, **kwargs: Any) -> None:
        super().update(*args, **kwargs)

    def update(self, *args: Any, **kwargs: Any) -> None:
        new = {}
        new.update(*args, **kwargs)
        super().update(MultiDict(new))

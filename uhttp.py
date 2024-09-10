"""ASGI micro framework"""

from __future__ import annotations

import enum
import json
import re
from ast import Tuple
from asyncio import to_thread
from http import HTTPMethod, HTTPStatus
from http.cookies import CookieError, SimpleCookie
from inspect import iscoroutinefunction
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Union
from urllib.parse import parse_qs, unquote

RouteHandler = Union[Callable[..., None], Callable[..., Awaitable[None]]]
Routes = Dict[str, Dict[HTTPMethod, RouteHandler]]


class Application:
    def __init__(
        self,
        routes: Optional[Routes] = None,
        startup: Optional[List[RouteHandler]] = None,
        shutdown: Optional[List[RouteHandler]] = None,
        before: Optional[List[RouteHandler]] = None,
        after: Optional[List[RouteHandler]] = None,
        max_content: int = 1048576,
    ) -> None:
        self._routes = routes or {}
        self._startup = startup or []
        self._shutdown = shutdown or []
        self._before = before or []
        self._after = after or []
        self._max_content = max_content

    def mount(self, app: Application, prefix: Optional[str] = "") -> None:
        self._startup += app._startup
        self._shutdown += app._shutdown
        self._before += app._before
        self._after += app._after
        self._routes.update({prefix + k: v for k, v in app._routes.items()})
        self._max_content = max(self._max_content, app._max_content)

    def startup(self, func: Callable) -> Callable:
        self._startup.append(func)
        return func

    def shutdown(self, func: Callable) -> Callable:
        self._shutdown.append(func)
        return func

    def before(self, func: Callable) -> Callable:
        self._before.append(func)
        return func

    def after(self, func: Callable) -> Callable:
        self._after.append(func)
        return func

    def route(
        self, path: str, methods: Tuple[HTTPMethod] = (HTTPMethod.GET,)
    ) -> Callable:
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
                if "application/json" in content_type:
                    try:
                        request.json = await to_thread(
                            json.loads, request.body.decode()
                        )
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        raise Response(HTTPStatus.BAD_REQUEST)
                elif "application/x-www-form-urlencoded" in content_type:
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
    def __init__(
        self,
        method: HTTPMethod,
        path: str,
        *,
        ip: Optional[str] = "",
        params: Optional[MultiDict] = None,
        args: Optional[Dict] = None,
        headers: Optional[MultiDict] = None,
        cookies: Optional[SimpleCookie] = None,
        body: Optional[bytes] = b"",
        json: Optional[Dict] = None,
        form: MultiDict = None,
        state: Optional[Dict] = None,
    ):
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
    def __init__(
        self,
        status: HTTPStatus,
        *,
        headers: Optional[MultiDict] = None,
        cookies: Optional[SimpleCookie] = None,
        body: Optional[bytes] = b"",
    ):
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
                headers={"content-type": "application/json"},
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

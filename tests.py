from typing import Any, Dict, List, Tuple

import uhttp


class MockApp(uhttp.Application):
    async def test(
        self,
        method: str,
        path: str,
        query_string: bytes = b"",
        headers: List[Tuple[bytes, bytes]] = None,
        body: bytes = b"",
    ) -> Dict[str, Any]:
        response: uhttp.Response = {}
        state: Dict[str, Any] = {}
        http_scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query_string,
            "headers": headers or [],
            "state": state,
        }

        async def http_receive() -> Dict[str, Any]:
            return {"body": body, "more_body": False}

        async def http_send(event: Dict[str, Any]) -> None:
            if event["type"] == "http.response.start":
                response["status"] = event["status"]
                response["headers"] = uhttp.MultiDict(
                    [[k.decode(), v.decode()] for k, v in event["headers"]]
                )
            elif event["type"] == "http.response.body":
                response["body"] = event["body"]

        lifespan_scope = {"type": "lifespan", "state": state}

        async def lifespan_receive() -> Dict[str, str]:
            if not response:
                return {"type": "lifespan.startup"}
            elif "body" in response:
                return {"type": "lifespan.shutdown"}
            else:
                return {"type": ""}

        async def lifespan_send(event: Dict[str, Any]) -> None:
            if event["type"] == "lifespan.startup.complete":
                await self(http_scope, http_receive, http_send)
            elif "message" in event:
                message = event["message"].encode()
                response["status"] = 500
                response["headers"] = uhttp.MultiDict(
                    {"content-length": str(len(message))}
                )
                response["body"] = message

        await self(lifespan_scope, lifespan_receive, lifespan_send)

        return response


async def test_lifespan_startup_fail() -> None:
    app = MockApp()

    @app.startup
    def fail(state: Dict[str, Any]) -> None:
        1 / 0

    response = await app.test("GET", "/")
    assert response["status"] == 500
    assert response["body"] == b"ZeroDivisionError: division by zero"


async def test_lifespan_shutdown_fail() -> None:
    app = MockApp()

    @app.shutdown
    def fail(state: Dict[str, Any]) -> None:
        1 / 0

    response = await app.test("GET", "/")
    assert response["status"] == 500
    assert response["body"] == b"ZeroDivisionError: division by zero"


async def test_lifespan_startup() -> None:
    app = MockApp()

    @app.startup
    def startup(state: Dict[str, Any]) -> None:
        state["msg"] = "HI!"

    @app.get("/")
    def say_hi(request: uhttp.Request) -> str:
        return request.state.get("msg")

    response = await app.test("GET", "/")
    assert response["body"] == b"HI!"


async def test_lifespan_shutdown() -> None:
    app = MockApp()
    msgs = ["HI!"]

    @app.startup
    def startup(state: Dict[str, Any]) -> None:
        state["msgs"] = msgs

    @app.shutdown
    def shutdown(state: Dict[str, Any]) -> None:
        state["msgs"].append("BYE!")

    await app.test("GET", "/")
    assert msgs[-1] == "BYE!"


async def test_204() -> None:
    app = MockApp()

    @app.get("/")
    def nop(request: uhttp.Request) -> None:
        pass

    response = await app.test("GET", "/")
    assert response["status"] == 204
    assert response["body"] == b""


async def test_404() -> None:
    app = MockApp()
    response = await app.test("GET", "/")
    assert response["status"] == 404


async def test_405() -> None:
    app = MockApp()

    @app.route("/", methods=("GET", "POST"))
    def index(request: uhttp.Request) -> None:
        pass

    response = await app.test("PUT", "/")
    assert response["status"] == 405
    assert response["headers"].get("allow") == "GET, POST"


async def test_413() -> None:
    app = MockApp()
    response = await app.test("POST", "/", body=b" " * (app._max_content + 1))
    assert response["status"] == 413


async def test_methods() -> None:
    app = MockApp()
    methods = ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS")

    @app.route("/", methods=methods)
    def index(request: uhttp.Request) -> str:
        return request.method

    for method in methods:
        response = await app.test(method, "/")
        assert response["body"] == method.encode()


async def test_path_parameters() -> None:
    app = MockApp()

    @app.get(r"/hello/(?P<name>\w+)")
    def hello(request: uhttp.Request) -> str:
        return f'Hello, {request.params.get("name")}!'

    response = await app.test("GET", "/hello/john")
    assert response["status"] == 200
    assert response["body"] == b"Hello, john!"


async def test_query_args() -> None:
    app = MockApp()
    args: Dict[str, List[str]] = {}

    @app.get("/")
    def index(request: uhttp.Request) -> None:
        args.update(request.args)

    await app.test("GET", "/", query_string=b"tag=music&tag=rock&type=book")
    assert args == {"tag": ["music", "rock"], "type": ["book"]}


async def test_headers() -> None:
    app = MockApp()
    headers: Dict[str, List[str]] = {}

    @app.get("/")
    def hello(request: uhttp.Request) -> None:
        headers.update(request.headers)

    await app.test("GET", "/", headers=[[b"from", b"test@example.com"]])
    assert headers == {"from": ["test@example.com"]}


async def test_cookie() -> None:
    app = MockApp()

    @app.get("/")
    def index(request: uhttp.Request) -> str:
        return request.cookies.output(header="Cookie:")

    response = await app.test("GET", "/", headers=[[b"cookie", b"id=1;name=john"]])
    assert response["body"] == b"Cookie: id=1\r\nCookie: name=john"


async def test_set_cookie() -> None:
    app = MockApp()

    @app.get("/")
    def index(request: uhttp.Request) -> uhttp.Response:
        return uhttp.Response(status=204, cookies={"id": 2, "name": "jane"})

    response = await app.test("GET", "/")
    assert response["headers"]._get("set-cookie") == ["id=2", "name=jane"]


async def test_bad_json() -> None:
    app = MockApp()

    response = await app.test(
        "POST",
        "/",
        headers=[[b"content-type", b"application/json"]],
        body=b'{"some": 1',
    )
    assert response["status"] == 400


async def test_good_json() -> None:
    app = MockApp()
    json: Dict[str, Any] = {}

    @app.post("/")
    def index(request: uhttp.Request) -> None:
        json.update(request.json)

    await app.test(
        "POST",
        "/",
        headers=[[b"content-type", b"application/json"]],
        body=b'{"some": 1}',
    )
    assert json == {"some": 1}


async def test_json_response() -> None:
    app = MockApp()

    @app.get("/")
    def json_hello(request: uhttp.Request) -> Dict[str, str]:
        return {"hello": "world"}

    response = await app.test("GET", "/")
    assert response["status"] == 200
    assert response["headers"]["content-type"] == "application/json"
    assert response["body"] == b'{"hello": "world"}'


async def test_form() -> None:
    app = MockApp()
    form: Dict[str, List[str]] = {}

    @app.post("/")
    def submit(request: uhttp.Request) -> None:
        form.update(request.form)

    await app.test(
        "POST",
        "/",
        headers=[[b"content-type", b"application/x-www-form-urlencoded"]],
        body=b"name=john&age=27",
    )

    assert form == {"name": ["john"], "age": ["27"]}


async def test_early_response() -> None:
    app = MockApp()

    @app.before
    def early(request: uhttp.Request) -> str:
        return "Hi! I'm early!"

    @app.route("/")
    def index(request: uhttp.Request) -> str:
        return "Maybe?"

    response = await app.test("GET", "/")
    assert response["status"] == 200
    assert response["body"] == b"Hi! I'm early!"


async def test_late_early_response() -> None:
    app = MockApp()

    @app.after
    def early(request: uhttp.Request, response: uhttp.Response) -> None:
        response.status = 200
        response.body = b"Am I early?"

    response = await app.test("POST", "/")
    assert response["status"] == 200
    assert response["body"] == b"Am I early?"
    assert response["headers"].get("content-length") == "11"


async def test_app_mount() -> None:
    app1 = MockApp()
    app2 = MockApp()

    @app1.route("/")
    def app1_index(request: uhttp.Request) -> None:
        pass

    @app2.route("/")
    def app2_index(request: uhttp.Request) -> None:
        pass

    app2.mount(app1, "/app1")

    assert app2._routes == {"/": {"GET": app2_index}, "/app1/": {"GET": app1_index}}

"""
Rejects request bodies larger than a set size before the app reads them.

FastAPI parses an entire multipart upload (spooling it to disk) before a
route runs, so a size check inside the route alone can't stop a huge
upload from using bandwidth and disk. This middleware stops it at the
door: it checks the Content-Length header, and also counts bytes as they
arrive for uploads that don't send one.
"""
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


BODYLESS_METHODS = {"GET", "HEAD", "OPTIONS"}

TOO_LARGE_MESSAGE = (
    "The upload is too large for PreClear to accept."
)


class RequestBodyTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=413,
            detail=TOO_LARGE_MESSAGE,
        )


class UploadSizeLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        max_body_bytes: int,
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] in BODYLESS_METHODS
        ):
            await self.app(scope, receive, send)
            return

        content_length = None

        for name, value in scope["headers"]:
            if name == b"content-length":
                content_length = value
                break

        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await PlainTextResponse(
                    "Invalid Content-Length header.",
                    status_code=400,
                )(scope, receive, send)
                return

            if declared > self.max_body_bytes:
                await PlainTextResponse(
                    TOO_LARGE_MESSAGE,
                    status_code=413,
                )(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received

            message = await receive()

            if message["type"] == "http.request":
                received += len(message.get("body", b""))

                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge()

            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True

            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)

        except RequestBodyTooLarge:
            if response_started:
                raise

            await PlainTextResponse(
                TOO_LARGE_MESSAGE,
                status_code=413,
            )(scope, receive, send)

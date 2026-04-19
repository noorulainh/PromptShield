from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        settings = get_settings()
        self.window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS
        self.max_requests = settings.RATE_LIMIT_MAX_REQUESTS
        self.buckets: dict[str, deque[float]] = defaultdict(deque)
        self.lock = Lock()

    async def dispatch(self, request: Request, call_next):
        if request.url.path.endswith("/health"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = monotonic()

        with self.lock:
            bucket = self.buckets[client_ip]
            while bucket and (now - bucket[0]) > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Please retry shortly.",
                        "window_seconds": self.window_seconds,
                        "max_requests": self.max_requests,
                    },
                )
            bucket.append(now)

        return await call_next(request)

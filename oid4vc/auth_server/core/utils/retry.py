"""Retry utilities for sync/async with exponential backoff."""

import asyncio
import inspect
import logging
import random
import time
from functools import wraps
from typing import Any, Callable, Iterable, Optional, Type


def with_retries(
    *,
    max_attempts: int = 3,
    base_delay: float = 0.2,
    max_delay: float = 2.0,
    jitter: float = 0.1,
    retry_on: Iterable[Type[BaseException]] = (Exception,),
    should_retry: Optional[Callable[[BaseException], bool]] = None,
    logger: Optional[logging.Logger] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Retry a callable on specified exceptions with backoff."""

    log = logger or logging.getLogger(__name__)
    retry_on_tuple = tuple(retry_on)

    def _next_delay(current: float) -> float:
        # Exponential backoff with small jitter
        rand = 1.0 + (jitter * random.random() if jitter > 0 else 0.0)
        return min(current * 2, max_delay) * rand

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                delay = base_delay
                for attempt in range(1, max_attempts + 1):
                    try:
                        return await func(*args, **kwargs)
                    except retry_on_tuple as exc:  # type: ignore[misc]
                        if should_retry is not None and not should_retry(exc):
                            raise
                        if attempt >= max_attempts:
                            raise
                        log.warning(
                            "%s attempt %d/%d failed: %s; retrying in %.2fs",
                            func.__name__,
                            attempt,
                            max_attempts,
                            exc,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        delay = _next_delay(delay)

            return async_wrapper

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            delay = base_delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except retry_on_tuple as exc:  # type: ignore[misc]
                    if should_retry is not None and not should_retry(exc):
                        raise
                    if attempt >= max_attempts:
                        raise
                    log.warning(
                        "%s attempt %d/%d failed: %s; retrying in %.2fs",
                        func.__name__,
                        attempt,
                        max_attempts,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                    delay = _next_delay(delay)

        return sync_wrapper

    return decorator

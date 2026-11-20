"""Rate limiting, retries and the shared retrieval error (design spec section 8.3-8.4).

RateLimiter and with_retries() are added in Task 4.
"""


class RetrievalError(Exception):
    """An external API could not be reached or answered with an error."""

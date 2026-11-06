"""Errors an agent can act on. The server turns all of these into ToolError."""


class DepauditError(Exception):
    """Base class: the message is written for the agent and says what to do next."""


class LockfileError(DepauditError):
    """A lockfile is missing, unsupported, or malformed."""


class NetworkError(DepauditError):
    """A remote API could not be reached or answered with an error."""


class RateLimitError(NetworkError):
    """A remote API kept answering HTTP 429."""


class NotFoundError(NetworkError):
    """A remote API answered HTTP 404."""

class WallboxError(Exception):
    """Base error for all wallbox client failures.

    The optional ``kind`` string mirrors the device's ``error.kind`` field and is
    kept populated on every subclass for backward compatibility with callers that
    branch on it (e.g. ``if err.kind == "Permission"``). New code should prefer
    catching the typed subclasses below.
    """

    def __init__(self, message=None, kind=None, field=None, key=None):
        self.kind = kind
        self.field = field
        self.message = message or "An error occurred"
        self.key = key
        super().__init__(self.__str__())

    def __str__(self):
        details = []
        if self.kind:
            details.append(f"Kind: {self.kind}")
        if self.field:
            details.append(f"Field: {self.field}")
        if self.key:
            details.append(f"URI: {self.key}")
        details.append(f"Message: {self.message}")
        return " | ".join(details)


class WallboxConnectionError(WallboxError):
    """The device could not be reached (refused, reset, network down)."""


class WallboxTimeoutError(WallboxError):
    """The device did not respond within the request timeout."""


class WallboxAuthError(WallboxError):
    """Authentication failed (bad password, or public-key challenge rejected)."""


class WallboxPermissionError(WallboxError):
    """The session is not (or no longer) authorized for this request.

    Corresponds to the device ``Permission`` error kind, which triggers the
    one-shot re-authentication retry in :meth:`WallboxClient.send`.
    """


class WallboxNotFoundError(WallboxError):
    """The requested resource does not exist (device ``NotFound`` error kind)."""


# Maps the device's ``error.kind`` string onto a typed exception class. Unknown
# kinds fall back to the base ``WallboxError``.
_KIND_TO_EXCEPTION = {
    "Permission": WallboxPermissionError,
    "NotFound": WallboxNotFoundError,
    "AuthenticationError": WallboxAuthError,
    "Authentication": WallboxAuthError,
}


def error_for_kind(kind):
    """Return the WallboxError subclass best matching a device ``error.kind``."""
    return _KIND_TO_EXCEPTION.get(kind, WallboxError)

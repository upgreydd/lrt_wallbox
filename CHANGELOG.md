# Changelog

## 0.2.0 (unreleased)

### Changed (mildly breaking)
- Network failures now raise typed `WallboxError` subclasses instead of leaking raw
  `requests` exceptions. New hierarchy: `WallboxConnectionError`, `WallboxTimeoutError`,
  `WallboxAuthError`, `WallboxPermissionError`, `WallboxNotFoundError` — all subclasses of
  `WallboxError`. Callers can now catch a single `WallboxError` for all device/transport
  failures. The `.kind` string is still populated for backward compatibility.
- Device `error.kind` values are mapped onto the matching exception subclass.

### Added
- `WallboxClient(key_path=...)` — choose where the ECDSA keypair is stored. Defaults to the
  package directory (legacy behaviour), but installs on read-only/shared filesystems
  (e.g. Home Assistant) should pass a writable, private directory.
- PEP 561 `py.typed` marker so downstreams get type information.
- Test suite (`pytest`) covering transport decode, error wrapping/mapping, key storage,
  auth caching, and log redaction. Install with `pip install -e '.[test]'`.

### Security
- DEBUG logs now redact sensitive fields (`password`, `encrypted`, `publicKey`, `signature`,
  `challenge`). Previously the cleartext password from `auth/password` could appear in logs.
- The private key file is created with `0600` permissions.
- Default `session_id` is now a random per-instance 10-digit value instead of a fixed
  constant (still overridable via the `session_id` argument).

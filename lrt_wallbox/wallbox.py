import logging
import os
import secrets
import threading
import time
from dataclasses import is_dataclass, asdict
from typing import Optional, TypeVar, Type, get_origin, get_args

import cbor2
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .exceptions import (
    WallboxError,
    WallboxConnectionError,
    WallboxTimeoutError,
    WallboxAuthError,
    error_for_kind,
)
from .msg_types import *

logger = logging.getLogger(__name__)

R = TypeVar("R")

# Keys whose values must never reach the logs (credentials / key material).
_SENSITIVE_KEYS = frozenset({"password", "encrypted", "publicKey", "signature", "challenge"})


def _redact(value):
    """Return a copy of *value* with sensitive fields masked, for safe logging."""
    if isinstance(value, dict):
        return {
            k: ("***" if k in _SENSITIVE_KEYS else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(_redact(v) for v in value)
    return value


class WallboxClient:
    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        session_id: Optional[str] = None,
        session_valid: float = 15.0,
        key_path: Optional[str] = None,
    ):
        """Create a client for an LRT/AEG wallbox.

        Args:
            ip: Device IP/host; reached over plaintext HTTP on the LAN.
            username / password: Device credentials for password auth.
            session_id: ``SESSIONID`` header value. Defaults to a random
                per-instance 10-digit string (override only if the device
                requires a specific value).
            session_valid: Seconds an auth is cached before re-authenticating.
            key_path: Directory in which to store the ECDSA keypair
                (``privkey.pem`` / ``pubkey.pem``). Defaults to the package
                directory for backwards compatibility, but callers running on
                read-only / shared installs (e.g. Home Assistant) should pass a
                writable, private location such as ``hass.config.path(...)``.
        """
        self.ip = ip
        self.session_id = session_id or "".join(secrets.choice("0123456789") for _ in range(10))
        self.__username = username
        self.__password = password
        self._session_valid = session_valid
        self._key_dir = key_path or os.path.dirname(__file__)
        self._last_key_auth = 0.0
        self._last_password_auth = 0.0
        self._key_auth_lock = threading.Lock()
        self._password_auth_lock = threading.Lock()

    def _load_keys(self) -> tuple[EllipticCurvePrivateKey, bytes]:
        priv_path = os.path.join(self._key_dir, "privkey.pem")
        pub_path = os.path.join(self._key_dir, "pubkey.pem")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                compressed_pub = f.read()
            return private_key, compressed_pub

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        compressed_pub = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            os.makedirs(self._key_dir, exist_ok=True)
            # Private key is a device credential: create it 0600 (owner-only).
            fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(priv_bytes)
            with open(pub_path, "wb") as f:
                f.write(compressed_pub)
        except OSError as e:
            raise WallboxError(
                message=(
                    f"Unable to persist wallbox keypair to {self._key_dir!r}: {e}. "
                    "Pass key_path= to a writable directory."
                ),
                kind="KeyStorageError",
            ) from e

        return private_key, compressed_pub

    def _key_auth(self):
        with self._key_auth_lock:
            if time.time() - self._last_key_auth < self._session_valid:
                logger.debug("Skipping key auth, still valid")
                return
            app_private_key, app_public_key = self._load_keys()
            user = self.user_current()
            if user.publicKey != list(app_public_key):
                logger.debug("User public key does not match local public key")
                user.publicKey = list(app_public_key)
                user_data = UserData(id=user.id, user=user)
                self.user_update(user_data)
            challenge_response = self.auth_key_init(user.id)
            logger.debug("Public key authentication challenge received")
            signature = app_private_key.sign(bytes(challenge_response.challenge), ec.ECDSA(hashes.SHA256()))
            r = self.auth_key_response(list(signature))
            if not r.authenticated:
                raise WallboxAuthError(message="Public key authentication failed", kind="AuthenticationError")
            self._last_key_auth = time.time()

    def _password_auth(self) -> None:
        with self._password_auth_lock:
            if time.time() - self._last_password_auth < self._session_valid:
                logger.debug("Skipping password auth, still valid")
                return
            r = self.auth_password(self.__username, self.__password)
            if not r.authenticated:
                raise WallboxAuthError(message="Password authentication failed", kind="AuthenticationError")
            self._last_password_auth = time.time()

    @staticmethod
    def _prepare_payload(payload) -> dict:
        if not payload.key.startswith("request/"):
            payload.key = f"request/{payload.key}"
        # If body is a list (CBOR array), skip asdict
        if hasattr(payload, "body") and isinstance(payload.body, list):
            return {"key": payload.key, "body": payload.body}
        if is_dataclass(payload):
            payload = asdict(payload)
        return payload

    def _maybe_authenticate(self, auth: bool, publickey_auth: bool) -> None:
        if auth:
            self._password_auth()
        if publickey_auth:
            self._key_auth()

    def send(self, key: str, response_model: Type[R], body: Optional[object] = None, auth=False, publickey_auth=False) -> Optional[R]:
        try:
            self._maybe_authenticate(auth, publickey_auth)
            return self._send_inner(key, response_model, body)
        except WallboxError as e:
            if e.kind == "Permission":
                if publickey_auth:
                    logger.debug("Publickey session expired — retrying key_auth() once.")
                    self._last_key_auth = 0
                    self._key_auth()
                    return self._send_inner(key, response_model, body)
                elif auth:
                    logger.debug("Password session expired — retrying auth_password() once.")
                    self._last_password_auth = 0
                    self._password_auth()
            raise

    def _send_inner(self, key: str, response_model: Type[R], body: Optional[object] = None) -> Optional[R]:
        if body is not None:
            if is_dataclass(body):
                if hasattr(body, "to_array"):
                    body = body.to_array()
                else:
                    body = asdict(body)
            payload = MessageRequest(key=key, body=body)
        else:
            payload = MessageRequest(key=key)
        payload = self._prepare_payload(payload)
        msg = f"sending payload key: {payload['key']}"
        if payload.get("body"):
            msg += f", body: {_redact(payload['body'])!r}"
        logger.debug(msg)

        encoded = cbor2.dumps(payload)
        try:
            resp = requests.post(
                f"http://{self.ip}/api",
                headers={
                    "Content-Type": "application/cbor",
                    "SESSIONID": self.session_id,
                },
                data=encoded,
                timeout=10,
            )
            resp.raise_for_status()
        except requests.exceptions.Timeout as e:
            raise WallboxTimeoutError(message=f"Request to {self.ip} timed out", kind="Timeout", key=key) from e
        except requests.exceptions.ConnectionError as e:
            raise WallboxConnectionError(message=f"Could not connect to {self.ip}: {e}", kind="ConnectionError", key=key) from e
        except requests.exceptions.RequestException as e:
            raise WallboxConnectionError(message=f"HTTP request to {self.ip} failed: {e}", kind="HTTPError", key=key) from e

        decoded = cbor2.loads(resp.content)
        if not resp.ok or not isinstance(decoded, dict):
            raise WallboxError(message=f"Invalid response: {decoded}", kind="InvalidResponse", key=key)
        else:
            logger.debug(f"received response: {_redact(decoded)}")
        if "error" in decoded:
            err = ErrorData(**decoded["error"])
            raise error_for_kind(err.kind)(message=err.message, field=err.field, kind=err.kind, key=key)

        body_data = decoded["body"]
        if response_model is not None:
            origin = get_origin(response_model)
            if origin in (list, tuple):
                item_type = get_args(response_model)[0] if get_args(response_model) else None
                if is_dataclass(item_type):
                    return [item_type(**item) for item in body_data]
                return body_data
            elif origin is dict:
                return body_data
            elif is_dataclass(response_model):
                if not isinstance(body_data, dict):
                    raise WallboxError(f"Invalid response: {body_data}", kind="InvalidResponse", key=key)
                return response_model(**body_data)
            else:
                return response_model(body_data)
        return body_data

    # Authentication methods
    def auth_password(self, name: str, password: str) -> AuthPasswordResponse:
        return self.send("auth/password", AuthPasswordResponse, AuthPasswordRequest(name=name, password=password))

    def auth_key_init(self, user_id: int) -> AuthKeyInitResponse:
        return self.send("auth/key/init", AuthKeyInitResponse, AuthKeyInitRequest(user_id=user_id))

    def auth_key_response(self, encrypted) -> AuthKeyResponseResponse:
        return self.send("auth/key/response", AuthKeyResponseResponse, AuthKeyResponseRequest(encrypted=encrypted))

    # Information retrieval methods
    def info_serial_get(self) -> InfoSerialGetResponse:
        return self.send("info/serial/get", InfoSerialGetResponse)

    def info_firmwares_get(self) -> InfoFirmwaresGetResponse:
        return self.send("info/firmwares/get", InfoFirmwaresGetResponse)

    # Network configuration methods
    def config_network_status(self) -> ConfigNetworkStatusResponse:
        return self.send("config/network/status", ConfigNetworkStatusResponse, auth=True)

    def config_network_get(self) -> ConfigNetworkGetResponse:
        return self.send("config/network/get", ConfigNetworkGetResponse, publickey_auth=True)

    def config_network_set(self):
        raise NotImplementedError("Network configuration set is not implemented yet.")

    #     self,
    #     wifi: Wifi = None,
    #     ethernet: Ethernet = None,
    # ) -> dict:
    #     return self.send("config/network/set", body, publickey_auth=True)

    # OCPP configuration methods
    def config_ocpp_get(self) -> ConfigOCCPData:
        return self.send("config/ocpp/get", ConfigOCCPData, publickey_auth=True)

    def config_ocpp_set(self, url: str = None) -> ConfigOCCPData:
        return self.send("config/ocpp/set", ConfigOCCPData, ConfigOCCPData(url), publickey_auth=True)

    # Load configuration methods
    def config_load_get(self) -> ConfigLoadResponse:
        return self.send("config/load/get", ConfigLoadResponse, publickey_auth=True)

    def config_load_set(self, max_current: int) -> ConfigLoadResponse:
        return self.send("config/load/set", ConfigLoadResponse, ConfigLoadSetRequest(maxCurrent=max_current), publickey_auth=True)

    # Setup completion methods
    def setup_get(self) -> SetupData:
        return self.send("setup/get", SetupData, publickey_auth=True)

    def setup_set(
        self,
        network: bool = True,
        ambient_light: bool = True,
        max_charging_power: bool = False,
    ) -> SetupData:
        return self.send(
            "setup/set",
            SetupData,
            SetupData(network=network, ambientLight=ambient_light, maxChargingPower=max_charging_power),
            publickey_auth=True,
        )

    # Atmel error retrieval method
    def atmel_error_get(self) -> AtmelErrorGetResponse:
        return self.send("atmel/error/get", AtmelErrorGetResponse)

    # RFID methods
    def rfid_get(self) -> list[RfidGetResponse]:
        return self.send("rfid/get", list[RfidGetResponse], publickey_auth=True)

    def rfid_scan(self, duration: int = 3) -> list[int]:
        if not 1 <= duration <= 3:
            raise ValueError("Duration must be between 1 and 3 seconds.")
        return self.send("rfid/scan", list[int], RfidScanRequest(duration=duration), publickey_auth=True)

    def rfid_add(self, tag_id: list[int], tag_name: str) -> RfidData:
        return self.send("rfid/add", RfidData, RfidData(tagId=tag_id, name=tag_name))

    def rfid_delete(self, tag_id: list) -> RfidData:
        return self.send("rfid/delete", RfidData, RfidDeleteRequest(tagId=tag_id), publickey_auth=True)

    # User management methods
    def user_get(self) -> list[User]:
        return self.send("user/get", list[User], auth=True)

    def user_current(self) -> User:
        return self.send("user/current", User, auth=True)

    def user_add(self, name: str, password: str, color: ColorFull, admin=False) -> User:
        return self.send("user/add", User, UserAddRequest(name=name, password=password, color=color, admin=admin), publickey_auth=True)

    def user_update(self, user_data: UserData) -> User:
        return self.send("user/update", User, user_data, auth=True)

    def user_delete(self, user_id: int) -> User:
        return self.send("user/delete", User, UserDeleteRequest(id=user_id), publickey_auth=True)

    # Transaction methods
    def transaction_get(self) -> TransactionEntry:
        return self.send("transaction/get", TransactionEntry, publickey_auth=True)

    def transaction_log_get(self) -> list[TransactionStopResponse]:
        return self.send("transaction/log/get", list[TransactionStopResponse], publickey_auth=True)

    def transaction_stop(self) -> TransactionStopResponse:
        return self.send("transaction/stop", TransactionStopResponse, publickey_auth=True)

    def transaction_start(self, tag_id: list[int]) -> TransactionEntry:
        return self.send("transaction/start", TransactionEntry, TransactionStartRequest(tag_id=tag_id), publickey_auth=True)

    # WLAN methods
    def wlan_scan(self) -> dict:
        raise NotImplementedError("WLAN scan is not implemented yet.")
        # return self.send("wlan/scan")

    # Utils methods
    def util_restart(self) -> UtilRestartData:
        return self.send("util/restart", UtilRestartData, UtilRestartData())

    def util_atmel_restart(self) -> UtilAtmelRestartResponse:
        return self.send("util/atmel/restart", UtilAtmelRestartResponse)

    def util_factory_reset(self) -> FactoryResetResponse:
        raise NotImplementedError("Factory reset is not implemented yet.")
        # return self.send("util/factory/reset", FactoryResetResponse)

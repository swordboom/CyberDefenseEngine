import hashlib
from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt


class TokenError(ValueError):
    pass


def sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_api_key(api_key: str, hash_salt: str) -> str:
    return sha256_hex(f"{hash_salt}|api_key|{api_key.strip()}")


def hash_identifier(identifier: str, hash_salt: str) -> str:
    return sha256_hex(f"{hash_salt}|id|{identifier.strip()}")


def create_access_token(
    *,
    secret: str,
    algorithm: str,
    institution_id: str,
    role: str,
    hashed_user_id: str | None,
    expires_minutes: int,
) -> str:
    now = datetime.now(tz=UTC)
    payload = {
        "sub": institution_id,
        "role": role,
        "hashed_user_id": hashed_user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_access_token(*, token: str, secret: str, algorithm: str) -> dict:
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
    except JWTError as exc:
        raise TokenError("Invalid or expired token") from exc
    institution_id = str(payload.get("sub", "")).strip()
    role = str(payload.get("role", "")).strip()
    if not institution_id or role not in {"student", "admin"}:
        raise TokenError("Token payload is missing required claims")
    return payload

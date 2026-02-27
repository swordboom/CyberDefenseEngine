from dataclasses import dataclass

from .config import Settings
from .schemas import AuthContextResponse, TokenResponse
from .security import TokenError, create_access_token, decode_access_token, hash_identifier
from .storage import Database, Institution, get_institution_by_api_key, seed_institutions


@dataclass
class AuthContext:
    institution_id: str
    institution_name: str
    plan_type: str
    role: str = "student"
    hashed_user_id: str | None = None

    def to_response(self) -> AuthContextResponse:
        return AuthContextResponse(
            institution_id=self.institution_id,
            institution_name=self.institution_name,
            plan_type=self.plan_type,
            role=self.role,
            hashed_user_id=self.hashed_user_id,
        )


class AuthManager:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self.default_institution_name = settings.default_institution_name

    def bootstrap(self) -> None:
        self.db.init_schema()
        with self.db.session() as session:
            seed_institutions(
                session,
                seeds=self.settings.institution_seed_json,
                hash_salt=self.settings.hash_salt,
            )

    def _get_default_context(self) -> AuthContext:
        with self.db.session() as session:
            for institution_name in (self.default_institution_name, "public-dev"):
                existing = get_institution_by_api_key(
                    session,
                    api_key=self.settings.institution_seed_json.get(institution_name, {}).get("api_key", ""),
                    hash_salt=self.settings.hash_salt,
                )
                if existing is not None:
                    return AuthContext(
                        institution_id=existing.id,
                        institution_name=existing.name,
                        plan_type=existing.plan_type,
                        role="student",
                    )
        raise ValueError("No default institution is configured")

    def validate_api_key(self, api_key: str | None) -> AuthContext:
        if not api_key:
            if self.settings.require_api_key:
                raise ValueError("Missing API key")
            return self._get_default_context()

        with self.db.session() as session:
            institution = get_institution_by_api_key(
                session,
                api_key=api_key,
                hash_salt=self.settings.hash_salt,
            )
            if institution is None:
                raise ValueError("Invalid API key")
            return AuthContext(
                institution_id=institution.id,
                institution_name=institution.name,
                plan_type=institution.plan_type,
                role="student",
            )

    def issue_token(self, *, api_key: str | None, role: str, hashed_user_id: str | None) -> TokenResponse:
        context = self.validate_api_key(api_key)
        normalized_role = role if role in {"student", "admin"} else "student"
        token = create_access_token(
            secret=self.settings.jwt_secret,
            algorithm=self.settings.jwt_algorithm,
            institution_id=context.institution_id,
            role=normalized_role,
            hashed_user_id=hashed_user_id,
            expires_minutes=self.settings.jwt_exp_minutes,
        )
        return TokenResponse(
            access_token=token,
            expires_in=self.settings.jwt_exp_minutes * 60,
            institution_id=context.institution_id,
            role=normalized_role,  # type: ignore[arg-type]
        )

    def validate_token(self, token: str) -> AuthContext:
        payload = decode_access_token(
            token=token,
            secret=self.settings.jwt_secret,
            algorithm=self.settings.jwt_algorithm,
        )
        institution_id = str(payload["sub"])
        role = str(payload["role"])
        hashed_user_id = payload.get("hashed_user_id")

        with self.db.session() as session:
            institution = session.get(Institution, institution_id)
            if institution is None:
                raise TokenError("Institution in token no longer exists")
            return AuthContext(
                institution_id=institution.id,
                institution_name=institution.name,
                plan_type=institution.plan_type,
                role=role,
                hashed_user_id=str(hashed_user_id).strip() if hashed_user_id else None,
            )

    def normalize_hashed_user_id(self, raw_value: str | None) -> str | None:
        if not raw_value:
            return None
        return hash_identifier(raw_value, self.settings.hash_salt)

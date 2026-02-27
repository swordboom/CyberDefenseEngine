import httpx


class ServiceCallError(RuntimeError):
    pass


class InternalServiceClient:
    def __init__(self, *, base_url: str, internal_token: str, timeout_ms: int):
        self.base_url = base_url.rstrip("/")
        self.internal_token = internal_token
        self.timeout = timeout_ms / 1000.0

    def _headers(self) -> dict[str, str]:
        return {"X-Internal-Token": self.internal_token}

    def post_json(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ServiceCallError(f"Invalid response payload from {url}")
            return data
        except httpx.HTTPError as exc:
            raise ServiceCallError(f"Request to {url} failed: {exc}") from exc

    def get_json(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.get(url, params=params, headers=self._headers(), timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ServiceCallError(f"Invalid response payload from {url}")
            return data
        except httpx.HTTPError as exc:
            raise ServiceCallError(f"Request to {url} failed: {exc}") from exc

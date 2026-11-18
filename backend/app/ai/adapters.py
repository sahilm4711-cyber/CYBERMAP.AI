"""Provider adapters — Phase 6 (ARCHITECTURE.md §7).

One interface, one adapter per provider (OpenAI, Groq, Google Gemini).
The provider is chosen by ``AI_PROVIDER`` / ``AI_MODEL`` env vars;
API keys are read ONLY from env vars at call time
(``OPENAI_API_KEY``, ``GROQ_API_KEY``, ``GOOGLE_API_KEY``) — never
stored, never logged, never present in code.

All provider failures are mapped to :class:`AIProviderError` with no
key material and no raw provider payload in the message, so nothing
sensitive can leak to API clients.
"""

import os

import httpx

from app.core.config import settings

REQUEST_TIMEOUT = 30.0
MAX_ATTEMPTS = 2  # one initial attempt + one retry on 5xx

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "groq": "llama-3.3-70b-versatile",
    "google-gemini": "gemini-2.0-flash",
}

OPENAI_EMBED_MODEL = "text-embedding-3-small"
GEMINI_EMBED_MODEL = "text-embedding-004"


class AIProviderError(Exception):
    """A provider call failed (missing key, HTTP error, bad payload).

    The message never contains key material or raw provider payloads.
    """


class BaseLLMAdapter:
    """Common interface every provider adapter implements."""

    provider_name: str = "base"
    env_key_name: str = ""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.model = model or DEFAULT_MODELS.get(
            self.provider_name, ""
        )
        # An explicitly passed key (tests) wins; otherwise the key is
        # read from the environment at call time, never stored here.
        self._api_key = api_key
        self._client = client
        self._transport = transport

    # -- key handling -------------------------------------------------
    def _get_api_key(self) -> str:
        key = self._api_key or os.environ.get(self.env_key_name, "")
        if not key:
            raise AIProviderError(
                f"{self.provider_name} API key is not configured"
            )
        return key

    def _http_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(
            timeout=REQUEST_TIMEOUT, transport=self._transport
        )

    def _owns_client(self) -> bool:
        return self._client is None

    # -- shared POST with one retry on 5xx ----------------------------
    def _post(self, url: str, headers: dict, payload: dict) -> dict:
        """POST ``payload`` as JSON; retry once on 5xx; return JSON."""
        # Key is only needed for authenticated calls; callers that
        # need it fetch it before calling this.
        client = self._http_client()
        last_error: Exception | None = None
        try:
            for attempt in range(MAX_ATTEMPTS):
                try:
                    response = client.post(
                        url, headers=headers, json=payload
                    )
                except httpx.TimeoutException as exc:
                    raise AIProviderError(
                        f"{self.provider_name} request timed out"
                    ) from exc
                except httpx.TransportError as exc:
                    raise AIProviderError(
                        f"{self.provider_name} request failed"
                    ) from exc
                if response.status_code >= 500 and attempt == 0:
                    last_error = AIProviderError(
                        f"{self.provider_name} returned HTTP "
                        f"{response.status_code}"
                    )
                    continue
                if response.status_code >= 400:
                    raise AIProviderError(
                        f"{self.provider_name} returned HTTP "
                        f"{response.status_code}"
                    )
                try:
                    return response.json()
                except ValueError as exc:
                    raise AIProviderError(
                        f"{self.provider_name} returned an "
                        "unparseable response"
                    ) from exc
            raise last_error or AIProviderError(
                f"{self.provider_name} request failed"
            )
        finally:
            if self._owns_client():
                client.close()

    # -- interface ----------------------------------------------------
    def chat(self, messages: list[dict], **kwargs) -> str:
        """Return the provider's reply text for ``messages``."""
        raise NotImplementedError

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one embedding vector per input text.

        Raises NotImplementedError when the provider has no
        embeddings API (e.g. Groq).
        """
        raise NotImplementedError


class _OpenAICompatibleAdapter(BaseLLMAdapter):
    """Shared chat logic for OpenAI and Groq (same wire format)."""

    chat_url: str = ""
    embeddings_url: str | None = None
    embed_model: str | None = None

    def chat(self, messages: list[dict], **kwargs) -> str:
        key = self._get_api_key()
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
        }
        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]
        data = self._post(
            self.chat_url,
            {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            payload,
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError(
                f"{self.provider_name} returned an unexpected "
                "chat response"
            ) from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        if self.embeddings_url is None or self.embed_model is None:
            raise NotImplementedError(
                f"{self.provider_name} does not offer an embeddings API"
            )
        key = self._get_api_key()
        data = self._post(
            self.embeddings_url,
            {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            {"model": self.embed_model, "input": texts},
        )
        try:
            return [item["embedding"] for item in data["data"]]
        except (KeyError, TypeError) as exc:
            raise AIProviderError(
                f"{self.provider_name} returned an unexpected "
                "embeddings response"
            ) from exc


class OpenAIAdapter(_OpenAICompatibleAdapter):
    """OpenAI chat + embeddings."""

    provider_name = "openai"
    env_key_name = "OPENAI_API_KEY"
    chat_url = "https://api.openai.com/v1/chat/completions"
    embeddings_url = "https://api.openai.com/v1/embeddings"
    embed_model = OPENAI_EMBED_MODEL


class GroqAdapter(_OpenAICompatibleAdapter):
    """Groq chat (OpenAI-compatible endpoint). No embeddings API."""

    provider_name = "groq"
    env_key_name = "GROQ_API_KEY"
    chat_url = "https://api.groq.com/openai/v1/chat/completions"
    embeddings_url = None
    embed_model = None


class GeminiAdapter(BaseLLMAdapter):
    """Google Gemini chat + embeddings (``?key=`` auth)."""

    provider_name = "google-gemini"
    env_key_name = "GOOGLE_API_KEY"
    embed_model = GEMINI_EMBED_MODEL

    def _model_url(self, action: str) -> str:
        key = self._get_api_key()
        return (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:{action}?key={key}"
        )

    def chat(self, messages: list[dict], **kwargs) -> str:
        # Gemini takes a single prompt; flatten the message list.
        prompt = "\n\n".join(
            f"{m.get('role', 'user')}: {m.get('content', '')}"
            for m in messages
        )
        data = self._post(
            self._model_url("generateContent"),
            {"Content-Type": "application/json"},
            {"contents": [{"parts": [{"text": prompt}]}]},
        )
        try:
            return data["candidates"][0]["content"]["parts"][0][
                "text"
            ]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError(
                "google-gemini returned an unexpected chat response"
            ) from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        key = self._get_api_key()
        vectors: list[list[float]] = []
        for text in texts:
            data = self._post(
                "https://generativelanguage.googleapis.com/v1beta/"
                f"models/{self.embed_model}:embedContent?key={key}",
                {"Content-Type": "application/json"},
                {
                    "model": f"models/{self.embed_model}",
                    "content": {"parts": [{"text": text}]},
                },
            )
            try:
                vectors.append(data["embedding"]["values"])
            except (KeyError, TypeError) as exc:
                raise AIProviderError(
                    "google-gemini returned an unexpected "
                    "embeddings response"
                ) from exc
        return vectors


_ADAPTERS = {
    "openai": OpenAIAdapter,
    "groq": GroqAdapter,
    "google-gemini": GeminiAdapter,
    "gemini": GeminiAdapter,
    "google": GeminiAdapter,
}


def get_adapter(
    client: httpx.Client | None = None,
    transport: httpx.BaseTransport | None = None,
) -> BaseLLMAdapter | None:
    """Build the configured provider adapter, or None in fallback mode.

    Empty ``settings.ai_provider`` means no provider is configured
    and the caller must use the non-AI fallback. An unknown provider
    name raises ValueError.
    """
    provider = (settings.ai_provider or "").strip().lower()
    if not provider:
        return None
    cls = _ADAPTERS.get(provider)
    if cls is None:
        raise ValueError(f"Unknown AI provider: {provider!r}")
    model = (settings.ai_model or "").strip() or None
    return cls(model=model, client=client, transport=transport)

import os
import re
import json
import math
import time
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from app.config import settings

# Detect pre-installed AI/ML packages (Zero new installations)
HAS_OPENAI: bool = False
openai: Any = None
try:
    import openai  # type: ignore
    HAS_OPENAI = True
except Exception:
    pass

HAS_GOOGLE_GENAI: bool = False
genai: Any = None
try:
    from google import genai  # type: ignore
    HAS_GOOGLE_GENAI = True
except Exception:
    pass

HAS_SKLEARN: bool = False
IsolationForest: Any = None
np: Any = None
try:
    import sklearn  # type: ignore
    from sklearn.ensemble import IsolationForest  # type: ignore
    import numpy as np  # type: ignore
    HAS_SKLEARN = True
except Exception:
    pass


# =============================================================================
# BASE AI MODEL PROVIDER
# =============================================================================
class BaseAiModelProvider(ABC):
    """Abstract Base Class for Multi-Provider AI Model Backends."""

    def __init__(self, model_name: str, **kwargs):
        self.model_name = model_name
        self.config = kwargs

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name identifier of the AI provider."""
        pass

    @abstractmethod
    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        """Generate text completion from the AI model."""
        pass

    @abstractmethod
    def check_health(self) -> Dict[str, Any]:
        """Verify model connectivity and availability."""
        pass

    def get_model_info(self) -> Dict[str, Any]:
        """Return provider configuration telemetry."""
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "is_configured": True,
        }


# =============================================================================
# 1. OLLAMA PROVIDER (Local Small Language Models)
# =============================================================================
class OllamaProvider(BaseAiModelProvider):
    """Local Ollama Engine (qwen2.5:7b, qwen2.5-coder:7b)."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        host_url: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ):
        model = model_name or settings.ai_model_name or "qwen2.5:7b"
        super().__init__(model, **kwargs)
        self.host_url = (host_url or settings.ollama_host or "http://localhost:11434").rstrip("/")
        self.timeout = timeout or settings.ai_timeout_seconds or 60.0

    @property
    def provider_name(self) -> str:
        return "ollama"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system_prompt:
            payload["system"] = system_prompt
        if json_format:
            payload["format"] = "json"

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host_url}/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "")

    def load_model(self) -> Dict[str, Any]:
        """Warm up / load the target Qwen 7B model into memory."""
        try:
            payload = {"model": self.model_name, "prompt": "", "stream": False}
            req = urllib.request.Request(
                f"{self.host_url}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {"status": "loaded", "model": self.model_name, "response": data}
        except Exception as e:
            return {"status": "load_failed", "model": self.model_name, "error": str(e)}

    def pull_model(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Trigger model pull on Ollama instance."""
        target = model_name or self.model_name
        try:
            payload = {"name": target, "stream": False}
            req = urllib.request.Request(
                f"{self.host_url}/api/pull",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=900.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {"status": "pulled", "model": target, "response": data}
        except Exception as e:
            return {"status": "pull_failed", "model": target, "error": str(e)}

    def check_health(self) -> Dict[str, Any]:
        start_t = time.perf_counter()
        # Fast raw TCP socket test (0.15s) so we fail fast if Ollama daemon is offline
        try:
            parsed = urlparse(self.host_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 11434
            with socket.create_connection((host, port), timeout=0.15):
                pass
        except Exception as sock_err:
            latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return {
                "status": "offline",
                "provider": self.provider_name,
                "target_url": self.host_url,
                "active_model": self.model_name,
                "available_models": [],
                "model_installed": False,
                "latency_ms": latency_ms,
                "error": f"Ollama daemon not reachable at {self.host_url}: {sock_err}",
                "installed_locally": False,
            }

        try:
            req = urllib.request.Request(f"{self.host_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name") for m in data.get("models", [])]
                latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
                
                # Check whether target model or any Qwen model is available
                has_target = any(self.model_name in m or "qwen" in m.lower() for m in models)
                status_val = "ready" if has_target else ("models_present" if models else "no_models")

                return {
                    "status": status_val,
                    "provider": self.provider_name,
                    "target_url": self.host_url,
                    "active_model": self.model_name,
                    "available_models": models,
                    "model_installed": has_target,
                    "latency_ms": latency_ms,
                    "installed_locally": True,
                }
        except Exception as e:
            latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return {
                "status": "offline",
                "provider": self.provider_name,
                "target_url": self.host_url,
                "active_model": self.model_name,
                "error": str(e),
                "latency_ms": latency_ms,
                "installed_locally": False,
            }


# =============================================================================
# 2. OPENAI / OPENAI-COMPATIBLE PROVIDER
# =============================================================================
class OpenAiProvider(BaseAiModelProvider):
    """
    OpenAI (GPT-4o, GPT-4o-mini) and OpenAI-compatible API Endpoints
    (Groq, vLLM, LMStudio, DeepSeek, LocalAI).
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ):
        model = model_name or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        super().__init__(model, **kwargs)
        self.api_key = api_key or settings.openai_api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = (base_url or settings.openai_base_url or "https://api.openai.com/v1").rstrip("/")
        self.timeout = timeout or settings.ai_timeout_seconds or 5.0

    @property
    def provider_name(self) -> str:
        return "openai"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not configured.")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
        }
        if json_format:
            payload["response_format"] = {"type": "json_object"}

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            return ""

    def check_health(self) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "ready_unconfigured",
                "provider": self.provider_name,
                "model": self.model_name,
                "base_url": self.base_url,
                "message": "OpenAI provider is code-ready; provide OPENAI_API_KEY to activate live API calls",
                "has_sdk": HAS_OPENAI,
            }
        return {
            "status": "configured",
            "provider": self.provider_name,
            "model": self.model_name,
            "base_url": self.base_url,
            "has_sdk": HAS_OPENAI,
        }


# =============================================================================
# 3. GOOGLE GEMINI PROVIDER
# =============================================================================
class GeminiProvider(BaseAiModelProvider):
    """Google Gemini (Gemini 1.5 Flash/Pro, Gemini 2.0)."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ):
        model = model_name or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        super().__init__(model, **kwargs)
        self.api_key = api_key or settings.gemini_api_key or os.getenv("GEMINI_API_KEY", "")
        self.timeout = timeout or settings.ai_timeout_seconds or 5.0

    @property
    def provider_name(self) -> str:
        return "gemini"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured.")

        # If google-genai SDK is present, attempt SDK invocation
        if HAS_GOOGLE_GENAI:
            try:
                client = genai.Client(api_key=self.api_key)
                full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
                response = client.models.generate_content(
                    model=self.model_name,
                    contents=full_prompt,
                )
                return response.text or ""
            except Exception:
                pass

        # Standard REST API invocation
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        contents = [{"parts": [{"text": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt}]}]
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if json_format:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
            return ""

    def check_health(self) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "ready_unconfigured",
                "provider": self.provider_name,
                "model": self.model_name,
                "message": "Google Gemini provider is code-ready; provide GEMINI_API_KEY to activate live API calls",
                "has_sdk": HAS_GOOGLE_GENAI,
            }
        return {
            "status": "configured",
            "provider": self.provider_name,
            "model": self.model_name,
            "has_sdk": HAS_GOOGLE_GENAI,
        }


# =============================================================================
# 4. ANTHROPIC CLAUDE PROVIDER
# =============================================================================
class AnthropicProvider(BaseAiModelProvider):
    """Anthropic Claude (Claude 3.5 Sonnet, Claude 3 Haiku)."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ):
        model = model_name or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        super().__init__(model, **kwargs)
        self.api_key = api_key or settings.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.timeout = timeout or settings.ai_timeout_seconds or 5.0

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not configured.")

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data.get("content", [])
            if content:
                return content[0].get("text", "")
            return ""

    def check_health(self) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "ready_unconfigured",
                "provider": self.provider_name,
                "model": self.model_name,
                "message": "Anthropic Claude provider is code-ready; provide ANTHROPIC_API_KEY to activate",
            }
        return {
            "status": "configured",
            "provider": self.provider_name,
            "model": self.model_name,
        }


# =============================================================================
# 5. HUGGING FACE INFERENCE PROVIDER
# =============================================================================
class HuggingFaceProvider(BaseAiModelProvider):
    """Hugging Face Inference API / Serverless Router."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ):
        model = model_name or os.getenv("HF_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
        # If it's passed an Ollama local tag instead of a HF repo, override it
        if "qwen" in model.lower() and "/" not in model:
            model = "Qwen/Qwen2.5-Coder-7B-Instruct"
            
        super().__init__(model, **kwargs)
        self.api_key = api_key or settings.huggingface_api_key or os.getenv("HUGGINGFACE_API_KEY", "")
        self.timeout = timeout or settings.ai_timeout_seconds or 5.0

    @property
    def provider_name(self) -> str:
        return "huggingface"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise ValueError("HUGGINGFACE_API_KEY is not configured.")

        try:
            from huggingface_hub import InferenceClient
        except ImportError:
            raise RuntimeError("huggingface_hub is not installed. Run 'pip install huggingface_hub'.")

        client = InferenceClient(token=self.api_key, timeout=self.timeout)
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            # Using chat_completion for instruct models like Qwen2.5-Coder-7B-Instruct
            response = client.chat_completion(
                model=self.model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=1024
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Hugging Face API Error: {e}")
            raise

    def check_health(self) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "ready_unconfigured",
                "provider": self.provider_name,
                "model": self.model_name,
                "message": "Hugging Face provider is code-ready; provide HUGGINGFACE_API_KEY to activate",
            }
        return {
            "status": "configured",
            "provider": self.provider_name,
            "model": self.model_name,
        }


# =============================================================================
# 6. LOCAL ML ANOMALY & THREAT DETECTOR (Offline Scikit-Learn Engine)
# =============================================================================
class LocalMLDetectorProvider(BaseAiModelProvider):
    """
    Offline Machine Learning Security Anomaly Detector.
    Uses scikit-learn & numpy to compute entropy, token frequency, structural deviations,
    and IsolationForest outlier scoring for 100% air-gapped sovereign intelligence.
    """

    def __init__(self, model_name: str = "ulpf_isolation_forest_v1", **kwargs):
        super().__init__(model_name, **kwargs)
        self._baseline_model = None
        self._init_baseline_model()

    @property
    def provider_name(self) -> str:
        return "local_ml"

    def _init_baseline_model(self):
        """Train baseline model on standard RFC syslog token features if scikit-learn is present."""
        if HAS_SKLEARN:
            try:
                # Sample baseline vectors [char_len, entropy, digit_ratio, punct_ratio, word_count]
                X_train = np.array([
                    [120, 4.2, 0.15, 0.12, 16],
                    [95, 3.9, 0.20, 0.10, 12],
                    [150, 4.4, 0.10, 0.15, 20],
                    [80, 3.8, 0.25, 0.08, 10],
                    [200, 4.6, 0.08, 0.18, 25],
                    [110, 4.1, 0.18, 0.11, 15],
                ])
                forest_kwargs: Dict[str, Any] = {"contamination": 0.1, "random_state": 42}
                self._baseline_model = IsolationForest(**forest_kwargs)  # type: ignore
                self._baseline_model.fit(X_train)
            except Exception:
                self._baseline_model = None

    def extract_features(self, text: str) -> List[float]:
        """Extract multi-dimensional statistical telemetry features from raw log string."""
        length = len(text)
        if length == 0:
            return [0.0, 0.0, 0.0, 0.0, 0.0]

        # Shannon Entropy
        probs = [text.count(c) / length for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)

        # Digit & Punctuation ratios
        digits = sum(1 for c in text if c.isdigit())
        puncts = sum(1 for c in text if not c.isalnum() and not c.isspace())
        words = len(text.split())

        return [float(length), round(entropy, 3), round(digits / length, 3), round(puncts / length, 3), float(words)]

    def score_anomaly(self, raw_message: str) -> Dict[str, Any]:
        """
        Calculate threat & anomaly confidence score (0.0 to 1.0).
        0.0 = Normal telemetry, 1.0 = Highly anomalous exploit attempt.
        """
        features = self.extract_features(raw_message)
        msg_lower = raw_message.lower()

        base_score = 0.05
        factors = []

        # High entropy payload check (e.g. base64 exploit, encrypted payload)
        if features[1] > 4.8:
            base_score += 0.35
            factors.append("High Shannon entropy (obfuscated or binary payload)")

        # SQL Injection indicators
        if any(k in msg_lower for k in ("union select", "' or '1'='1", "1=1", "drop table", "--", "information_schema")):
            base_score += 0.55
            factors.append("SQL injection syntax signature")

        # Command Injection & XSS indicators
        if any(k in msg_lower for k in ("; cat /etc/passwd", "| sh", "/bin/sh", "<script", "alert(", "cmd.exe")):
            base_score += 0.50
            factors.append("Command / script injection pattern")

        # Brute-force authentication failures
        if any(k in msg_lower for k in ("failed password", "invalid user", "auth_fail", "auth_failed", "login failure")):
            base_score += 0.40
            factors.append("Repeated authentication failure indicator")

        # Isolation Forest outlier scoring if available
        if HAS_SKLEARN and self._baseline_model is not None:
            try:
                vec = np.array([features])
                score_raw = self._baseline_model.score_samples(vec)[0]
                # Map isolation forest score [-1.0, 0.5] to anomaly factor
                if score_raw < -0.15:
                    base_score += 0.20
                    factors.append("Statistical feature-space outlier (IsolationForest)")
            except Exception:
                pass

        final_score = round(min(1.0, base_score), 2)
        severity = "critical" if final_score >= 0.85 else ("high" if final_score >= 0.65 else ("medium" if final_score >= 0.40 else "low"))

        return {
            "anomaly_score": final_score,
            "severity": severity,
            "is_anomalous": final_score >= 0.50,
            "features": {
                "char_length": features[0],
                "shannon_entropy": features[1],
                "digit_ratio": features[2],
                "punctuation_ratio": features[3],
                "word_count": features[4],
            },
            "anomaly_factors": factors if factors else ["Standard operational format"],
        }

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        """Local ML statistical heuristic text synthesis."""
        return json.dumps({
            "model": "local_ml_isolation_forest",
            "status": "heuristic_synthesized",
            "prompt_tokens_evaluated": len(prompt.split()),
        })

    def check_health(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "provider": self.provider_name,
            "model": self.model_name,
            "scikit_learn_loaded": HAS_SKLEARN,
            "offline_air_gapped": True,
            "zero_api_key_required": True,
        }


class HeuristicProvider(BaseAiModelProvider):
    """Deterministic Rule-Based / Heuristic AI provider for offline analysis."""

    def __init__(self, model_name: Optional[str] = None, **kwargs):
        super().__init__(model_name or "heuristic-rule-engine-v1", **kwargs)

    @property
    def provider_name(self) -> str:
        return "heuristic"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        return json.dumps({
            "model": self.model_name,
            "status": "heuristic_synthesized",
            "format": "key_value" if "src=" in prompt or "dst=" in prompt else "delimited",
        })

    def check_health(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "provider": self.provider_name,
            "model": self.model_name,
            "offline_air_gapped": True,
            "zero_api_key_required": True,
        }

# =============================================================================
# 8. THREE-STEP CASCADING FALLBACK PROVIDER
# =============================================================================
class ThreeStepFallbackProvider(BaseAiModelProvider):
    """
    Cascading 3-Step Router:
    1. Local Model (Ollama)
    2. API Key Model (HuggingFace/OpenAI)
    3. Default (Heuristic/Pydantic)
    """

    def __init__(self, model_name: Optional[str] = None, **kwargs):
        super().__init__(model_name or "cascading-router", **kwargs)
        self.step1_local = OllamaProvider()
        self.step2_api = HuggingFaceProvider()
        self.step3_default = HeuristicProvider()

    @property
    def provider_name(self) -> str:
        return "three_step"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.2,
    ) -> str:
        # Step 1: Local Model
        try:
            h1 = self.step1_local.check_health()
            if h1.get("status") in ("ready", "models_present"):
                return self.step1_local.generate_text(prompt, system_prompt, json_format, temperature)
        except Exception:
            pass

        # Step 2: API Key Model
        try:
            h2 = self.step2_api.check_health()
            if h2.get("status") == "configured":
                return self.step2_api.generate_text(prompt, system_prompt, json_format, temperature)
        except Exception:
            pass

        # Step 3: Default Pydantic/Heuristic
        return self.step3_default.generate_text(prompt, system_prompt, json_format, temperature)

    def check_health(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "provider": self.provider_name,
            "model": self.model_name,
            "message": "3-Step Fallback Strategy Enabled (Local -> API -> Pydantic)"
        }



# =============================================================================
# AI PROVIDER FACTORY & ORCHESTRATOR
# =============================================================================
class AiProviderFactory:
    """
    Dynamic Multi-Provider AI Factory.
    Routes queries to the primary Ollama sovereign LLM engine (or external backends if configured).
    """

    SUPPORTED_PROVIDERS: List[str] = [
        "ollama",
        "openai",
        "gemini",
        "anthropic",
        "huggingface",
        "local_ml",
        "heuristic",
        "three_step",
    ]

    _instances: Dict[str, BaseAiModelProvider] = {}
    _active_provider_name: str = "ollama"

    @classmethod
    def _create_provider(cls, p_name: str, model_name: Optional[str] = None) -> BaseAiModelProvider:
        """Create concrete provider instance avoiding abstract class instantiation warnings."""
        if p_name == "openai":
            return OpenAiProvider(model_name=model_name)
        elif p_name == "gemini":
            return GeminiProvider(model_name=model_name)
        elif p_name == "anthropic":
            return AnthropicProvider(model_name=model_name)
        elif p_name == "huggingface":
            return HuggingFaceProvider(model_name=model_name)
        elif p_name == "local_ml":
            return LocalMLDetectorProvider(model_name=model_name or "ulpf_isolation_forest_v1")
        elif p_name == "heuristic":
            return HeuristicProvider(model_name=model_name)
        elif p_name == "three_step":
            return ThreeStepFallbackProvider(model_name=model_name)
        else:
            return OllamaProvider(model_name=model_name)

    @classmethod
    def get_provider(
        cls,
        provider_name: Optional[str] = None,
        model_name: Optional[str] = None,
    ) -> BaseAiModelProvider:
        """Instantiate or retrieve cached AI provider."""
        p_name = (provider_name or settings.ai_provider or cls._active_provider_name or "ollama").lower()
        if p_name not in cls.SUPPORTED_PROVIDERS:
            p_name = "ollama"

        cache_key = f"{p_name}:{model_name or 'default'}"
        if cache_key not in cls._instances:
            cls._instances[cache_key] = cls._create_provider(p_name, model_name)

        return cls._instances[cache_key]

    @classmethod
    def set_active_provider(cls, provider_name: str) -> bool:
        """Switch the system-wide active AI provider at runtime."""
        p_name = provider_name.lower()
        if p_name in cls.SUPPORTED_PROVIDERS:
            cls._active_provider_name = p_name
            return True
        return False

    @classmethod
    def get_active_provider_name(cls) -> str:
        return cls._active_provider_name

    @classmethod
    def list_all_providers(cls) -> List[Dict[str, Any]]:
        """Return health and status across all supported AI providers."""
        results = []
        for name in cls.SUPPORTED_PROVIDERS:
            provider = cls.get_provider(name)
            health = provider.check_health()
            results.append({
                "provider": name,
                "is_active": (name == cls._active_provider_name),
                "health": health,
            })
        return results

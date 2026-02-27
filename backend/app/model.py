import logging
import os
import re
import time
from dataclasses import dataclass

import numpy as np

try:
    import onnxruntime as ort
except Exception:  # pragma: no cover
    ort = None

try:
    import torch
except Exception:  # pragma: no cover
    torch = None

try:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
except Exception:  # pragma: no cover
    AutoModelForSequenceClassification = None
    AutoTokenizer = None

logger = logging.getLogger(__name__)


@dataclass
class InferenceResult:
    risk_score: float
    latency_ms: float
    backend: str


class PhishingModel:
    def __init__(
        self,
        model_name: str,
        onnx_path: str,
        onnx_quantized_path: str | None = None,
        max_length: int = 256,
        onnx_intra_op_threads: int = 0,
        onnx_inter_op_threads: int = 0,
        onnx_providers: list[str] | None = None,
        force_heuristic: bool = False,
        hf_token: str | None = None,
    ):
        self.max_length = max_length
        self.tokenizer = None
        self.model = None
        self.onnx_path = onnx_path
        self.onnx_session = None
        self.onnx_input_names = set()
        self.force_heuristic = force_heuristic
        self.hf_token = hf_token
        self.backend = "heuristic"
        self.onnx_providers = onnx_providers or ["CPUExecutionProvider"]

        if self.force_heuristic:
            logger.info("Heuristic mode forced via configuration")
            return

        if AutoTokenizer is not None:
            try:
                token_kwargs = {"token": self.hf_token} if self.hf_token else {}
                self.tokenizer = AutoTokenizer.from_pretrained(model_name, **token_kwargs)
            except Exception as exc:
                logger.warning("Tokenizer load failed, using heuristic fallback: %s", exc)

        selected_onnx_path = onnx_quantized_path or onnx_path
        if self.tokenizer is not None and ort is not None and os.path.exists(selected_onnx_path):
            try:
                session_options = ort.SessionOptions()
                session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                if onnx_intra_op_threads > 0:
                    session_options.intra_op_num_threads = onnx_intra_op_threads
                if onnx_inter_op_threads > 0:
                    session_options.inter_op_num_threads = onnx_inter_op_threads

                self.onnx_session = ort.InferenceSession(
                    selected_onnx_path,
                    sess_options=session_options,
                    providers=self.onnx_providers,
                )
                self.onnx_input_names = {entry.name for entry in self.onnx_session.get_inputs()}
                self.backend = "onnx"
            except Exception as exc:
                logger.warning("ONNX session init failed, attempting torch/heuristic path: %s", exc)

        if self.onnx_session is None and self.tokenizer is not None:
            if AutoModelForSequenceClassification is not None and torch is not None:
                try:
                    token_kwargs = {"token": self.hf_token} if self.hf_token else {}
                    self.model = AutoModelForSequenceClassification.from_pretrained(
                        model_name,
                        num_labels=2,
                        **token_kwargs,
                    )
                    self.model.eval()
                    self.backend = "torch"
                except Exception as exc:
                    logger.warning("Torch model load failed, using heuristic fallback: %s", exc)

    @staticmethod
    def _softmax(logits: np.ndarray) -> np.ndarray:
        shifted = logits - np.max(logits, axis=-1, keepdims=True)
        exp = np.exp(shifted)
        return exp / np.sum(exp, axis=-1, keepdims=True)

    def _url_features(self, url: str) -> float:
        suspicious = ["login", "verify", "update", "secure", "password", "bank"]
        score = 0.0
        score += 0.2 if "@" in url else 0.0
        score += 0.15 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) else 0.0
        score += 0.05 * sum(tok in url.lower() for tok in suspicious)
        score += 0.1 if len(url) > 70 else 0.0
        return min(score, 0.6)

    def _heuristic_risk(self, text: str, url: str) -> float:
        score = 0.1 + self._url_features(url)
        lower = text.lower()
        suspicious = ["verify", "password", "urgent", "account", "click", "confirm"]
        score += 0.08 * sum(tok in lower for tok in suspicious)
        score += 0.15 if "http://" in url.lower() else 0.0
        score += 0.1 if "://" not in url else 0.0
        return min(score, 0.98)

    def _predict_onnx(self, payload: str) -> float:
        if self.tokenizer is None or self.onnx_session is None:
            raise RuntimeError("ONNX path unavailable")
        inputs = self.tokenizer(payload, return_tensors="np", truncation=True, max_length=self.max_length)
        ort_inputs = {k: np.asarray(v, dtype=np.int64) for k, v in inputs.items() if k in self.onnx_input_names}
        if not ort_inputs:
            raise RuntimeError("Tokenizer outputs do not match ONNX input names")
        logits = np.asarray(self.onnx_session.run(None, ort_inputs)[0], dtype=np.float32)
        probs = self._softmax(logits)[0]
        return float(probs[1])

    def _predict_torch(self, payload: str) -> float:
        if self.tokenizer is None or self.model is None or torch is None:
            raise RuntimeError("Torch path unavailable")
        inputs = self.tokenizer(payload, return_tensors="pt", truncation=True, max_length=self.max_length)
        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0]
        return float(probs[1].item())

    def predict(self, text: str, url: str) -> InferenceResult:
        start = time.perf_counter()
        backend = "heuristic"
        payload = f"{text} [SEP] {url}"

        if self.force_heuristic:
            risk = self._heuristic_risk(text, url)
        else:
            try:
                if self.onnx_session is not None and self.tokenizer is not None:
                    risk = self._predict_onnx(payload)
                    backend = "onnx"
                elif self.model is not None and self.tokenizer is not None and torch is not None:
                    risk = self._predict_torch(payload)
                    backend = "torch"
                else:
                    risk = self._heuristic_risk(text, url)
                    backend = "heuristic"
            except Exception as exc:
                logger.warning("Model inference failed, using heuristic fallback: %s", exc)
                risk = self._heuristic_risk(text, url)
                backend = "heuristic"

        if backend in {"onnx", "torch"}:
            risk = min(1.0, risk + self._url_features(url))
        else:
            risk = min(1.0, risk)
        latency_ms = (time.perf_counter() - start) * 1000
        return InferenceResult(risk_score=risk, latency_ms=latency_ms, backend=backend)

    def predict_batch(self, samples: list[tuple[str, str]]) -> list[InferenceResult]:
        if not samples:
            return []
        start = time.perf_counter()

        if (
            not self.force_heuristic
            and self.onnx_session is not None
            and self.tokenizer is not None
            and len(samples) > 1
        ):
            payloads = [f"{text} [SEP] {url}" for text, url in samples]
            inputs = self.tokenizer(
                payloads,
                return_tensors="np",
                truncation=True,
                padding=True,
                max_length=self.max_length,
            )
            ort_inputs = {k: np.asarray(v, dtype=np.int64) for k, v in inputs.items() if k in self.onnx_input_names}
            logits = np.asarray(self.onnx_session.run(None, ort_inputs)[0], dtype=np.float32)
            probs = self._softmax(logits)
            latency_ms = (time.perf_counter() - start) * 1000
            results: list[InferenceResult] = []
            for idx, (_, url) in enumerate(samples):
                risk = min(1.0, float(probs[idx][1]) + self._url_features(url))
                results.append(InferenceResult(risk_score=risk, latency_ms=latency_ms / len(samples), backend="onnx"))
            return results

        return [self.predict(text=text, url=url) for text, url in samples]

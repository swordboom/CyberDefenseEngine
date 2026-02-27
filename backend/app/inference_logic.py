from .config import Settings
from .model import PhishingModel
from .privacy import to_risk_bucket
from .schemas import InferenceResponse


class InferenceManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model = PhishingModel(
            model_name=settings.model_name,
            onnx_path=settings.onnx_path,
            onnx_quantized_path=settings.onnx_quantized_path,
            max_length=settings.max_length,
            onnx_intra_op_threads=settings.onnx_intra_op_threads,
            onnx_inter_op_threads=settings.onnx_inter_op_threads,
            onnx_providers=settings.onnx_providers,
            force_heuristic=settings.force_heuristic,
            hf_token=settings.hf_token,
        )

    def analyze(self, *, text: str, url: str) -> InferenceResponse:
        result = self.model.predict(text=text, url=url)
        score = round(result.risk_score, 4)
        return InferenceResponse(
            risk_score=score,
            prediction="phishing" if score >= self.settings.risk_threshold else "benign",
            risk_bucket=to_risk_bucket(score),  # type: ignore[arg-type]
            inference_latency_ms=round(result.latency_ms, 3),
            model_backend=result.backend,  # type: ignore[arg-type]
        )

    def analyze_batch(self, *, items: list[tuple[str, str]]) -> list[InferenceResponse]:
        results = self.model.predict_batch(items)
        responses: list[InferenceResponse] = []
        for result in results:
            score = round(result.risk_score, 4)
            responses.append(
                InferenceResponse(
                    risk_score=score,
                    prediction="phishing" if score >= self.settings.risk_threshold else "benign",
                    risk_bucket=to_risk_bucket(score),  # type: ignore[arg-type]
                    inference_latency_ms=round(result.latency_ms, 3),
                    model_backend=result.backend,  # type: ignore[arg-type]
                )
            )
        return responses

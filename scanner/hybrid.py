"""Optional transformer fusion for the deterministic scanner."""

from dataclasses import replace
from typing import Optional

from scanner.risk_engine import RiskAssessment


_INFERENCE_CACHE = {}


def enrich_with_transformer(
    assessment: RiskAssessment,
    text: str,
    model_path: Optional[str] = None,
    gpu_id: Optional[int] = None,
) -> RiskAssessment:
    """Attach model evidence without making the scanner depend on ML artifacts.

    Importing the ML stack is deliberately lazy: the rules-only scanner remains
    usable in CI and on developer machines without PyTorch or Transformers.
    """
    try:
        from ml.config import InferenceConfig
        from ml.inference import SecretTransformerInference

        default_config = InferenceConfig()
        config = InferenceConfig(
            model_path=model_path or default_config.model_path,
            gpu_id=gpu_id,
        )
        cache_key = (config.model_path, config.gpu_id)
        inference = _INFERENCE_CACHE.get(cache_key)
        if inference is None:
            inference = SecretTransformerInference(config)
            _INFERENCE_CACHE[cache_key] = inference
        result = inference.predict_snippet(text)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        return replace(assessment, hybrid_decision=f"transformer_unavailable: {type(exc).__name__}")

    probability = float(result.get("probability", 0.0))
    confidence = float(result.get("confidence", 0.0))
    if not result.get("available", False):
        return replace(assessment, hybrid_decision="transformer_checkpoint_missing")

    decision = "rules_only"
    if assessment.risk_level in ("HIGH", "CRITICAL"):
        decision = "rules_confirmed"
    elif probability >= 0.65 and assessment.findings:
        decision = "transformer_confirmed"
    elif probability >= 0.85:
        decision = "transformer_only"
    elif probability < 0.35:
        decision = "transformer_rejected"
    else:
        decision = "inconclusive"

    return replace(
        assessment,
        transformer_available=True,
        transformer_probability=round(probability, 4),
        transformer_confidence=round(confidence, 4),
        hybrid_decision=decision,
    )
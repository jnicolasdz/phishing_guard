from dataclasses import dataclass

@dataclass(frozen=True)
class Decision:
    action: str
    reason: str

def decide(result: dict, *, auto_quarantine: bool, risk_high: float,
           risk_low: float, min_confidence: str) -> Decision:
    valid_labels = {"legitimate", "phishing", "suspicious"}
    if not isinstance(result, dict) or result.get("label") not in valid_labels:
        return Decision("review", "Clasificación ausente o inválida")
    try:
        risk = float(result["risk_score"])
        if not 0 <= risk <= 1: raise ValueError
    except (KeyError, TypeError, ValueError):
        return Decision("review", "Puntuación de riesgo inválida")
    if result.get("limitations"):
        return Decision("review", "El análisis declara limitaciones")
    confidence = result.get("confidence", "low")
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    if confidence not in confidence_rank or min_confidence not in confidence_rank:
        return Decision("review", "Nivel de confianza desconocido")
    if result["label"] == "legitimate" and risk <= risk_low and confidence_rank[confidence] >= confidence_rank[min_confidence]:
        return Decision("record_only", "Clasificación legítima de bajo riesgo")
    if result["label"] == "phishing" and risk >= risk_high and confidence_rank[confidence] >= confidence_rank[min_confidence]:
        if auto_quarantine:
            return Decision("quarantine", "Phishing de riesgo alto según política")
        return Decision("review", "Cuarentena automática deshabilitada")
    return Decision("review", "Resultado intermedio o señales contradictorias")

from typing import TypedDict, Any
from langgraph.graph import StateGraph, START, END
from .classifier import LocalClassifier, PROMPT_VERSION
from .policy import decide
from .repository import Repository

class GraphState(TypedDict, total=False):
    message_id: int
    payload: dict
    classification: dict
    decision: dict
    status: str
    error: str

class PhishingWorkflow:
    def __init__(self, repository: Repository, classifier: LocalClassifier, settings):
        self.repo, self.classifier, self.settings = repository, classifier, settings
        builder = StateGraph(GraphState)
        builder.add_node("load_message", self.load_message)
        builder.add_node("classify", self.classify)
        builder.add_node("apply_policy", self.apply_policy)
        builder.add_node("record_only", self.record_only)
        builder.add_node("quarantine", self.quarantine)
        builder.add_node("review", self.review)
        builder.add_node("fail", self.fail)
        builder.add_edge(START, "load_message")
        builder.add_conditional_edges("load_message", self.after_load,
                                      {"classify": "classify", "fail": "fail"})
        builder.add_conditional_edges("classify", self.after_classify,
                                      {"policy": "apply_policy", "fail": "fail"})
        builder.add_conditional_edges("apply_policy", self.after_policy,
                                      {"record_only": "record_only", "quarantine": "quarantine", "review": "review"})
        builder.add_edge("record_only", END)
        builder.add_edge("quarantine", END)
        builder.add_edge("review", END)
        builder.add_edge("fail", END)
        self.graph = builder.compile()

    def load_message(self, state: GraphState):
        item = self.repo.get_message(state["message_id"])
        if not item:
            return {"status": "FAILED", "error": "message_not_found"}
        return {"payload": item["payload"], "status": "ANALYZING"}

    def after_load(self, state: GraphState):
        return "classify" if state.get("payload") else "fail"

    def classify(self, state: GraphState):
        try:
            result = self.classifier.classify(state["payload"])
            # Pydantic/structured output is still validated at the boundary.
            from .classifier import Classification
            result = Classification.model_validate(result).model_dump()
            self.repo.save_classification(state["message_id"], result, self.classifier.model_id, PROMPT_VERSION)
            self.repo.set_status(state["message_id"], "CLASSIFIED", "classification_saved")
            return {"classification": result, "status": "CLASSIFIED"}
        except Exception as exc:
            self.repo.set_status(state["message_id"], "RETRY_PENDING", "classification_error",
                                 {"error_type": type(exc).__name__})
            return {"status": "RETRY_PENDING", "error": type(exc).__name__}

    def after_classify(self, state: GraphState):
        return "policy" if state.get("classification") else "fail"

    def apply_policy(self, state: GraphState):
        d = decide(state["classification"],
                   auto_quarantine=self.settings.auto_quarantine_enabled,
                   risk_high=self.settings.risk_high, risk_low=self.settings.risk_low,
                   min_confidence=self.settings.min_confidence)
        self.repo.set_status(state["message_id"],
                             "ACTION_PENDING" if d.action in {"quarantine", "record_only"} else "PENDING_REVIEW",
                             "policy_decision", {"action": d.action, "reason": d.reason})
        return {"decision": {"action": d.action, "reason": d.reason}}

    def after_policy(self, state: GraphState):
        return state["decision"]["action"]

    def record_only(self, state: GraphState):
        self.repo.set_status(state["message_id"], "COMPLETED", "no_action_required",
                             {"reason": state["decision"]["reason"]})
        return {"status": "COMPLETED"}

    def quarantine(self, state: GraphState):
        # The actual IMAP move is intentionally not performed in the graph without
        # a verified source UID and an explicitly supplied IMAP action adapter.
        # This node records a request for the separate, idempotent action worker.
        mid = state["message_id"]
        key = f"quarantine:{mid}"
        self.repo.create_action(mid, key, "imap_quarantine")
        self.repo.set_status(mid, "ACTION_PENDING", "quarantine_requested",
                             {"action_key": key, "reason": state["decision"]["reason"]})
        return {"status": "ACTION_PENDING"}

    def review(self, state: GraphState):
        self.repo.set_status(state["message_id"], "PENDING_REVIEW", "review_required",
                             {"reason": state["decision"]["reason"]})
        return {"status": "PENDING_REVIEW"}

    def fail(self, state: GraphState):
        status = state.get("status", "FAILED")
        if status not in {"RETRY_PENDING", "FAILED"}: status = "FAILED"
        if state.get("message_id"):
            self.repo.set_status(state["message_id"], status, "workflow_failed",
                                 {"error": state.get("error", "unknown")})
        return {"status": status}

    def run(self, message_id: int) -> dict[str, Any]:
        return self.graph.invoke({"message_id": message_id})

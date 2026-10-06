import sys, time, json, hashlib, logging, os
from collections import Counter

# ===== CONFIGURE REPMHL PERSISTENT LOGGING =====
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "REPMHL.log"),
    format='%(asctime)s %(message)s',
    level=logging.INFO
)

# ===== MODEL REGISTRY =====
MODEL_REGISTRY = {
    "SuperGrok-4.7": {"provider": "xai", "policy": "strict daily use"},
    "SuperGrok-4.6": {"provider": "xai", "policy": "fallback"},
    "gpt-5.6-Luna-Terra-Sol": {"provider": "openai", "policy": "strict"},
    "gpt-5.7-Codex-Cyber": {"provider": "openai", "policy": "security code"},
    "Claude-Fable-5.1": {"provider": "anthropic", "policy": "review"},
    "Claude-Mythos-5.1": {"provider": "anthropic", "policy": "medical"},
    "Claude-Sonnet-5": {"provider": "anthropic", "policy": "daily use"},
    "GitHub Copilot": {"provider": "GitHub", "policy": "strict per session"},
    "DevAssist420+SovAI": {"provider": "internal", "policy": "daily router"}
}

# ===== ROUTING LOGIC =====
ROUTING = {
    "defaults": {
        "primary_model": "SuperGrok-4.7",
        "use_judge": True
    },
    "heavy_judge": {
        "enabled": True,
        "role": "final_quality_gate",
        "trigger_strategy": {
            "always_for": ["medical", "education"],
            "general_sampling_rate": 0.1
        }
    },
    "yank_behavior": {
        "low_risk": "rewrite_safer",
        "medium_risk": "replace_with_safe_generic",
        "high_critical_risk": "polite_refusal"
    },
    "model_selection": {
        "low_risk": ["SuperGrok-4.7"],
        "medium_risk": ["SuperGrok-4.7", "gpt-5.7-Codex-Cyber"],
        "high_risk": ["Claude-Fable-5.1", "Claude-Mythos-5.1", "gpt-5.6-Luna-Terra-Sol"]
    }
}

# ===== HEAVY JUDGE =====
class HeavyJudge:
    def __init__(self, model_name="SuperGrok-5.7-hybrid"):
        self.model = model_name
        self.strictness = {"medical": 0.95, "education": 0.90, "general": 0.75}

    def review(self, original_output: str, context: str, risk_score: float = 0.0) -> dict:
        verdict = self._generate_verdict(original_output, context, risk_score)
        final_output = original_output
        if verdict["action"] in ["yank", "rewrite"]:
            final_output = self._safe_replacement(original_output, context)
        self._log_to_REPMHL(verdict)
        return {"final_output": final_output, "verdict": verdict, "judge_model": self.model}

    def _generate_verdict(self, text, context, risk_score=0.0):
        keywords = {"medical": 50, "legal": 45, "safety": 50, "financial": 25}
        t = text.lower()
        score = sum(w for k, w in keywords.items() if k in t)
        score += self.strictness.get(context.lower(), 0.75) * 10
        score = min(score, 100)
        action = "yank" if score >= 75 else ("rewrite" if score >= 40 else "pass")
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "risk_score": score/100,
            "action": action,
            "hash": hashlib.sha3_512(text.encode()).hexdigest(),
            "context": context
        }

    def _safe_replacement(self, original_output: str, context: str) -> str:
        return f"[Content replaced for {context} safety]"

    def _log_to_REPMHL(self, verdict: dict):
        logging.info(json.dumps(verdict))

# ===== MULTI-MODEL COUNCIL VOTING =====
def multi_model_council(user_request: str, models: list) -> str:
    outputs = [f"[{m}] {user_request}" for m in models]
    votes = Counter(outputs)
    consensus = votes.most_common(1)[0][0]
    return consensus

# ===== DYNAMIC CONTEXT DETECTION =====
def detect_context(user_request: str) -> str:
    keywords = {
        "medical": ["surgery", "dosage", "medicine"],
        "finance": ["stocks", "finance", "loan"],
        "legal": ["law", "contract", "court"]
    }
    for context, words in keywords.items():
        if any(w in user_request.lower() for w in words):
            return context
    return "general"

# ===== USER LEARNING STATEFUL & STATELESS DISPLAY =====
def display_user_learning(output: str, stateful_data: dict = None):
    print("=== Stateful Display ===")
    if stateful_data:
        for k, v in stateful_data.items():
            print(f"{k}: {v}")
    else:
        print("No prior history (stateless mode)")
    print("\n=== Output ===")
    print(output)
    print("\n<button>Accept</button> <button>Decline</button> <button>Discuss</button>")

# ===== REQUEST ROUTER =====
def route_request(user_request: str):
    context = detect_context(user_request)
    risk = "high" if context in ["medical", "legal", "finance"] else "low"
    council_models = ROUTING["model_selection"].get(f"{risk}_risk", [ROUTING["defaults"]["primary_model"]])
    council_vote_output = multi_model_council(user_request, council_models)
    if ROUTING["defaults"]["use_judge"]:
        judge = HeavyJudge()
        result = judge.review(council_vote_output, context)
        return result["final_output"], result["verdict"]
    else:
        return council_vote_output, {"action": "pass"}

# ===== MAIN EXECUTION =====
if __name__ == "__main__":
    user_req = sys.argv[1] if len(sys.argv) > 1 else "Check medical dosage"
    output, verdict = route_request(user_req)
    user_history = {"last_action": verdict["action"], "risk_score": verdict.get("risk_score")}
    display_user_learning(output, stateful_data=user_history)

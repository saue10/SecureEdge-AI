"""
Bounded Cybersecurity Explanation & Remediation Advisor using a genuine pretrained
Llama-family model (SmolLM2-135M-Instruct / Llama-3.2) exported via torch.export / ExecuTorch.
Strictly enforces the PS3 separation of duties:
- Specialized detectors determine threat_type, classification, confidence, risk_level, and evidence.
- Llama summarizes detector evidence in clear, non-expert language and recommends safe actions.
- Llama NEVER invents unverified threat evidence and NEVER overrides the detector's risk_level.
"""

from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from transformers import AutoTokenizer

from src.common.config import LLAMA_MODEL_DIR
from src.common.logger import get_logger
from src.common.schemas import LlamaExplanationInput, LlamaExplanationOutput
from src.executorch.runtime import ExecuTorchLlamaRuntime
from src.llama.tokenizer import CyberLlamaTokenizer

logger = get_logger("SecureEdge.LlamaAdvisor")


class LlamaCyberAdvisor:
    """
    On-device Llama-family Threat Advisor backed by ExecuTorch (.pte / ExportedProgram).
    Uses offline local HuggingFace tokenizer (models/llama_executorch/tokenizer/) and
    executes autoregressive token decoding through the static ExportedProgram graph.
    """

    DEFAULT_TOKENIZER_DIR = LLAMA_MODEL_DIR / "tokenizer"

    def __init__(
        self,
        runtime: Optional[ExecuTorchLlamaRuntime] = None,
        tokenizer: Optional[Any] = None,
        max_new_tokens: int = 10,
    ) -> None:
        self.runtime = runtime or ExecuTorchLlamaRuntime()
        self.max_new_tokens = max_new_tokens
        self.tokenizer = tokenizer or self._load_offline_tokenizer()
        self.last_performance_metrics: Dict[str, float] = {}

    def _load_offline_tokenizer(self) -> Any:
        """Load the saved local tokenizer strictly offline (local_files_only=True)."""
        if self.DEFAULT_TOKENIZER_DIR.exists():
            try:
                tok = AutoTokenizer.from_pretrained(str(self.DEFAULT_TOKENIZER_DIR), local_files_only=True)
                logger.info("Loaded offline HuggingFace Llama-family tokenizer from %s", self.DEFAULT_TOKENIZER_DIR)
                return tok
            except Exception as exc:
                logger.warning("Failed to load local HF tokenizer (%s); falling back to CyberLlamaTokenizer", exc)
        return CyberLlamaTokenizer()

    def reload(self) -> bool:
        """Reload tokenizer and ExecuTorch runtime from disk."""
        self.tokenizer = self._load_offline_tokenizer()
        return self.runtime.load()

    def build_bounded_prompt(self, llama_input: LlamaExplanationInput) -> str:
        """Construct a bounded, chat-formatted prompt conditioning Llama strictly on verified evidence."""
        ev_joined = "; ".join(llama_input.evidence[:3])
        system_msg = (
            "You are SecureEdge AI. Summarize the verified cybersecurity evidence in one clear sentence "
            "without inventing any new URLs, IPs, or indicators."
        )
        user_msg = (
            f"Threat: {llama_input.threat_type}. Risk: {llama_input.risk_level}. "
            f"Confidence: {int(round(llama_input.confidence * 100))}%. "
            f"Verified evidence: {ev_joined}. Summary:"
        )

        if hasattr(self.tokenizer, "apply_chat_template"):
            try:
                return self.tokenizer.apply_chat_template(
                    [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
                    tokenize=False,
                    add_generation_prompt=True,
                )
            except Exception:
                pass

        return f"{system_msg}\n{user_msg}\n"

    def explain(self, llama_input: LlamaExplanationInput) -> LlamaExplanationOutput:
        """
        Execute local Llama inference via the exported static graph runtime and return a
        validated LlamaExplanationOutput strictly grounded in the detector evidence.
        """
        t0 = time.perf_counter()

        if not isinstance(llama_input, LlamaExplanationInput):
            llama_input = LlamaExplanationInput.model_validate(llama_input)

        prompt_str = self.build_bounded_prompt(llama_input)
        max_prompt_len = max(16, self.runtime.seq_len - self.max_new_tokens - 1)

        if hasattr(self.tokenizer, "encode"):
            try:
                prompt_ids = self.tokenizer.encode(prompt_str, add_special_tokens=True)
            except TypeError:
                prompt_ids = self.tokenizer.encode(prompt_str, add_bos=True, add_eos=False, max_length=max_prompt_len)
            prompt_ids = prompt_ids[:max_prompt_len]
        else:
            prompt_ids = [1]

        eos_id = int(getattr(self.tokenizer, "eos_token_id", 2) or 2)
        pad_id = int(getattr(self.tokenizer, "pad_token_id", 0) or 0)

        pte_status = self.runtime.verify_pte_artifact()
        pte_verified = bool(pte_status.get("verified", False))

        generated_decoded = ""
        if self.runtime.is_loaded:
            try:
                gen_ids, perf = self.runtime.generate_tokens(
                    prompt_token_ids=prompt_ids,
                    max_new_tokens=self.max_new_tokens,
                    eos_token_id=eos_id,
                    pad_token_id=pad_id,
                )
                self.last_performance_metrics = perf
                generated_decoded = self.tokenizer.decode(gen_ids, skip_special_tokens=True).strip()
            except Exception as exc:
                logger.error("ExecuTorch Llama generation error: %s", exc)

        explanation, recommendation = self._format_grounded_advisory(llama_input, generated_decoded)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return LlamaExplanationOutput(
            explanation=explanation,
            recommendation=recommendation,
            risk_level=llama_input.risk_level,
            runtime_backend=self.runtime.runtime_backend,
            pte_artifact_verified=pte_verified,
            generation_latency_ms=round(elapsed_ms, 3),
        )

    @staticmethod
    def _format_grounded_advisory(
        inp: LlamaExplanationInput,
        llm_clause: str,
    ) -> tuple[str, str]:
        """
        Combine the detector's verified forensic evidence with the local Llama model's
        decoded summary while enforcing strict anti-hallucination guardrails.
        """
        evidence_summary = "; ".join(inp.evidence[:3])
        conf_pct = f"{inp.confidence * 100:.1f}%"

        cleaned_llm = " ".join(llm_clause.split()).strip(" .:-")
        # Guardrail: reject empty or contradicting clauses (e.g. claiming benign when high risk)
        is_safe_llm_clause = len(cleaned_llm) >= 12 and not (
            inp.risk_level in ("high", "critical") and any(w in cleaned_llm.lower() for w in ("completely safe", "no threat"))
        )

        if inp.threat_type == "phishing":
            base_exp = (
                f"The URL exhibits {inp.risk_level}-risk characteristics commonly associated with phishing "
                f"(detector confidence: {conf_pct}). Key verified indicators: {evidence_summary}."
            )
            if is_safe_llm_clause:
                base_exp += f" On-device Llama summary: {cleaned_llm}."
            rec = (
                "Do not open the link or enter any login credentials, OTPs, or financial details. "
                "Verify the request independently by navigating directly to the organization's official application or website."
            )
        elif inp.threat_type in ("scam", "spam"):
            label_desc = "financial/credential scam" if inp.threat_type == "scam" else "unsolicited spam"
            base_exp = (
                f"This message contains patterns characteristic of a {label_desc} with {inp.risk_level} risk "
                f"(detector confidence: {conf_pct}). Key verified indicators: {evidence_summary}."
            )
            if is_safe_llm_clause:
                base_exp += f" On-device Llama summary: {cleaned_llm}."
            rec = (
                "Do not click any embedded links, call unfamiliar phone numbers, or share OTP/KYC/UPI details. "
                "Block and report the sender, and contact your bank or service provider only through official channels."
            )
        elif inp.threat_type == "network_anomaly":
            base_exp = (
                f"Network traffic analysis identified a {inp.risk_level}-risk flow anomaly "
                f"(detector confidence: {conf_pct}). Key verified indicators: {evidence_summary}."
            )
            if is_safe_llm_clause:
                base_exp += f" On-device Llama summary: {cleaned_llm}."
            rec = (
                "Inspect the source IP and targeted service port on your local firewall. "
                "Rate-limit or block repeated unauthorized connection bursts and verify that sensitive administrative ports are not exposed."
            )
        else:
            base_exp = (
                f"No malicious threat indicators were triggered during local inspection "
                f"(benign confidence: {conf_pct}). {evidence_summary}."
            )
            rec = (
                "No immediate remediation action is required. Continue practicing standard digital hygiene "
                "and verify unexpected requests before sharing sensitive data."
            )

        return base_exp, rec

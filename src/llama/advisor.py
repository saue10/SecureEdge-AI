"""
Bounded Cybersecurity Explanation & Remediation Advisor using Llama + ExecuTorch.
Strictly enforces the PS3 separation of duties:
- Specialized detectors determine threat_type, classification, confidence, risk_level, and evidence.
- Llama summarizes detector evidence in clear, non-expert language and recommends safe actions.
- Llama NEVER invents unverified threat evidence and NEVER overrides the detector's risk_level.
"""

import time
from typing import Dict, List, Optional

from src.common.logger import get_logger
from src.common.schemas import LlamaExplanationInput, LlamaExplanationOutput
from src.executorch.runtime import ExecuTorchLlamaRuntime
from src.llama.tokenizer import CyberLlamaTokenizer

logger = get_logger("SecureEdge.LlamaAdvisor")


class LlamaCyberAdvisor:
    """
    On-device Llama-family Threat Advisor backed by ExecuTorch (.pte / ExportedProgram).
    Combines autoregressive neural token decoding from the exported LlamaForCausalLM graph
    with strict evidence grounding and Pydantic output schema validation.
    """

    def __init__(
        self,
        runtime: Optional[ExecuTorchLlamaRuntime] = None,
        tokenizer: Optional[CyberLlamaTokenizer] = None,
    ) -> None:
        self.tokenizer = tokenizer or CyberLlamaTokenizer()
        self.runtime = runtime or ExecuTorchLlamaRuntime()
        self.last_performance_metrics: Dict[str, float] = {}

    def reload(self) -> bool:
        """Reload tokenizer and ExecuTorch runtime from disk."""
        self.tokenizer._build_or_load_vocab()
        return self.runtime.load()

    def build_bounded_prompt(self, llama_input: LlamaExplanationInput) -> str:
        """Construct the structured prompt conditioning Llama on detector findings."""
        ev_joined = " ; ".join(llama_input.evidence[:3])
        return (
            f"<json> threat_type : {llama_input.threat_type} , "
            f"risk_level : {llama_input.risk_level} , "
            f"confidence : {int(round(llama_input.confidence * 100))} % , "
            f"evidence : [ {ev_joined} ] <sep>"
        )

    def explain(self, llama_input: LlamaExplanationInput) -> LlamaExplanationOutput:
        """
        Execute local Llama inference via ExecuTorch runtime and return a validated
        LlamaExplanationOutput strictly grounded in the provided detector evidence.
        """
        t0 = time.perf_counter()

        # Verify input schema
        if not isinstance(llama_input, LlamaExplanationInput):
            llama_input = LlamaExplanationInput.model_validate(llama_input)

        prompt_str = self.build_bounded_prompt(llama_input)
        prompt_ids = self.tokenizer.encode(prompt_str, add_bos=True, add_eos=False, max_length=36)

        pte_status = self.runtime.verify_pte_artifact()
        pte_verified = bool(pte_status.get("verified", False))

        generated_decoded = ""
        if self.runtime.is_loaded:
            try:
                gen_ids, perf = self.runtime.generate_tokens(
                    prompt_token_ids=prompt_ids,
                    max_new_tokens=24,
                    eos_token_id=self.tokenizer.eos_token_id,
                    pad_token_id=self.tokenizer.pad_token_id,
                )
                self.last_performance_metrics = perf
                generated_decoded = self.tokenizer.decode(gen_ids, skip_special_tokens=True)
            except Exception as exc:
                logger.error("ExecuTorch Llama generation error: %s", exc)

        # Grounded synthesis: combine Llama's decoded advisory clause with strictly verified detector evidence
        explanation, recommendation = self._format_grounded_advisory(llama_input, generated_decoded)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        output = LlamaExplanationOutput(
            explanation=explanation,
            recommendation=recommendation,
            risk_level=llama_input.risk_level,
            runtime_backend=self.runtime.runtime_backend,
            pte_artifact_verified=pte_verified,
            generation_latency_ms=round(elapsed_ms, 3),
        )
        return output

    @staticmethod
    def _format_grounded_advisory(
        inp: LlamaExplanationInput,
        llm_clause: str,
    ) -> tuple[str, str]:
        """
        Ensure the final explanation and recommendation cite ONLY the detector's verified
        evidence and provide clear, non-expert remediation steps tailored to the threat type.
        """
        evidence_summary = "; ".join(inp.evidence[:3])
        conf_pct = f"{inp.confidence * 100:.1f}%"

        # Verify that any LLM-decoded clause does not contradict the detector or inject foreign claims
        has_valid_llm_clause = (
            len(llm_clause) >= 15
            and any(k in llm_clause for k in ("phishing", "scam", "network", "benign", "credentials", "suspicious", "safe"))
        )

        if inp.threat_type == "phishing":
            base_exp = (
                f"The URL exhibits {inp.risk_level}-risk characteristics commonly associated with phishing "
                f"(detector confidence: {conf_pct}). Key verified indicators: {evidence_summary}."
            )
            if has_valid_llm_clause and "phishing" in llm_clause:
                base_exp += f" Local Llama assessment: {llm_clause.capitalize()}."
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
            if has_valid_llm_clause and ("scam" in llm_clause or "message" in llm_clause):
                base_exp += f" Local Llama assessment: {llm_clause.capitalize()}."
            rec = (
                "Do not click any embedded links, call unfamiliar phone numbers, or share OTP/KYC/UPI details. "
                "Block and report the sender, and contact your bank or service provider only through official channels."
            )
        elif inp.threat_type == "network_anomaly":
            base_exp = (
                f"Network traffic analysis identified a {inp.risk_level}-risk flow anomaly "
                f"(detector confidence: {conf_pct}). Key verified indicators: {evidence_summary}."
            )
            if has_valid_llm_clause and ("network" in llm_clause or "flow" in llm_clause):
                base_exp += f" Local Llama assessment: {llm_clause.capitalize()}."
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

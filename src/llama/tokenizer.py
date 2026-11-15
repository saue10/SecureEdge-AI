"""Deterministic tokenizer for on-device Llama cybersecurity advisory generation."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from src.common.config import LLAMA_MODEL_DIR


SPECIAL_TOKENS = [
    "<pad>",   # 0
    "<bos>",   # 1
    "<eos>",   # 2
    "<unk>",   # 3
    "<sep>",   # 4
    "<json>",  # 5
    "</json>", # 6
]

CORE_CYBER_VOCAB = [
    # Structural & JSON tokens
    "{", "}", ":", ",", "[", "]", "\"", "threat_type", "risk_level", "confidence",
    "evidence", "explanation", "recommendation",
    # Threat types & severities
    "phishing", "scam", "spam", "network_anomaly", "benign",
    "low", "medium", "high", "critical", "malicious", "suspicious",
    # URL indicators
    "url", "link", "domain", "hostname", "ip", "address", "subdomain", "tld",
    "punycode", "homograph", "shortener", "http", "https", "tls", "encrypted",
    "unencrypted", "hyphen", "hyphens", "port", "executable", "payload",
    "impersonation", "brand", "credential", "login", "verify", "password",
    "redirect", "obfuscation", "lexical", "structure", "characters", "registered",
    # SMS indicators
    "sms", "message", "text", "urgency", "coercion", "financial", "kyc", "upi",
    "otp", "bank", "account", "suspended", "blocked", "lottery", "prize",
    "winner", "reward", "cashback", "callback", "phone", "number", "currency",
    "solicitation", "promotional", "transactional", "share", "never",
    # Network indicators
    "network", "flow", "packet", "packets", "bytes", "tcp", "udp", "icmp",
    "syn", "flood", "dos", "scan", "probing", "ssh", "rdp", "smb", "telnet",
    "brute", "force", "rst", "rejection", "c2", "backdoor", "exfiltration",
    "throughput", "burst", "destination", "source", "service", "admin",
    # Explanation & Remediation vocabulary
    "the", "this", "contains", "exhibits", "indicates", "detected", "associated",
    "with", "commonly", "used", "in", "attacks", "campaigns", "to", "deceive",
    "users", "into", "revealing", "sensitive", "credentials", "or", "authorizing",
    "fraudulent", "transactions", "do", "not", "open", "click", "enter",
    "call", "reply", "delete", "block", "sender", "immediately", "using",
    "official", "application", "website", "contact", "institution", "directly",
    "isolate", "host", "inspect", "firewall", "rules", "rate", "limit",
    "connection", "attempts", "no", "anomalous", "indicators", "were", "found",
    "safe", "standard", "proceed", "normal", "caution", "verified", "on", "device",
    "by", "specialized", "detector", "and", "analyzed", "locally", "via",
    "executorch", "arm", "edge", "runtime", ".", ";", "-", "(", ")", "/", "%",
]


class CyberLlamaTokenizer:
    """
    Lightweight, zero-network-dependency word/subword tokenizer for the on-device
    LlamaForCausalLM cybersecurity advisor. Maps structured threat JSON prompts and
    remediation outputs into compact integer token IDs in [0, vocab_size - 1].
    """

    DEFAULT_VOCAB_PATH = LLAMA_MODEL_DIR / "tokenizer_vocab.json"
    VOCAB_SIZE = 512

    def __init__(self, vocab_path: Optional[Path] = None) -> None:
        self.vocab_path = Path(vocab_path) if vocab_path else self.DEFAULT_VOCAB_PATH
        self.token_to_id: Dict[str, int] = {}
        self.id_to_token: Dict[int, str] = {}
        self._build_or_load_vocab()

    def _build_or_load_vocab(self) -> None:
        if self.vocab_path.exists():
            try:
                data = json.loads(self.vocab_path.read_text(encoding="utf-8"))
                self.token_to_id = {k: int(v) for k, v in data["token_to_id"].items()}
                self.id_to_token = {int(v): k for k, v in self.token_to_id.items()}
                return
            except Exception:
                pass

        tokens = list(SPECIAL_TOKENS)
        for word in CORE_CYBER_VOCAB:
            if word not in tokens:
                tokens.append(word)

        # Pad vocabulary up to exact VOCAB_SIZE (512) with numbered subword slots
        idx = 0
        while len(tokens) < self.VOCAB_SIZE:
            candidate = f"<tok_{idx}>"
            if candidate not in tokens:
                tokens.append(candidate)
            idx += 1

        tokens = tokens[: self.VOCAB_SIZE]
        self.token_to_id = {tok: i for i, tok in enumerate(tokens)}
        self.id_to_token = {i: tok for i, tok in enumerate(tokens)}

    def save(self, path: Optional[Path] = None) -> Path:
        target = Path(path) if path else self.vocab_path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "vocab_size": self.VOCAB_SIZE,
            "pad_token_id": self.pad_token_id,
            "bos_token_id": self.bos_token_id,
            "eos_token_id": self.eos_token_id,
            "unk_token_id": self.unk_token_id,
            "token_to_id": self.token_to_id,
        }
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target

    @property
    def pad_token_id(self) -> int:
        return 0

    @property
    def bos_token_id(self) -> int:
        return 1

    @property
    def eos_token_id(self) -> int:
        return 2

    @property
    def unk_token_id(self) -> int:
        return 3

    def encode(self, text: str, add_bos: bool = True, add_eos: bool = False, max_length: int = 40) -> List[int]:
        """Convert input string into token IDs."""
        raw_tokens = re.findall(r"<[a-z_/]+>|[a-z0-9_]+|[{}:\"\[\],.;()-/%]", text.lower())
        ids: List[int] = []
        if add_bos:
            ids.append(self.bos_token_id)
        for tok in raw_tokens:
            ids.append(self.token_to_id.get(tok, self.unk_token_id))
            if len(ids) >= max_length - (1 if add_eos else 0):
                break
        if add_eos:
            ids.append(self.eos_token_id)
        return ids

    def decode(self, token_ids: List[int], skip_special_tokens: bool = True) -> str:
        """Convert token IDs back into readable text."""
        special_ids = {0, 1, 2, 3, 4, 5, 6} if skip_special_tokens else set()
        words: List[str] = []
        for tid in token_ids:
            if tid in special_ids:
                continue
            tok = self.id_to_token.get(int(tid), "")
            if tok and not tok.startswith("<tok_"):
                words.append(tok)
        text = " ".join(words)
        text = re.sub(r"\s+([.,;:)%\]}])", r"\1", text)
        return text.strip()

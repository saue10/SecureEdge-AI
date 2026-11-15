"""Flow-based feature extraction for Network Anomaly and Intrusion Detection."""

import math
from typing import Any, Dict, List, Tuple
import numpy as np


FLOW_FEATURE_NAMES: List[str] = [
    "flow_duration_sec",
    "protocol_id",           # 6=TCP, 17=UDP, 1=ICMP, 0=Other
    "dst_port",
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_packet_size",
    "syn_flag_ratio",
    "rst_flag_ratio",
    "ack_flag_ratio",
    "fin_flag_ratio",
    "unique_dst_ports_window",
    "connection_frequency",
    "payload_byte_ratio",
    "is_sensitive_admin_port",
]

SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit-Default",
    5555: "ADB-Debug",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9001: "Tor-ORPort",
}


class NetworkFlowFeatureExtractor:
    """Extracts standardized 16-dimensional flow features and forensic evidence from flow records."""

    feature_names: List[str] = FLOW_FEATURE_NAMES

    @classmethod
    def extract_features_and_evidence(cls, flow: Dict[str, Any]) -> Tuple[Dict[str, float], List[str], str]:
        """
        Convert a raw flow dictionary (from Scapy packet aggregation or dataset record)
        into 16 numeric features, human-readable forensic evidence, and specific attack subtype hint.
        """
        duration = max(0.001, float(flow.get("flow_duration_sec", 0.1)))
        proto_raw = flow.get("protocol", flow.get("protocol_id", 6))
        if isinstance(proto_raw, str):
            proto_map = {"tcp": 6.0, "udp": 17.0, "icmp": 1.0}
            protocol_id = proto_map.get(proto_raw.lower(), 0.0)
        else:
            protocol_id = float(proto_raw)

        dst_port = float(flow.get("dst_port", 80))
        packet_count = max(1.0, float(flow.get("packet_count", 1)))
        byte_count = max(0.0, float(flow.get("byte_count", packet_count * 64)))

        pps = float(flow.get("packets_per_sec", packet_count / duration))
        bps = float(flow.get("bytes_per_sec", byte_count / duration))
        mean_pkt_size = byte_count / max(packet_count, 1.0)

        syn_ratio = float(flow.get("syn_flag_ratio", 0.0))
        rst_ratio = float(flow.get("rst_flag_ratio", 0.0))
        ack_ratio = float(flow.get("ack_flag_ratio", 0.8 if protocol_id == 6.0 else 0.0))
        fin_ratio = float(flow.get("fin_flag_ratio", 0.1 if protocol_id == 6.0 else 0.0))

        unique_ports = max(1.0, float(flow.get("unique_dst_ports_window", 1)))
        conn_freq = max(1.0, float(flow.get("connection_frequency", 1)))
        payload_ratio = float(flow.get("payload_byte_ratio", 0.5))
        port_int = int(dst_port)
        is_sensitive_port = 1.0 if port_int in SENSITIVE_PORTS else 0.0

        features: Dict[str, float] = {
            "flow_duration_sec": round(duration, 4),
            "protocol_id": protocol_id,
            "dst_port": dst_port,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "mean_packet_size": round(mean_pkt_size, 2),
            "syn_flag_ratio": round(syn_ratio, 4),
            "rst_flag_ratio": round(rst_ratio, 4),
            "ack_flag_ratio": round(ack_ratio, 4),
            "fin_flag_ratio": round(fin_ratio, 4),
            "unique_dst_ports_window": unique_ports,
            "connection_frequency": conn_freq,
            "payload_byte_ratio": round(payload_ratio, 4),
            "is_sensitive_admin_port": is_sensitive_port,
        }

        evidence: List[str] = []
        subtype = "benign"

        if unique_ports >= 15:
            evidence.append(
                f"Port-scan signature: single source probed {int(unique_ports)} distinct destination ports in window"
            )
            subtype = "port_scan"

        if syn_ratio >= 0.70 and ack_ratio <= 0.20 and pps >= 80:
            evidence.append(
                f"SYN flood / DoS anomaly: high SYN ratio ({syn_ratio:.0%}) with {pps:.0f} packets/sec and unacknowledged handshakes"
            )
            subtype = "syn_flood_dos"

        if is_sensitive_port > 0 and conn_freq >= 12:
            svc_name = SENSITIVE_PORTS.get(port_int, f"Port-{port_int}")
            evidence.append(
                f"Repeated connection bursts ({int(conn_freq)} attempts) targeting sensitive service port {port_int} ({svc_name})"
            )
            if subtype == "benign":
                subtype = "brute_force_probe"

        if rst_ratio >= 0.50 and packet_count >= 10:
            evidence.append(f"High TCP RST rejection rate ({rst_ratio:.0%}) indicating rejected service probes")
            if subtype == "benign":
                subtype = "rejected_probe"

        if bps >= 500_000 and payload_ratio >= 0.85 and port_int not in (80, 443):
            evidence.append(
                f"High-throughput outbound/inbound data transfer ({bps / 1024:.1f} KB/s) on non-web port {port_int}"
            )
            if subtype == "benign":
                subtype = "data_exfiltration_anomaly"

        if port_int in (4444, 5555, 6667, 31337):
            evidence.append(
                f"Traffic directed to known C2 / remote shell / debug port {port_int} ({SENSITIVE_PORTS.get(port_int, 'Suspicious-Port')})"
            )
            subtype = "c2_backdoor_channel"

        if not evidence:
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(protocol_id), "IP")
            evidence.append(
                f"Normal {proto_name} flow to port {port_int} ({int(packet_count)} pkts, {mean_pkt_size:.0f}B avg size, {duration:.2f}s duration)"
            )

        return features, evidence, subtype

    @classmethod
    def transform_single(cls, flow: Dict[str, Any]) -> np.ndarray:
        """Convert single flow dict to 1D numpy vector of shape (16,)."""
        feats, _, _ = cls.extract_features_and_evidence(flow)
        return np.array([feats[k] for k in FLOW_FEATURE_NAMES], dtype=np.float64)

    @classmethod
    def transform_batch(cls, flows: List[Dict[str, Any]]) -> np.ndarray:
        """Convert list of flow dicts to 2D numpy matrix of shape (N, 16)."""
        return np.vstack([cls.transform_single(f) for f in flows])

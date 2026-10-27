"""
MITRE ATT&CK Framework Mapping and Active Defense Playbook Engine
================================================================
Provides cyber threat intelligence enrichment, MITRE tactic & technique mapping,
and automated containment playbooks for autonomous SOC defense.
"""

from datetime import datetime
from typing import Dict, List, Optional


MITRE_TACTICS_MAP = {
    "DoS / SYN Flood": {
        "tactic": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "severity": "HIGH",
        "description": "Adversary generates excessive traffic volume to exhaust network bandwidth or service state table capacity.",
        "recommended_action": "Execute automated iptables DROP rule on offending source IP and engage SYN proxy filtering.",
        "firewall_rule": "iptables -A INPUT -s {src_ip} -p tcp --syn -j DROP",
    },
    "Probe / Stealth Port Scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "severity": "MEDIUM",
        "description": "Adversary enumerates open network ports and running services to identify exploitable attack surfaces.",
        "recommended_action": "Quarantine source IP from perimeter routing and apply rate-limiting across ingress gateways.",
        "firewall_rule": "iptables -I INPUT 1 -s {src_ip} -j REJECT --reject-with icmp-port-unreachable",
    },
    "R2L / SSH Brute Force": {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "severity": "HIGH",
        "description": "Adversary attempts repeated authentication requests against remote management services.",
        "recommended_action": "Block offending source IP on port 22, terminate existing sessions, and enforce MFA challenge.",
        "firewall_rule": "iptables -A INPUT -s {src_ip} -p tcp --dport 22 -j DROP",
    },
    "U2R / Privilege Escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Adversary exploits software vulnerability or buffer overflow to elevate local permissions to root/SYSTEM.",
        "recommended_action": "Immediately isolate compromised host from network segment and capture process memory dump.",
        "firewall_rule": "iptables -A FORWARD -s {src_ip} -j DROP",
    },
    "Data Exfiltration / C2": {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "severity": "CRITICAL",
        "description": "Adversary steals sensitive organization data by tunneling traffic over unauthorized outbound channels.",
        "recommended_action": "Sever outbound C2 beacon socket, block destination egress, and quarantine source workstation.",
        "firewall_rule": "iptables -A OUTPUT -d {dst_ip} -j DROP",
    },
    "Zero-Day / Distributed Attack": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "severity": "HIGH",
        "description": "Novel behavioral traffic deviation detected matching unknown zero-day or evasion exploit pattern.",
        "recommended_action": "Engage Agentic AI drift recovery, retrain neural models on drifted cluster, and throttle untrusted subnet.",
        "firewall_rule": "iptables -A INPUT -s {src_ip} -m limit --limit 5/sec -j ACCEPT",
    },
}


class ActiveDefenseManager:
    """
    Manages active defense containment rules, firewall blocklists, and MITRE enrichment.
    """

    def __init__(self):
        self.blocked_ips: Dict[str, dict] = {}
        self.containment_history: List[dict] = []

    def enrich_threat(self, attack_type: str, src_ip: str, dst_ip: str, packet_id: int) -> dict:
        """Enrich an attack event with MITRE ATT&CK intel and containment recommendation"""
        profile = MITRE_TACTICS_MAP.get(attack_type, MITRE_TACTICS_MAP["Zero-Day / Distributed Attack"])

        rule = profile["firewall_rule"].format(src_ip=src_ip, dst_ip=dst_ip)
        is_blocked = src_ip in self.blocked_ips

        return {
            "attack_type": attack_type,
            "tactic": profile["tactic"],
            "technique_id": profile["technique_id"],
            "technique_name": profile["technique_name"],
            "severity": profile["severity"],
            "description": profile["description"],
            "recommended_action": profile["recommended_action"],
            "firewall_rule": rule,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_id": packet_id,
            "is_contained": is_blocked,
        }

    def block_ip(self, ip: str, reason: str, attack_type: str, technique_id: str, auto: bool = True) -> dict:
        """Quarantine and block an offending IP address"""
        record = {
            "ip": ip,
            "blocked_at": datetime.now().isoformat(),
            "reason": reason,
            "attack_type": attack_type,
            "technique_id": technique_id,
            "action": "QUARANTINE_IP",
            "autonomous": auto,
            "status": "ACTIVE_BLOCK",
        }
        self.blocked_ips[ip] = record
        self.containment_history.append(record)
        return record

    def unblock_ip(self, ip: str) -> Optional[dict]:
        """Lift quarantine from an IP address"""
        if ip in self.blocked_ips:
            record = self.blocked_ips.pop(ip)
            record["unblocked_at"] = datetime.now().isoformat()
            record["status"] = "RESOLVED"
            return record
        return None

    def get_blocked_list(self) -> List[dict]:
        """Return list of currently quarantined IPs"""
        return list(self.blocked_ips.values())

    def get_history(self) -> List[dict]:
        """Return containment action history"""
        return self.containment_history[-50:]

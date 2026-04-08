"""
Advanced Security Insights Module
Extracts rich, actionable security intelligence from clustered events
"""
import numpy as np
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta
import re
import ipaddress

from event_parser import SecurityEvent


@dataclass
class AttackPattern:
    """Detected attack pattern information"""
    pattern_id: str
    pattern_name: str
    description: str
    confidence: float
    mitre_techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    timeline: dict = field(default_factory=dict)
    severity: str = "medium"


@dataclass
class ThreatActor:
    """Potential threat actor profile"""
    actor_id: str
    source_ips: list[str]
    behavior_type: str  # "scanner", "brute_forcer", "data_exfil", "lateral_movement", "apt"
    activity_timeline: list[dict] = field(default_factory=list)
    targeted_systems: list[str] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class AnomalyScore:
    """Anomaly detection scores for events"""
    overall_score: float
    temporal_score: float
    network_score: float
    behavior_score: float
    volume_score: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class SecurityInsight:
    """Rich security insight extracted from cluster analysis"""
    insight_id: str
    category: str  # "attack", "policy_violation", "misconfiguration", "anomaly", "reconnaissance"
    title: str
    description: str
    severity: str  # "critical", "high", "medium", "low", "info"
    confidence: float
    
    # Evidence
    event_count: int = 0
    sample_events: list[dict] = field(default_factory=list)
    
    # Context
    affected_subsystems: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    target_assets: list[str] = field(default_factory=list)
    
    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    
    # Recommendations
    immediate_actions: list[str] = field(default_factory=list)
    long_term_actions: list[str] = field(default_factory=list)
    
    # Related
    related_clusters: list[int] = field(default_factory=list)
    ioc_indicators: list[dict] = field(default_factory=list)


@dataclass 
class ClusterCorrelation:
    """Correlation between two clusters"""
    cluster_a: int
    cluster_b: int
    correlation_type: str  # "same_source", "same_target", "attack_chain", "sequence_latent_similarity", ...
    correlation_strength: float
    shared_indicators: list[str] = field(default_factory=list)
    description: str = ""


class SecurityInsightsEngine:
    """
    Advanced engine for extracting rich security insights from clustered events
    """
    
    # MITRE ATT&CK mappings
    MITRE_MAPPINGS = {
        # Reconnaissance
        "scan": ("Reconnaissance", "T1595 - Active Scanning"),
        "probe": ("Reconnaissance", "T1595 - Active Scanning"),
        "enumerate": ("Discovery", "T1046 - Network Service Scanning"),
        
        # Initial Access
        "brute": ("Credential Access", "T1110 - Brute Force"),
        "phishing": ("Initial Access", "T1566 - Phishing"),
        "exploit": ("Initial Access", "T1190 - Exploit Public-Facing Application"),
        
        # Execution
        "injection": ("Execution", "T1059 - Command and Scripting Interpreter"),
        "sqli": ("Initial Access", "T1190 - Exploit Public-Facing Application"),
        "xss": ("Initial Access", "T1189 - Drive-by Compromise"),
        "rce": ("Execution", "T1203 - Exploitation for Client Execution"),
        
        # Persistence
        "backdoor": ("Persistence", "T1505 - Server Software Component"),
        "webshell": ("Persistence", "T1505.003 - Web Shell"),
        
        # Defense Evasion
        "obfuscation": ("Defense Evasion", "T1027 - Obfuscated Files or Information"),
        
        # Credential Access
        "password": ("Credential Access", "T1110 - Brute Force"),
        "credential": ("Credential Access", "T1555 - Credentials from Password Stores"),
        
        # Lateral Movement
        "smb": ("Lateral Movement", "T1021.002 - SMB/Windows Admin Shares"),
        "rdp": ("Lateral Movement", "T1021.001 - Remote Desktop Protocol"),
        "ssh": ("Lateral Movement", "T1021.004 - SSH"),
        
        # Collection
        "exfil": ("Exfiltration", "T1041 - Exfiltration Over C2 Channel"),
        
        # Command and Control
        "c2": ("Command and Control", "T1071 - Application Layer Protocol"),
        "beacon": ("Command and Control", "T1095 - Non-Application Layer Protocol"),
        
        # Impact
        "ddos": ("Impact", "T1498 - Network Denial of Service"),
        "ransomware": ("Impact", "T1486 - Data Encrypted for Impact"),
        "malware": ("Execution", "T1204 - User Execution"),
    }
    
    # Known bad ports and their risk
    SUSPICIOUS_PORTS = {
        22: ("SSH", "high"),
        23: ("Telnet", "critical"),
        25: ("SMTP", "medium"),
        110: ("POP3", "medium"),
        135: ("RPC", "high"),
        137: ("NetBIOS", "high"),
        139: ("NetBIOS", "high"),
        445: ("SMB", "critical"),
        1433: ("MSSQL", "high"),
        1521: ("Oracle", "high"),
        3306: ("MySQL", "high"),
        3389: ("RDP", "critical"),
        4444: ("Metasploit", "critical"),
        5432: ("PostgreSQL", "high"),
        5900: ("VNC", "high"),
        6379: ("Redis", "high"),
        8080: ("HTTP Alt", "medium"),
        27017: ("MongoDB", "high"),
    }
    
    # Private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    
    def __init__(self):
        self.insights = []
        self.attack_patterns = []
        self.threat_actors = []
        self.correlations = []
    
    def analyze_cluster_insights(
        self,
        cluster_id: int,
        events: list[SecurityEvent],
        latent_features: Optional[np.ndarray] = None
    ) -> list[SecurityInsight]:
        """
        Extract rich security insights from a single cluster
        """
        insights = []
        
        if not events:
            return insights
        
        # Collect statistics
        stats = self._collect_cluster_stats(events)
        
        # Detect attack patterns
        attack_insights = self._detect_attack_patterns(cluster_id, events, stats)
        insights.extend(attack_insights)
        
        # Detect policy violations
        policy_insights = self._detect_policy_violations(cluster_id, events, stats)
        insights.extend(policy_insights)
        
        # Detect anomalies
        anomaly_insights = self._detect_anomalies(cluster_id, events, stats)
        insights.extend(anomaly_insights)
        
        # Detect reconnaissance
        recon_insights = self._detect_reconnaissance(cluster_id, events, stats)
        insights.extend(recon_insights)
        
        # Detect data exfiltration patterns
        exfil_insights = self._detect_data_exfiltration(cluster_id, events, stats)
        insights.extend(exfil_insights)
        
        return insights
    
    def _collect_cluster_stats(self, events: list[SecurityEvent]) -> dict:
        """Collect comprehensive statistics from cluster events"""
        stats = {
            "total_events": len(events),
            "subsystems": Counter(),
            "actions": Counter(),
            "severities": Counter(),
            "source_ips": Counter(),
            "dest_ips": Counter(),
            "dest_ports": Counter(),
            "users": Counter(),
            "hours": Counter(),
            "content_words": Counter(),
            "protocols": Counter(),
            "timestamps": [],
            "external_sources": 0,
            "internal_sources": 0,
            "blocked_count": 0,
            "allowed_count": 0,
        }
        
        for event in events:
            if event.subsystem:
                stats["subsystems"][event.subsystem] += 1
            if event.action:
                stats["actions"][event.action.lower()] += 1
                if event.action.lower() in ["block", "blocked", "deny", "denied", "drop"]:
                    stats["blocked_count"] += 1
                elif event.action.lower() in ["allow", "allowed", "accept", "pass"]:
                    stats["allowed_count"] += 1
            if event.severity:
                stats["severities"][event.severity.lower()] += 1
            if event.source_ip:
                stats["source_ips"][event.source_ip] += 1
                if self._is_external_ip(event.source_ip):
                    stats["external_sources"] += 1
                else:
                    stats["internal_sources"] += 1
            if event.dest_ip:
                stats["dest_ips"][event.dest_ip] += 1
            if event.dest_port > 0:
                stats["dest_ports"][event.dest_port] += 1
            if event.user:
                stats["users"][event.user] += 1
            if event.protocol:
                stats["protocols"][event.protocol.upper()] += 1
            if event.timestamp:
                stats["timestamps"].append(event.timestamp)
                try:
                    dt = datetime.strptime(event.timestamp, "%Y-%m-%d %H:%M:%S")
                    stats["hours"][dt.hour] += 1
                except:
                    pass
            if event.content:
                words = re.findall(r'\b\w+\b', event.content.lower())
                for word in words:
                    if len(word) > 3:
                        stats["content_words"][word] += 1
        
        return stats
    
    def _is_external_ip(self, ip_str: str) -> bool:
        """Check if IP is external (public)"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not any(ip in net for net in self.PRIVATE_RANGES)
        except:
            return False
    
    def _detect_attack_patterns(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> list[SecurityInsight]:
        """Detect known attack patterns"""
        insights = []
        
        # Brute Force Detection
        if self._is_brute_force(stats):
            insight = self._create_brute_force_insight(cluster_id, events, stats)
            insights.append(insight)
        
        # Web Application Attack
        if self._is_web_attack(stats):
            insight = self._create_web_attack_insight(cluster_id, events, stats)
            insights.append(insight)
        
        # DDoS Detection
        if self._is_ddos(stats):
            insight = self._create_ddos_insight(cluster_id, events, stats)
            insights.append(insight)
        
        # Malware/C2 Detection
        if self._is_malware_c2(stats):
            insight = self._create_malware_insight(cluster_id, events, stats)
            insights.append(insight)
        
        return insights
    
    def _is_brute_force(self, stats: dict) -> bool:
        """Detect brute force attack patterns"""
        # Check for authentication-related keywords
        auth_keywords = ["brute", "force", "login", "auth", "password", "failed", "invalid"]
        keyword_count = sum(stats["content_words"].get(kw, 0) for kw in auth_keywords)
        
        # Check for targeted ports
        brute_force_ports = {22, 23, 3389, 21, 5900}
        targeted_ports = set(p for p, _ in stats["dest_ports"].most_common(5))
        
        # Check for repeated source
        if stats["source_ips"]:
            top_source_count = stats["source_ips"].most_common(1)[0][1]
            if top_source_count > stats["total_events"] * 0.5:
                if keyword_count > 0 or targeted_ports & brute_force_ports:
                    return True
        
        return keyword_count >= 3 and stats["blocked_count"] > stats["allowed_count"]
    
    def _create_brute_force_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for brute force attack"""
        top_sources = [ip for ip, _ in stats["source_ips"].most_common(5)]
        top_ports = [p for p, _ in stats["dest_ports"].most_common(3)]
        
        port_services = []
        for port in top_ports:
            if port in self.SUSPICIOUS_PORTS:
                port_services.append(f"{port} ({self.SUSPICIOUS_PORTS[port][0]})")
            else:
                port_services.append(str(port))
        
        return SecurityInsight(
            insight_id=f"bf_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="attack",
            title="Brute Force Attack Detected",
            description=f"Detected {stats['total_events']} brute force attempts targeting "
                       f"services on ports {', '.join(port_services)}. "
                       f"{stats['blocked_count']} attempts were blocked.",
            severity="high" if stats["blocked_count"] < stats["total_events"] * 0.9 else "medium",
            confidence=0.85,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=top_sources,
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Credential Access"],
            mitre_techniques=["T1110 - Brute Force"],
            immediate_actions=[
                f"Block source IPs: {', '.join(top_sources[:3])}",
                "Enable account lockout policies",
                "Review authentication logs for compromised accounts",
                "Enable multi-factor authentication",
            ],
            long_term_actions=[
                "Implement rate limiting on authentication endpoints",
                "Deploy intrusion detection rules for brute force patterns",
                "Consider geographic IP blocking if attacks originate from specific regions",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[{"type": "ip", "value": ip, "context": "brute_force_source"} for ip in top_sources]
        )
    
    def _is_web_attack(self, stats: dict) -> bool:
        """Detect web application attacks"""
        web_attack_keywords = [
            "sqli", "injection", "xss", "script", "union", "select",
            "exec", "shell", "eval", "passwd", "etc", "traversal",
            "directory", "lfi", "rfi", "include", "php", "asp"
        ]
        keyword_count = sum(stats["content_words"].get(kw, 0) for kw in web_attack_keywords)
        
        waf_events = stats["subsystems"].get("waf", 0)
        web_ports = stats["dest_ports"].get(80, 0) + stats["dest_ports"].get(443, 0) + stats["dest_ports"].get(8080, 0)
        
        return (keyword_count >= 2 or waf_events > 0) and web_ports > 0
    
    def _create_web_attack_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for web application attack"""
        attack_types = []
        if any(kw in stats["content_words"] for kw in ["sqli", "sql", "injection", "union", "select"]):
            attack_types.append("SQL Injection")
        if any(kw in stats["content_words"] for kw in ["xss", "script", "javascript"]):
            attack_types.append("Cross-Site Scripting (XSS)")
        if any(kw in stats["content_words"] for kw in ["traversal", "directory", "lfi", "rfi"]):
            attack_types.append("Path Traversal")
        if any(kw in stats["content_words"] for kw in ["shell", "exec", "command"]):
            attack_types.append("Command Injection")
        
        if not attack_types:
            attack_types = ["Web Application Attack"]
        
        return SecurityInsight(
            insight_id=f"web_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="attack",
            title=f"Web Application Attack: {', '.join(attack_types)}",
            description=f"Detected {stats['total_events']} web application attack attempts. "
                       f"Attack types identified: {', '.join(attack_types)}. "
                       f"WAF blocked {stats['blocked_count']} requests.",
            severity="critical" if "SQL Injection" in attack_types or "Command Injection" in attack_types else "high",
            confidence=0.9 if stats["subsystems"].get("waf", 0) > 0 else 0.75,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(5)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Initial Access", "Execution"],
            mitre_techniques=["T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter"],
            immediate_actions=[
                "Review and update WAF rules",
                "Check for successful exploitation attempts",
                "Scan affected systems for compromise",
                "Review application logs for post-exploitation activity",
            ],
            long_term_actions=[
                "Conduct security audit of web applications",
                "Implement input validation and parameterized queries",
                "Enable Content Security Policy (CSP) headers",
                "Regular penetration testing",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[{"type": "ip", "value": ip, "context": "web_attacker"} for ip, _ in stats["source_ips"].most_common(3)]
        )
    
    def _is_ddos(self, stats: dict) -> bool:
        """Detect DDoS patterns"""
        ddos_keywords = ["ddos", "dos", "flood", "syn", "amplification", "reflection"]
        keyword_count = sum(stats["content_words"].get(kw, 0) for kw in ddos_keywords)
        
        ddos_subsys = stats["subsystems"].get("ddos", 0)
        high_volume = stats["total_events"] > 1000
        
        # Multiple sources targeting same destination
        many_sources = len(stats["source_ips"]) > 50
        single_target = len(stats["dest_ips"]) <= 3
        
        return ddos_subsys > 0 or keyword_count >= 1 or (high_volume and many_sources and single_target)
    
    def _create_ddos_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for DDoS attack"""
        return SecurityInsight(
            insight_id=f"ddos_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="attack",
            title="Distributed Denial of Service (DDoS) Attack",
            description=f"Detected DDoS attack with {stats['total_events']} events from "
                       f"{len(stats['source_ips'])} unique sources. "
                       f"Target: {list(stats['dest_ips'].keys())[:3]}.",
            severity="critical",
            confidence=0.9 if stats["subsystems"].get("ddos", 0) > 0 else 0.75,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(20)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Impact"],
            mitre_techniques=["T1498 - Network Denial of Service", "T1499 - Endpoint Denial of Service"],
            immediate_actions=[
                "Enable DDoS mitigation services",
                "Implement rate limiting",
                "Block attacking IP ranges at network perimeter",
                "Contact upstream ISP for traffic scrubbing",
            ],
            long_term_actions=[
                "Deploy CDN with DDoS protection",
                "Implement anycast DNS",
                "Create incident response playbook for DDoS",
                "Review network architecture for single points of failure",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[]
        )
    
    def _is_malware_c2(self, stats: dict) -> bool:
        """Detect malware or C2 activity"""
        malware_keywords = ["malware", "virus", "trojan", "c2", "beacon", "callback", "botnet", "backdoor"]
        keyword_count = sum(stats["content_words"].get(kw, 0) for kw in malware_keywords)
        
        # Check for suspicious port usage
        suspicious_port_activity = any(
            port in stats["dest_ports"] 
            for port in [4444, 5555, 6666, 8888, 31337]
        )
        
        return keyword_count >= 1 or suspicious_port_activity
    
    def _create_malware_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for malware/C2 activity"""
        return SecurityInsight(
            insight_id=f"malware_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="attack",
            title="Potential Malware/C2 Communication Detected",
            description=f"Detected {stats['total_events']} events with characteristics of "
                       f"malware or command-and-control communication.",
            severity="critical",
            confidence=0.7,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(10)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(10)],
            mitre_tactics=["Command and Control", "Execution"],
            mitre_techniques=["T1071 - Application Layer Protocol", "T1204 - User Execution"],
            immediate_actions=[
                "Isolate potentially infected systems",
                "Capture network traffic for analysis",
                "Run endpoint detection and response (EDR) scans",
                "Block identified C2 destinations",
            ],
            long_term_actions=[
                "Review endpoint security configurations",
                "Implement network segmentation",
                "Deploy DNS sinkholing for known C2 domains",
                "Conduct forensic investigation",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[
                {"type": "ip", "value": ip, "context": "potential_c2"} 
                for ip, _ in stats["dest_ips"].most_common(5)
            ]
        )
    
    def _detect_policy_violations(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> list[SecurityInsight]:
        """Detect security policy violations"""
        insights = []
        
        # Unauthorized access attempts
        if self._is_unauthorized_access(stats):
            insights.append(self._create_unauthorized_access_insight(cluster_id, events, stats))
        
        # Data policy violations
        if self._is_data_policy_violation(stats):
            insights.append(self._create_data_policy_insight(cluster_id, events, stats))
        
        return insights
    
    def _is_unauthorized_access(self, stats: dict) -> bool:
        """Check for unauthorized access patterns"""
        auth_words = ["unauthorized", "denied", "forbidden", "invalid", "expired"]
        return sum(stats["content_words"].get(w, 0) for w in auth_words) >= 2
    
    def _create_unauthorized_access_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for unauthorized access"""
        return SecurityInsight(
            insight_id=f"unauth_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="policy_violation",
            title="Unauthorized Access Attempts",
            description=f"Detected {stats['total_events']} unauthorized access attempts. "
                       f"Users involved: {', '.join([u for u, _ in stats['users'].most_common(3)])}.",
            severity="medium",
            confidence=0.8,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(5)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Initial Access"],
            mitre_techniques=["T1078 - Valid Accounts"],
            immediate_actions=[
                "Review access control policies",
                "Check for compromised credentials",
                "Audit user permissions",
            ],
            long_term_actions=[
                "Implement principle of least privilege",
                "Regular access reviews",
                "Enhanced monitoring for sensitive resources",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[]
        )
    
    def _is_data_policy_violation(self, stats: dict) -> bool:
        """Check for data policy violations"""
        data_words = ["sensitive", "confidential", "pii", "privacy", "compliance", "violation"]
        return sum(stats["content_words"].get(w, 0) for w in data_words) >= 1
    
    def _create_data_policy_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for data policy violation"""
        return SecurityInsight(
            insight_id=f"data_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="policy_violation",
            title="Data Policy Violation",
            description=f"Detected {stats['total_events']} potential data policy violations.",
            severity="high",
            confidence=0.75,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(5)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Collection", "Exfiltration"],
            mitre_techniques=["T1005 - Data from Local System"],
            immediate_actions=[
                "Review data access logs",
                "Identify affected data categories",
                "Assess compliance impact",
            ],
            long_term_actions=[
                "Enhance data loss prevention (DLP) policies",
                "Implement data classification",
                "Regular compliance audits",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[]
        )
    
    def _detect_anomalies(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> list[SecurityInsight]:
        """Detect anomalous patterns"""
        insights = []
        
        # Temporal anomaly (off-hours activity)
        if self._is_temporal_anomaly(stats):
            insights.append(self._create_temporal_anomaly_insight(cluster_id, events, stats))
        
        # Volume anomaly
        if self._is_volume_anomaly(stats):
            insights.append(self._create_volume_anomaly_insight(cluster_id, events, stats))
        
        return insights
    
    def _is_temporal_anomaly(self, stats: dict) -> bool:
        """Check for unusual timing patterns"""
        if not stats["hours"]:
            return False
        
        # Check for predominantly off-hours activity
        off_hours = sum(stats["hours"].get(h, 0) for h in [0, 1, 2, 3, 4, 5, 22, 23])
        total = sum(stats["hours"].values())
        
        return total > 0 and off_hours / total > 0.6
    
    def _create_temporal_anomaly_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for temporal anomaly"""
        peak_hours = [h for h, _ in sorted(stats["hours"].items(), key=lambda x: -x[1])[:3]]
        
        return SecurityInsight(
            insight_id=f"temporal_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="anomaly",
            title="Unusual Off-Hours Activity Pattern",
            description=f"Detected {stats['total_events']} events with unusual timing. "
                       f"Peak activity hours: {peak_hours}. This may indicate automated attacks or APT activity.",
            severity="medium",
            confidence=0.7,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(5)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Defense Evasion"],
            mitre_techniques=["T1036 - Masquerading"],
            immediate_actions=[
                "Review activity for legitimate business justification",
                "Check if activity correlates with scheduled tasks",
                "Investigate source systems",
            ],
            long_term_actions=[
                "Establish baseline for normal activity patterns",
                "Implement time-based access policies",
                "Enhanced monitoring during off-hours",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[]
        )
    
    def _is_volume_anomaly(self, stats: dict) -> bool:
        """Check for unusual volume patterns"""
        # High concentration from single source
        if stats["source_ips"]:
            top_source_ratio = stats["source_ips"].most_common(1)[0][1] / stats["total_events"]
            if top_source_ratio > 0.7 and stats["total_events"] > 100:
                return True
        return False
    
    def _create_volume_anomaly_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for volume anomaly"""
        top_source = stats["source_ips"].most_common(1)[0]
        
        return SecurityInsight(
            insight_id=f"volume_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="anomaly",
            title="Abnormal Traffic Volume from Single Source",
            description=f"Source {top_source[0]} generated {top_source[1]} out of {stats['total_events']} events "
                       f"({top_source[1]/stats['total_events']*100:.1f}%). This concentrated activity is anomalous.",
            severity="medium",
            confidence=0.75,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[top_source[0]],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Reconnaissance", "Impact"],
            mitre_techniques=["T1046 - Network Service Scanning"],
            immediate_actions=[
                f"Investigate source IP {top_source[0]}",
                "Check for compromised systems",
                "Consider temporary rate limiting",
            ],
            long_term_actions=[
                "Implement behavioral analytics",
                "Establish traffic baselines",
                "Deploy anomaly detection",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[{"type": "ip", "value": top_source[0], "context": "high_volume_source"}]
        )
    
    def _detect_reconnaissance(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> list[SecurityInsight]:
        """Detect reconnaissance activity"""
        insights = []
        
        recon_keywords = ["scan", "probe", "enumerate", "discover", "port"]
        keyword_count = sum(stats["content_words"].get(kw, 0) for kw in recon_keywords)
        
        # Check for port scanning pattern (many ports, single source)
        many_ports = len(stats["dest_ports"]) > 10
        concentrated_source = len(stats["source_ips"]) <= 3
        
        if keyword_count >= 1 or (many_ports and concentrated_source):
            insights.append(self._create_recon_insight(cluster_id, events, stats))
        
        return insights
    
    def _create_recon_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for reconnaissance"""
        return SecurityInsight(
            insight_id=f"recon_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="reconnaissance",
            title="Network Reconnaissance Detected",
            description=f"Detected reconnaissance activity: {len(stats['dest_ports'])} unique ports probed "
                       f"from {len(stats['source_ips'])} source(s). This is often a precursor to attacks.",
            severity="medium",
            confidence=0.8,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(5)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Reconnaissance", "Discovery"],
            mitre_techniques=["T1595 - Active Scanning", "T1046 - Network Service Scanning"],
            immediate_actions=[
                "Block scanning source IPs",
                "Review firewall rules for exposed services",
                "Check for successful connections from scanners",
            ],
            long_term_actions=[
                "Implement honeypots to detect scanning",
                "Reduce attack surface by closing unnecessary ports",
                "Deploy port knocking or single packet authorization",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[{"type": "ip", "value": ip, "context": "scanner"} for ip, _ in stats["source_ips"].most_common(3)]
        )
    
    def _detect_data_exfiltration(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> list[SecurityInsight]:
        """Detect potential data exfiltration"""
        insights = []
        
        exfil_keywords = ["exfil", "upload", "transfer", "export", "copy", "steal"]
        keyword_count = sum(stats["content_words"].get(kw, 0) for kw in exfil_keywords)
        
        # Internal source to external destination pattern
        internal_to_external = stats["internal_sources"] > stats["external_sources"]
        if keyword_count >= 1 or (internal_to_external and stats["blocked_count"] > 0):
            # Check if mostly internal sources
            if internal_to_external:
                insights.append(self._create_exfil_insight(cluster_id, events, stats))
        
        return insights
    
    def _create_exfil_insight(
        self, 
        cluster_id: int, 
        events: list[SecurityEvent], 
        stats: dict
    ) -> SecurityInsight:
        """Create insight for data exfiltration"""
        return SecurityInsight(
            insight_id=f"exfil_{cluster_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category="attack",
            title="Potential Data Exfiltration",
            description=f"Detected {stats['total_events']} events with characteristics of data exfiltration. "
                       f"Internal systems communicating with {len(stats['dest_ips'])} external destinations.",
            severity="high",
            confidence=0.65,
            event_count=stats["total_events"],
            sample_events=self._get_sample_events(events, 5),
            affected_subsystems=list(stats["subsystems"].keys()),
            source_ips=[ip for ip, _ in stats["source_ips"].most_common(5)],
            target_assets=[ip for ip, _ in stats["dest_ips"].most_common(5)],
            mitre_tactics=["Exfiltration"],
            mitre_techniques=["T1041 - Exfiltration Over C2 Channel", "T1048 - Exfiltration Over Alternative Protocol"],
            immediate_actions=[
                "Review source systems for compromise",
                "Check for unauthorized file access",
                "Block suspicious external destinations",
                "Preserve evidence for forensics",
            ],
            long_term_actions=[
                "Implement data loss prevention (DLP)",
                "Monitor for large data transfers",
                "Segment sensitive data networks",
                "Regular data access audits",
            ],
            related_clusters=[cluster_id],
            ioc_indicators=[{"type": "ip", "value": ip, "context": "exfil_destination"} for ip, _ in stats["dest_ips"].most_common(5)]
        )
    
    def _get_sample_events(self, events: list[SecurityEvent], n: int = 5) -> list[dict]:
        """Get sample events as dictionaries"""
        samples = []
        for event in events[:n]:
            samples.append({
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port,
                "subsystem": event.subsystem,
                "action": event.action,
                "severity": event.severity,
                "user": event.user,
                "content": event.content[:200] if event.content else ""
            })
        return samples
    
    def find_cluster_correlations(
        self,
        cluster_profiles: list[dict],
        events_by_cluster: dict[int, list[SecurityEvent]],
        latent_embeddings: Optional[np.ndarray] = None,
        cluster_labels: Optional[np.ndarray] = None,
        latent_similarity_threshold: float = 0.55,
    ) -> list[ClusterCorrelation]:
        """
        Find correlations between clusters.

        Combines (1) classical IOC / graph overlap heuristics with (2) optional
        **sequence-model latent similarity**: when ``latent_embeddings`` and
        ``cluster_labels`` are provided, cluster centroids in embedding space
        are compared with cosine similarity (useful for LSTM/Transformer IDEC).
        """
        correlations = []
        
        cluster_ids = list(events_by_cluster.keys())

        # Latent-space similarity (sequence / deep embedding geometry)
        if (
            latent_embeddings is not None
            and cluster_labels is not None
            and len(latent_embeddings) == len(cluster_labels)
            and latent_embeddings.ndim == 2
        ):
            uniq = sorted(set(int(c) for c in cluster_labels))
            centroids: dict[int, np.ndarray] = {}
            for cid in uniq:
                mask = cluster_labels == cid
                if not np.any(mask):
                    continue
                v = latent_embeddings[mask].mean(axis=0)
                n = np.linalg.norm(v) + 1e-8
                centroids[cid] = v / n
            cids = sorted(centroids.keys())
            for i, a in enumerate(cids):
                for b in cids[i + 1 :]:
                    sim = float(np.dot(centroids[a], centroids[b]))
                    if sim >= latent_similarity_threshold:
                        correlations.append(
                            ClusterCorrelation(
                                cluster_a=a,
                                cluster_b=b,
                                correlation_type="sequence_latent_similarity",
                                correlation_strength=sim,
                                shared_indicators=[],
                                description=(
                                    f"Sequence-embedding centroids align (cosine={sim:.3f}); "
                                    f"clusters {a} and {b} may reflect related behaviors in latent space"
                                ),
                            )
                        )
        
        for i, cluster_a in enumerate(cluster_ids):
            events_a = events_by_cluster[cluster_a]
            sources_a = set(e.source_ip for e in events_a if e.source_ip)
            targets_a = set(e.dest_ip for e in events_a if e.dest_ip)
            
            for cluster_b in cluster_ids[i+1:]:
                events_b = events_by_cluster[cluster_b]
                sources_b = set(e.source_ip for e in events_b if e.source_ip)
                targets_b = set(e.dest_ip for e in events_b if e.dest_ip)
                
                # Same source correlation
                shared_sources = sources_a & sources_b
                if shared_sources:
                    strength = len(shared_sources) / max(len(sources_a), len(sources_b))
                    if strength > 0.1:
                        correlations.append(ClusterCorrelation(
                            cluster_a=cluster_a,
                            cluster_b=cluster_b,
                            correlation_type="same_source",
                            correlation_strength=strength,
                            shared_indicators=list(shared_sources)[:5],
                            description=f"Clusters share {len(shared_sources)} source IPs"
                        ))
                
                # Same target correlation
                shared_targets = targets_a & targets_b
                if shared_targets:
                    strength = len(shared_targets) / max(len(targets_a), len(targets_b))
                    if strength > 0.1:
                        correlations.append(ClusterCorrelation(
                            cluster_a=cluster_a,
                            cluster_b=cluster_b,
                            correlation_type="same_target",
                            correlation_strength=strength,
                            shared_indicators=list(shared_targets)[:5],
                            description=f"Clusters target {len(shared_targets)} common systems"
                        ))
                
                # Attack chain detection (source in A is target in B or vice versa)
                sources_targeting = sources_a & targets_b
                if sources_targeting:
                    correlations.append(ClusterCorrelation(
                        cluster_a=cluster_a,
                        cluster_b=cluster_b,
                        correlation_type="attack_chain",
                        correlation_strength=len(sources_targeting) / len(sources_a),
                        shared_indicators=list(sources_targeting)[:5],
                        description=f"Potential attack chain: sources in cluster {cluster_a} are targets in cluster {cluster_b}"
                    ))
        
        return correlations
    
    def generate_executive_summary(
        self,
        all_insights: list[SecurityInsight],
        cluster_count: int,
        total_events: int
    ) -> dict:
        """Generate executive summary of all insights"""
        severity_counts = Counter(i.severity for i in all_insights)
        category_counts = Counter(i.category for i in all_insights)
        
        # Top threats
        critical_insights = [i for i in all_insights if i.severity == "critical"]
        high_insights = [i for i in all_insights if i.severity == "high"]
        
        # Collect all IOCs
        all_iocs = []
        for insight in all_insights:
            all_iocs.extend(insight.ioc_indicators)
        
        # Unique malicious IPs
        malicious_ips = set()
        for ioc in all_iocs:
            if ioc.get("type") == "ip":
                malicious_ips.add(ioc.get("value"))
        
        # MITRE coverage
        all_tactics = []
        all_techniques = []
        for insight in all_insights:
            all_tactics.extend(insight.mitre_tactics)
            all_techniques.extend(insight.mitre_techniques)
        
        return {
            "overview": {
                "total_events_analyzed": total_events,
                "clusters_identified": cluster_count,
                "insights_generated": len(all_insights),
                "unique_malicious_ips": len(malicious_ips),
            },
            "severity_distribution": dict(severity_counts),
            "category_distribution": dict(category_counts),
            "critical_findings": [
                {
                    "title": i.title,
                    "description": i.description[:200],
                    "event_count": i.event_count,
                    "immediate_actions": i.immediate_actions[:2]
                }
                for i in critical_insights[:5]
            ],
            "high_priority_findings": [
                {
                    "title": i.title,
                    "description": i.description[:200],
                    "event_count": i.event_count,
                }
                for i in high_insights[:5]
            ],
            "mitre_coverage": {
                "tactics": list(set(all_tactics)),
                "techniques": list(set(all_techniques))[:15],
            },
            "top_threat_actors": list(malicious_ips)[:10],
            "recommended_priorities": self._generate_priorities(all_insights),
        }
    
    def _generate_priorities(self, insights: list[SecurityInsight]) -> list[str]:
        """Generate prioritized action recommendations"""
        priorities = []
        
        critical = [i for i in insights if i.severity == "critical"]
        if critical:
            priorities.append(f"CRITICAL: Address {len(critical)} critical findings immediately")
        
        attacks = [i for i in insights if i.category == "attack"]
        if attacks:
            priorities.append(f"Investigate {len(attacks)} detected attack patterns")
        
        # Check for specific patterns
        has_brute_force = any("Brute Force" in i.title for i in insights)
        has_web_attack = any("Web Application" in i.title for i in insights)
        has_ddos = any("DDoS" in i.title for i in insights)
        has_exfil = any("Exfiltration" in i.title for i in insights)
        
        if has_brute_force:
            priorities.append("Strengthen authentication mechanisms and implement MFA")
        if has_web_attack:
            priorities.append("Review and update WAF rules; audit web applications")
        if has_ddos:
            priorities.append("Enable DDoS mitigation and review network capacity")
        if has_exfil:
            priorities.append("Implement DLP controls and investigate affected systems")
        
        return priorities[:5]

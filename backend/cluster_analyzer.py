"""
Security Cluster Analysis Module
Extracts security insights from clustered events
"""
import numpy as np
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

from event_parser import SecurityEvent, EventParser


@dataclass
class ClusterProfile:
    """Profile describing a cluster of security events"""
    cluster_id: int
    size: int
    
    # Dominant characteristics
    primary_subsystems: list[str] = field(default_factory=list)
    primary_actions: list[str] = field(default_factory=list)
    severity_distribution: dict = field(default_factory=dict)
    
    # Network patterns
    top_source_ips: list[tuple] = field(default_factory=list)
    top_dest_ips: list[tuple] = field(default_factory=list)
    top_dest_ports: list[tuple] = field(default_factory=list)
    
    # Temporal patterns
    peak_hours: list[int] = field(default_factory=list)
    weekend_ratio: float = 0.0
    business_hours_ratio: float = 0.0
    
    # User patterns
    top_users: list[tuple] = field(default_factory=list)
    has_user_ratio: float = 0.0
    
    # Common content patterns
    content_keywords: list[str] = field(default_factory=list)
    
    # Security assessment
    threat_level: str = "unknown"
    threat_indicators: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    
    # Representative events
    representative_events: list[dict] = field(default_factory=list)


class ClusterAnalyzer:
    """
    Analyzes clusters of security events to extract security intelligence
    """
    
    # Known malicious ports
    SUSPICIOUS_PORTS = {
        22: "SSH brute force target",
        23: "Telnet (insecure)",
        25: "SMTP spam relay",
        445: "SMB (ransomware target)",
        1433: "MSSQL attack target",
        3306: "MySQL attack target",
        3389: "RDP brute force target",
        4444: "Metasploit default",
        5900: "VNC attack target",
        6379: "Redis (often unprotected)",
        27017: "MongoDB (often unprotected)",
    }
    
    # Threat keywords in content
    THREAT_KEYWORDS = [
        'attack', 'exploit', 'malware', 'virus', 'trojan', 'ransomware',
        'brute', 'force', 'injection', 'sqli', 'xss', 'csrf', 'rce',
        'overflow', 'shell', 'backdoor', 'rootkit', 'phishing', 'spam',
        'ddos', 'dos', 'scan', 'probe', 'enumerate', 'unauthorized',
        'blocked', 'denied', 'dropped', 'quarantine', 'isolated',
        'violation', 'anomaly', 'suspicious', 'threat', 'critical',
        'intrusion', 'breach', 'exfiltration', 'c2', 'command',
    ]
    
    def __init__(self, parser: Optional[EventParser] = None):
        self.parser = parser or EventParser()
    
    def analyze_cluster(
        self,
        events: list[SecurityEvent],
        cluster_id: int,
        latent_centroid: Optional[np.ndarray] = None
    ) -> ClusterProfile:
        """
        Analyze a cluster of security events
        
        Args:
            events: List of SecurityEvent objects in this cluster
            cluster_id: Cluster identifier
            latent_centroid: Optional centroid in latent space
            
        Returns:
            ClusterProfile with extracted insights
        """
        profile = ClusterProfile(cluster_id=cluster_id, size=len(events))
        
        if not events:
            return profile
        
        # Collect statistics
        subsystems = Counter()
        actions = Counter()
        severities = Counter()
        source_ips = Counter()
        dest_ips = Counter()
        dest_ports = Counter()
        users = Counter()
        hours = Counter()
        content_words = Counter()
        
        weekend_count = 0
        business_hours_count = 0
        has_user_count = 0
        
        for event in events:
            # Subsystem and action
            if event.subsystem:
                subsystems[event.subsystem] += 1
            if event.action:
                actions[event.action] += 1
            if event.severity:
                severities[event.severity] += 1
            
            # Network info
            if event.source_ip:
                source_ips[event.source_ip] += 1
            if event.dest_ip:
                dest_ips[event.dest_ip] += 1
            if event.dest_port > 0:
                dest_ports[event.dest_port] += 1
            
            # User info
            if event.user:
                users[event.user] += 1
                has_user_count += 1
            
            # Temporal analysis
            if event.timestamp:
                try:
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S']:
                        try:
                            dt = datetime.strptime(event.timestamp, fmt)
                            hours[dt.hour] += 1
                            if dt.weekday() >= 5:
                                weekend_count += 1
                            if 9 <= dt.hour <= 17:
                                business_hours_count += 1
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass
            
            # Content analysis
            if event.content:
                words = event.content.lower().split()
                for word in words:
                    word = ''.join(c for c in word if c.isalnum())
                    if len(word) > 3:
                        content_words[word] += 1
        
        # Populate profile
        profile.primary_subsystems = [s for s, _ in subsystems.most_common(3)]
        profile.primary_actions = [a for a, _ in actions.most_common(3)]
        profile.severity_distribution = dict(severities)
        
        profile.top_source_ips = source_ips.most_common(5)
        profile.top_dest_ips = dest_ips.most_common(5)
        profile.top_dest_ports = dest_ports.most_common(5)
        
        # Peak hours (top 3)
        if hours:
            profile.peak_hours = [h for h, _ in hours.most_common(3)]
        
        profile.weekend_ratio = weekend_count / len(events) if events else 0
        profile.business_hours_ratio = business_hours_count / len(events) if events else 0
        
        profile.top_users = users.most_common(5)
        profile.has_user_ratio = has_user_count / len(events) if events else 0
        
        # Content keywords (filter out common words)
        stopwords = {'the', 'and', 'for', 'from', 'with', 'this', 'that', 'have', 'been'}
        profile.content_keywords = [
            w for w, c in content_words.most_common(20) 
            if w not in stopwords and c > 1
        ][:10]
        
        # Assess threat level
        profile.threat_level, profile.threat_indicators = self._assess_threat(
            profile, events
        )
        
        # Generate recommendations
        profile.recommended_actions = self._generate_recommendations(profile)
        
        # Select representative events
        profile.representative_events = self._select_representatives(events, 5)
        
        return profile
    
    def _assess_threat(
        self,
        profile: ClusterProfile,
        events: list[SecurityEvent]
    ) -> tuple[str, list[str]]:
        """Assess threat level based on cluster characteristics"""
        indicators = []
        threat_score = 0
        
        # Check for blocking actions
        block_actions = {'block', 'blocked', 'deny', 'denied', 'drop', 'dropped', 'reject'}
        if any(a in block_actions for a in profile.primary_actions):
            indicators.append("Contains blocked/denied events")
            threat_score += 2
        
        # Check for high severity
        if 'critical' in profile.severity_distribution or 'high' in profile.severity_distribution:
            crit_count = profile.severity_distribution.get('critical', 0)
            high_count = profile.severity_distribution.get('high', 0)
            if crit_count + high_count > profile.size * 0.1:
                indicators.append(f"High severity events: {crit_count} critical, {high_count} high")
                threat_score += 3
        
        # Check for suspicious ports
        for port, count in profile.top_dest_ports:
            if port in self.SUSPICIOUS_PORTS:
                indicators.append(f"Suspicious port {port}: {self.SUSPICIOUS_PORTS[port]}")
                threat_score += 2
                break
        
        # Check for threat keywords in content
        threat_keywords_found = [
            kw for kw in profile.content_keywords 
            if any(tk in kw for tk in self.THREAT_KEYWORDS)
        ]
        if threat_keywords_found:
            indicators.append(f"Threat keywords: {', '.join(threat_keywords_found[:5])}")
            threat_score += len(threat_keywords_found)
        
        # Check for IPS/IDS events
        if any(s in ['ips', 'ids', 'ddos', 'waf'] for s in profile.primary_subsystems):
            indicators.append("Security detection system alerts")
            threat_score += 2
        
        # Check for off-hours activity (potential APT)
        if profile.weekend_ratio > 0.5:
            indicators.append("Predominantly weekend activity")
            threat_score += 1
        if profile.business_hours_ratio < 0.3 and profile.peak_hours:
            night_hours = [h for h in profile.peak_hours if h < 6 or h > 22]
            if night_hours:
                indicators.append(f"Night-time activity pattern (peak: {night_hours})")
                threat_score += 2
        
        # Check for single source targeting multiple destinations
        if len(profile.top_source_ips) == 1 and len(profile.top_dest_ips) > 3:
            indicators.append("Single source scanning multiple targets")
            threat_score += 2
        
        # Determine threat level
        if threat_score >= 8:
            threat_level = "critical"
        elif threat_score >= 5:
            threat_level = "high"
        elif threat_score >= 3:
            threat_level = "medium"
        elif threat_score >= 1:
            threat_level = "low"
        else:
            threat_level = "info"
        
        return threat_level, indicators
    
    def _generate_recommendations(self, profile: ClusterProfile) -> list[str]:
        """Generate security recommendations based on cluster profile"""
        recommendations = []
        
        if profile.threat_level == "critical":
            recommendations.append("URGENT: Immediate investigation required")
            recommendations.append("Consider isolating affected systems")
        
        if profile.threat_level in ["critical", "high"]:
            recommendations.append("Escalate to security operations team")
            recommendations.append("Preserve logs for forensic analysis")
        
        # Port-specific recommendations
        for port, count in profile.top_dest_ports[:3]:
            if port == 3389:
                recommendations.append("Review RDP access policies and enable NLA")
            elif port == 22:
                recommendations.append("Implement key-based SSH authentication")
            elif port == 445:
                recommendations.append("Audit SMB shares and disable SMBv1")
            elif port in [1433, 3306, 5432]:
                recommendations.append("Ensure databases are not exposed to internet")
        
        # Subsystem-specific
        if 'vpn' in profile.primary_subsystems:
            recommendations.append("Review VPN authentication logs")
        if 'waf' in profile.primary_subsystems:
            recommendations.append("Analyze blocked web attack patterns")
        if 'mail' in profile.primary_subsystems:
            recommendations.append("Check for phishing campaign patterns")
        
        # IP-based recommendations
        if profile.top_source_ips:
            top_ip, count = profile.top_source_ips[0]
            if count > profile.size * 0.5:
                recommendations.append(f"Consider blocking IP {top_ip} (responsible for {count} events)")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _select_representatives(
        self,
        events: list[SecurityEvent],
        n: int = 5
    ) -> list[dict]:
        """Select representative events from the cluster"""
        if not events:
            return []
        
        # Prioritize events with more information
        scored_events = []
        for event in events:
            score = 0
            if event.content:
                score += len(event.content) / 100
            if event.action:
                score += 1
            if event.severity in ['critical', 'high']:
                score += 2
            if event.user:
                score += 0.5
            scored_events.append((score, event))
        
        # Sort by score and select top N
        scored_events.sort(key=lambda x: x[0], reverse=True)
        
        return [
            {
                'timestamp': e.timestamp,
                'source_ip': e.source_ip,
                'dest_ip': e.dest_ip,
                'dest_port': e.dest_port,
                'subsystem': e.subsystem,
                'action': e.action,
                'severity': e.severity,
                'user': e.user,
                'content': e.content[:200] if e.content else ''
            }
            for _, e in scored_events[:n]
        ]
    
    def generate_cluster_summary(
        self,
        profiles: list[ClusterProfile]
    ) -> dict:
        """Generate overall summary of all clusters"""
        if not profiles:
            return {}
        
        total_events = sum(p.size for p in profiles)
        
        # Threat distribution
        threat_dist = Counter(p.threat_level for p in profiles)
        
        # Find high-priority clusters
        critical_clusters = [p for p in profiles if p.threat_level == "critical"]
        high_clusters = [p for p in profiles if p.threat_level == "high"]
        
        # Aggregate top threats
        all_indicators = []
        for p in profiles:
            all_indicators.extend(p.threat_indicators)
        top_indicators = Counter(all_indicators).most_common(10)
        
        # Subsystem distribution across clusters
        subsystem_clusters = defaultdict(list)
        for p in profiles:
            for s in p.primary_subsystems:
                subsystem_clusters[s].append(p.cluster_id)
        
        return {
            'total_events': total_events,
            'total_clusters': len(profiles),
            'threat_distribution': dict(threat_dist),
            'critical_clusters': [p.cluster_id for p in critical_clusters],
            'high_risk_clusters': [p.cluster_id for p in high_clusters],
            'top_threat_indicators': top_indicators,
            'subsystem_distribution': {
                s: len(clusters) for s, clusters in subsystem_clusters.items()
            },
            'clusters_by_subsystem': dict(subsystem_clusters),
            'avg_cluster_size': total_events / len(profiles) if profiles else 0,
            'size_range': {
                'min': min(p.size for p in profiles),
                'max': max(p.size for p in profiles)
            }
        }


def analyze_clusters_from_results(
    events: list[SecurityEvent],
    labels: np.ndarray,
    latent_features: Optional[np.ndarray] = None
) -> tuple[list[ClusterProfile], dict]:
    """
    Convenience function to analyze clustering results
    
    Args:
        events: List of SecurityEvent objects
        labels: Cluster labels for each event
        latent_features: Optional latent representations
        
    Returns:
        Tuple of (cluster_profiles, summary)
    """
    analyzer = ClusterAnalyzer()
    
    # Group events by cluster
    cluster_events = defaultdict(list)
    for event, label in zip(events, labels):
        cluster_events[int(label)].append(event)
    
    # Analyze each cluster
    profiles = []
    for cluster_id in sorted(cluster_events.keys()):
        centroid = None
        if latent_features is not None:
            cluster_mask = labels == cluster_id
            if np.any(cluster_mask):
                centroid = latent_features[cluster_mask].mean(axis=0)
        
        profile = analyzer.analyze_cluster(
            cluster_events[cluster_id],
            cluster_id,
            centroid
        )
        profiles.append(profile)
    
    # Generate summary
    summary = analyzer.generate_cluster_summary(profiles)
    
    return profiles, summary

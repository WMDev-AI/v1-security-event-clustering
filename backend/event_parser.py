"""
Security Event Parser for Semi-Structured Log Data
Handles key=value format events from various security subsystems
"""
import re
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime


@dataclass
class SecurityEvent:
    """Represents a parsed security event"""
    timestamp: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    source_port: int = 0
    subsystem: str = ""
    user: str = ""
    action: str = ""
    severity: str = ""
    content: str = ""
    protocol: str = ""
    raw_data: dict = field(default_factory=dict)


class EventParser:
    """Parser for semi-structured security events in key=value format"""
    
    # Common field mappings for normalization
    FIELD_MAPPINGS = {
        'sourceip': 'source_ip',
        'src_ip': 'source_ip',
        'srcip': 'source_ip',
        'source': 'source_ip',
        'destip': 'dest_ip',
        'dst_ip': 'dest_ip',
        'dstip': 'dest_ip',
        'destination': 'dest_ip',
        'destport': 'dest_port',
        'dst_port': 'dest_port',
        'dstport': 'dest_port',
        'sourceport': 'source_port',
        'src_port': 'source_port',
        'srcport': 'source_port',
        'subsys': 'subsystem',
        'system': 'subsystem',
        'module': 'subsystem',
        'msg': 'content',
        'message': 'content',
        'desc': 'content',
        'description': 'content',
        'ts': 'timestamp',
        'time': 'timestamp',
        'datetime': 'timestamp',
        'proto': 'protocol',
        'act': 'action',
        'event_action': 'action',
        'sev': 'severity',
        'level': 'severity',
        'priority': 'severity',
        'username': 'user',
        'usr': 'user',
        'account': 'user',
    }
    
    # Known subsystems for one-hot encoding
    KNOWN_SUBSYSTEMS = [
        'firewall', 'ips', 'ddos', 'waf', 'webfilter', 
        'mail', 'vpn', 'proxy', 'dns', 'antivirus',
        'sandbox', 'dlp', 'nat', 'router', 'auth'
    ]
    
    # Known actions for encoding
    KNOWN_ACTIONS = [
        'block', 'blocked', 'deny', 'denied', 'drop', 'dropped',
        'allow', 'allowed', 'accept', 'accepted', 'pass', 'passed',
        'alert', 'warning', 'critical', 'info', 'log',
        'quarantine', 'isolate', 'redirect', 'modify'
    ]
    
    # Known severity levels
    SEVERITY_LEVELS = {
        'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0,
        'emergency': 4, 'alert': 4, 'error': 3, 'warning': 2, 'notice': 1, 'debug': 0
    }
    
    def __init__(self):
        # Regex for parsing key=value pairs (handles quoted values)
        self.kv_pattern = re.compile(
            r"(\w+)=(?:'([^']*)'|\"([^\"]*)\"|(\S+))"
        )
        # IP address pattern
        self.ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        )
        # IPv6 pattern (simplified)
        self.ipv6_pattern = re.compile(
            r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        )
    
    def parse_event(self, raw_event: str) -> SecurityEvent:
        """Parse a single raw event string into SecurityEvent"""
        event = SecurityEvent()
        event.raw_data = {}
        
        # Find all key=value pairs
        matches = self.kv_pattern.findall(raw_event)
        
        for match in matches:
            key = match[0].lower()
            # Value is in one of the capture groups (quoted or unquoted)
            value = match[1] or match[2] or match[3]
            
            # Normalize field name
            normalized_key = self.FIELD_MAPPINGS.get(key, key)
            event.raw_data[normalized_key] = value
            
            # Set typed fields
            if normalized_key == 'timestamp':
                event.timestamp = value
            elif normalized_key == 'source_ip':
                event.source_ip = value
            elif normalized_key == 'dest_ip':
                event.dest_ip = value
            elif normalized_key == 'dest_port':
                try:
                    event.dest_port = int(value)
                except ValueError:
                    event.dest_port = 0
            elif normalized_key == 'source_port':
                try:
                    event.source_port = int(value)
                except ValueError:
                    event.source_port = 0
            elif normalized_key == 'subsystem':
                event.subsystem = value.lower()
            elif normalized_key == 'user':
                event.user = value
            elif normalized_key == 'action':
                event.action = value.lower()
            elif normalized_key == 'severity':
                event.severity = value.lower()
            elif normalized_key == 'content':
                event.content = value
            elif normalized_key == 'protocol':
                event.protocol = value.upper()
        
        # Extract action from content if not present
        if not event.action and event.content:
            content_lower = event.content.lower()
            for action in self.KNOWN_ACTIONS:
                if action in content_lower:
                    event.action = action
                    break
        
        return event
    
    def parse_events(self, raw_events: list[str]) -> list[SecurityEvent]:
        """Parse multiple raw events"""
        return [self.parse_event(e) for e in raw_events if e.strip()]
    
    def ip_to_features(self, ip: str) -> list[float]:
        """Convert IP address to numerical features"""
        if not ip:
            return [0.0, 0.0, 0.0, 0.0, 0.0]  # 4 octets + is_private flag
        
        try:
            if self.ip_pattern.match(ip):
                octets = [int(o) / 255.0 for o in ip.split('.')]
                # Check if private IP
                first_octet = int(ip.split('.')[0])
                second_octet = int(ip.split('.')[1])
                is_private = (
                    first_octet == 10 or
                    (first_octet == 172 and 16 <= second_octet <= 31) or
                    (first_octet == 192 and second_octet == 168) or
                    first_octet == 127
                )
                return octets + [1.0 if is_private else 0.0]
            else:
                return [0.0, 0.0, 0.0, 0.0, 0.0]
        except Exception:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
    
    def port_to_features(self, port: int) -> list[float]:
        """Convert port number to features"""
        if port <= 0:
            return [0.0, 0.0, 0.0, 0.0]
        
        # Normalize port
        normalized = min(port / 65535.0, 1.0)
        
        # Port category flags
        is_well_known = 1.0 if port < 1024 else 0.0
        is_registered = 1.0 if 1024 <= port < 49152 else 0.0
        is_dynamic = 1.0 if port >= 49152 else 0.0
        
        return [normalized, is_well_known, is_registered, is_dynamic]
    
    def subsystem_to_features(self, subsystem: str) -> list[float]:
        """One-hot encode subsystem"""
        features = [0.0] * len(self.KNOWN_SUBSYSTEMS)
        if subsystem:
            for i, known in enumerate(self.KNOWN_SUBSYSTEMS):
                if known in subsystem.lower():
                    features[i] = 1.0
                    break
        return features
    
    def action_to_features(self, action: str) -> list[float]:
        """Encode action as features"""
        # Group actions: [block, allow, alert, other]
        if not action:
            return [0.0, 0.0, 0.0, 1.0]
        
        action_lower = action.lower()
        if any(a in action_lower for a in ['block', 'deny', 'drop', 'reject']):
            return [1.0, 0.0, 0.0, 0.0]
        elif any(a in action_lower for a in ['allow', 'accept', 'pass', 'permit']):
            return [0.0, 1.0, 0.0, 0.0]
        elif any(a in action_lower for a in ['alert', 'warning', 'critical']):
            return [0.0, 0.0, 1.0, 0.0]
        else:
            return [0.0, 0.0, 0.0, 1.0]
    
    def severity_to_feature(self, severity: str) -> float:
        """Convert severity to numerical feature"""
        if not severity:
            return 0.5  # Unknown severity
        return self.SEVERITY_LEVELS.get(severity.lower(), 2) / 4.0
    
    def timestamp_to_features(self, timestamp: str) -> list[float]:
        """Extract temporal features from timestamp"""
        if not timestamp:
            return [0.0, 0.0, 0.0, 0.0]  # hour_norm, day_of_week, is_weekend, is_business_hours
        
        try:
            # Try common formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%d-%m-%Y %H:%M:%S']:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    break
                except ValueError:
                    continue
            else:
                return [0.0, 0.0, 0.0, 0.0]
            
            hour_norm = dt.hour / 23.0
            day_of_week = dt.weekday() / 6.0
            is_weekend = 1.0 if dt.weekday() >= 5 else 0.0
            is_business_hours = 1.0 if 9 <= dt.hour <= 17 else 0.0
            
            return [hour_norm, day_of_week, is_weekend, is_business_hours]
        except Exception:
            return [0.0, 0.0, 0.0, 0.0]
    
    def event_to_features(self, event: SecurityEvent) -> list[float]:
        """Convert a SecurityEvent to a feature vector"""
        features = []
        
        # Source IP features (5)
        features.extend(self.ip_to_features(event.source_ip))
        
        # Dest IP features (5)
        features.extend(self.ip_to_features(event.dest_ip))
        
        # Port features (8) - source and dest
        features.extend(self.port_to_features(event.source_port))
        features.extend(self.port_to_features(event.dest_port))
        
        # Subsystem features (15)
        features.extend(self.subsystem_to_features(event.subsystem))
        
        # Action features (4)
        features.extend(self.action_to_features(event.action))
        
        # Severity feature (1)
        features.append(self.severity_to_feature(event.severity))
        
        # Timestamp features (4)
        features.extend(self.timestamp_to_features(event.timestamp))
        
        # Protocol feature (common protocols one-hot: TCP, UDP, ICMP, HTTP, HTTPS, other)
        protocol_features = [0.0] * 6
        if event.protocol:
            protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'HTTP': 3, 'HTTPS': 4}
            idx = protocol_map.get(event.protocol.upper(), 5)
            protocol_features[idx] = 1.0
        features.extend(protocol_features)
        
        # Has user flag
        features.append(1.0 if event.user else 0.0)
        
        # Content length (normalized)
        content_len = min(len(event.content) / 500.0, 1.0) if event.content else 0.0
        features.append(content_len)
        
        return features
    
    def get_feature_dim(self) -> int:
        """Return the dimension of feature vectors"""
        return 51  # 5+5+8+15+4+1+4+6+1+1 = 50, plus content length = 51


# Example usage and testing
if __name__ == "__main__":
    parser = EventParser()
    
    # Test events
    test_events = [
        "timestamp=2020-02-02 01:00:00 sourceip=22.2.2.2 destip=3.4.3.2 destport=4444 subsys=vpn user=a content='blocked by user policy'",
        "timestamp=2020-02-03 14:30:00 src_ip=192.168.1.100 dst_ip=10.0.0.1 dstport=443 subsys=firewall action=allow proto=HTTPS",
        "time=2020-02-04 08:15:00 sourceip=10.10.10.10 destip=8.8.8.8 destport=53 module=dns severity=low msg='DNS query'",
    ]
    
    for raw in test_events:
        event = parser.parse_event(raw)
        features = parser.event_to_features(event)
        print(f"Subsystem: {event.subsystem}, Action: {event.action}, Features dim: {len(features)}")

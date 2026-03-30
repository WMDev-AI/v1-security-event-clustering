"""
Security Event Parser for Semi-Structured Log Data
Handles key=value format events from various security subsystems with subsystem-specific field extraction
"""
import re
import numpy as np
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime


@dataclass
class SecurityEvent:
    """Represents a parsed security event"""
    # Core fields (common across all subsystems)
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
    
    # Subsystem-specific fields
    subsystem_fields: dict = field(default_factory=dict)  # Dynamic fields per subsystem
    
    # WAF/Web Filter specific
    url: str = ""
    response_code: int = 0
    reason: str = ""
    
    # IPS/IDS specific
    rule_id: str = ""
    rule_name: str = ""
    attack_type: str = ""
    
    # VPN specific
    vpn_user: str = ""
    vpn_hub: str = ""
    vpn_protocol: str = ""
    vpn_bytes_in: int = 0
    vpn_bytes_out: int = 0
    vpn_session_id: str = ""
    
    # Mail/DLP specific
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    attachment_count: int = 0
    file_hash: str = ""
    dlp_category: str = ""
    
    # Proxy/Web specific
    request_method: str = ""
    user_agent: str = ""
    referer: str = ""
    content_type: str = ""
    
    # DNS specific
    dns_query: str = ""
    dns_response: str = ""
    query_type: str = ""
    
    # AV/Sandbox specific
    malware_name: str = ""
    malware_family: str = ""
    detection_method: str = ""
    sandbox_verdict: str = ""
    
    # DDoS specific
    attack_vector: str = ""
    packets_dropped: int = 0
    bandwidth_consumed: float = 0.0
    
    # Firewall specific
    firewall_policy: str = ""
    firewall_zone_from: str = ""
    firewall_zone_to: str = ""


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
    
    # Subsystem-specific field mappings
    SUBSYSTEM_FIELD_MAPPINGS = {
        'waf': {
            'url': ['uri', 'path', 'request_uri'],
            'response_code': ['http_code', 'status_code', 'response_status'],
            'reason': ['block_reason', 'violation_reason', 'rule_match'],
            'request_method': ['method', 'http_method'],
            'user_agent': ['agent', 'browser'],
            'attack_type': ['attack', 'violation_type', 'threat_type'],
        },
        'webfilter': {
            'url': ['uri', 'domain', 'destination_url'],
            'response_code': ['http_code', 'status_code'],
            'reason': ['filter_reason', 'category', 'block_reason'],
            'content_type': ['mime_type', 'content_category'],
            'referer': ['referrer', 'ref'],
        },
        'ips': {
            'rule_id': ['rule', 'rule_number', 'sig_id'],
            'rule_name': ['rule_name', 'signature', 'threat_name'],
            'attack_type': ['attack_type', 'classification', 'threat_type'],
            'severity': ['threat_level', 'alert_severity'],
        },
        'vpn': {
            'vpn_user': ['user', 'login_user', 'authenticated_user'],
            'vpn_hub': ['hub', 'gateway', 'vpn_gateway'],
            'vpn_protocol': ['protocol', 'vpn_protocol', 'tunnel_type'],
            'vpn_bytes_in': ['bytes_in', 'data_in', 'ingress_bytes'],
            'vpn_bytes_out': ['bytes_out', 'data_out', 'egress_bytes'],
            'vpn_session_id': ['session_id', 'tunnel_id', 'connection_id'],
        },
        'mail': {
            'sender': ['from', 'sender', 'mail_from'],
            'recipient': ['to', 'recipient', 'mail_to'],
            'subject': ['subject', 'mail_subject'],
            'attachment_count': ['attachments', 'file_count'],
            'dlp_category': ['category', 'content_category', 'mail_category'],
        },
        'dlp': {
            'sender': ['source_user', 'user', 'from_user'],
            'recipient': ['dest_user', 'to_user'],
            'file_hash': ['hash', 'file_hash', 'md5'],
            'dlp_category': ['category', 'data_type', 'policy_name'],
            'attachment_count': ['file_count', 'attachment_count'],
        },
        'proxy': {
            'url': ['destination_url', 'uri', 'host'],
            'request_method': ['method', 'http_method'],
            'user_agent': ['agent', 'browser', 'user_agent'],
            'referer': ['referrer', 'ref'],
            'content_type': ['mime_type', 'content_type'],
        },
        'dns': {
            'dns_query': ['query', 'domain', 'query_name'],
            'dns_response': ['response', 'answer', 'resolved_ip'],
            'query_type': ['type', 'record_type', 'query_type'],
        },
        'sandbox': {
            'malware_name': ['malware', 'threat_name', 'detected_malware'],
            'malware_family': ['family', 'malware_family', 'variant'],
            'detection_method': ['method', 'detection_method', 'analyzer'],
            'sandbox_verdict': ['verdict', 'result', 'analysis_result'],
            'file_hash': ['hash', 'md5', 'sha256'],
        },
        'antivirus': {
            'malware_name': ['virus', 'threat_name', 'malware_name'],
            'malware_family': ['family', 'variant'],
            'detection_method': ['engine', 'scanner', 'detection_type'],
            'file_hash': ['hash', 'file_hash'],
        },
        'ddos': {
            'attack_vector': ['vector', 'attack_type', 'method'],
            'packets_dropped': ['dropped_packets', 'blocked_packets'],
            'bandwidth_consumed': ['bandwidth', 'traffic_volume', 'bps'],
            'attack_type': ['attack_type', 'ddos_type'],
        },
        'firewall': {
            'firewall_policy': ['policy', 'policy_name', 'rule_set'],
            'firewall_zone_from': ['src_zone', 'from_zone', 'ingress_zone'],
            'firewall_zone_to': ['dst_zone', 'to_zone', 'egress_zone'],
        },
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
        """Parse a single raw event string into SecurityEvent with subsystem-specific handling"""
        event = SecurityEvent()
        event.raw_data = {}
        
        # Find all key=value pairs
        matches = self.kv_pattern.findall(raw_event)
        
        # First pass: get subsystem to know which specific fields to extract
        temp_subsystem = None
        for match in matches:
            key = match[0].lower()
            value = match[1] or match[2] or match[3]
            normalized_key = self.FIELD_MAPPINGS.get(key, key)
            if normalized_key == 'subsystem':
                temp_subsystem = value.lower()
                break
        
        # Second pass: parse all fields and apply subsystem-specific mappings
        for match in matches:
            key = match[0].lower()
            value = match[1] or match[2] or match[3]
            
            # Normalize field name
            normalized_key = self.FIELD_MAPPINGS.get(key, key)
            event.raw_data[normalized_key] = value
            
            # Set standard typed fields
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
            
            # Apply subsystem-specific field mappings
            if event.subsystem and event.subsystem in self.SUBSYSTEM_FIELD_MAPPINGS:
                subsys_mappings = self.SUBSYSTEM_FIELD_MAPPINGS[event.subsystem]
                
                # Check if this key matches any subsystem-specific field aliases
                for field_name, aliases in subsys_mappings.items():
                    if key in aliases or normalized_key in aliases:
                        # Parse and set the field based on type
                        self._set_subsystem_field(event, field_name, value, event.subsystem)
                        # Also store in generic subsystem_fields dict
                        event.subsystem_fields[field_name] = value
        
        # Extract action from content if not present
        if not event.action and event.content:
            content_lower = event.content.lower()
            for action in self.KNOWN_ACTIONS:
                if action in content_lower:
                    event.action = action
                    break
        
        return event
    
    def _set_subsystem_field(self, event: SecurityEvent, field_name: str, value: str, subsystem: str):
        """Set subsystem-specific fields with type conversion"""
        try:
            if field_name == 'url':
                event.url = value
            elif field_name == 'response_code':
                event.response_code = int(value) if value.isdigit() else 0
            elif field_name == 'reason':
                event.reason = value
            elif field_name == 'rule_id':
                event.rule_id = value
            elif field_name == 'rule_name':
                event.rule_name = value
            elif field_name == 'attack_type':
                event.attack_type = value
            elif field_name == 'vpn_user':
                event.vpn_user = value
            elif field_name == 'vpn_hub':
                event.vpn_hub = value
            elif field_name == 'vpn_protocol':
                event.vpn_protocol = value
            elif field_name == 'vpn_bytes_in':
                event.vpn_bytes_in = int(value) if value.isdigit() else 0
            elif field_name == 'vpn_bytes_out':
                event.vpn_bytes_out = int(value) if value.isdigit() else 0
            elif field_name == 'vpn_session_id':
                event.vpn_session_id = value
            elif field_name == 'sender':
                event.sender = value
            elif field_name == 'recipient':
                event.recipient = value
            elif field_name == 'subject':
                event.subject = value
            elif field_name == 'attachment_count':
                event.attachment_count = int(value) if value.isdigit() else 0
            elif field_name == 'file_hash':
                event.file_hash = value
            elif field_name == 'dlp_category':
                event.dlp_category = value
            elif field_name == 'request_method':
                event.request_method = value
            elif field_name == 'user_agent':
                event.user_agent = value
            elif field_name == 'referer':
                event.referer = value
            elif field_name == 'content_type':
                event.content_type = value
            elif field_name == 'dns_query':
                event.dns_query = value
            elif field_name == 'dns_response':
                event.dns_response = value
            elif field_name == 'query_type':
                event.query_type = value
            elif field_name == 'malware_name':
                event.malware_name = value
            elif field_name == 'malware_family':
                event.malware_family = value
            elif field_name == 'detection_method':
                event.detection_method = value
            elif field_name == 'sandbox_verdict':
                event.sandbox_verdict = value
            elif field_name == 'attack_vector':
                event.attack_vector = value
            elif field_name == 'packets_dropped':
                event.packets_dropped = int(value) if value.isdigit() else 0
            elif field_name == 'bandwidth_consumed':
                event.bandwidth_consumed = float(value) if self._is_float(value) else 0.0
            elif field_name == 'firewall_policy':
                event.firewall_policy = value
            elif field_name == 'firewall_zone_from':
                event.firewall_zone_from = value
            elif field_name == 'firewall_zone_to':
                event.firewall_zone_to = value
        except Exception:
            pass  # Silently skip conversion errors
    
    def _is_float(self, value: str) -> bool:
        """Check if string can be converted to float"""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
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
        """Convert a SecurityEvent to a feature vector, including subsystem-specific fields"""
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
        
        # Subsystem-specific features (varies by subsystem)
        subsys_features = self._extract_subsystem_features(event)
        features.extend(subsys_features)
        
        return features
    
    def _extract_subsystem_features(self, event: SecurityEvent) -> list[float]:
        """Extract subsystem-specific numerical features"""
        features = []
        
        if event.subsystem == 'waf' or event.subsystem == 'webfilter':
            # URL length (normalized)
            url_len = min(len(event.url) / 200.0, 1.0) if event.url else 0.0
            features.append(url_len)
            # Response code (normalized by 500)
            response_norm = min(event.response_code / 500.0, 1.0) if event.response_code > 0 else 0.0
            features.append(response_norm)
            # Has reason
            features.append(1.0 if event.reason else 0.0)
            # HTTP method encoding: GET=0, POST=1, PUT=2, DELETE=3, OTHER=4
            method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3}
            method_val = method_map.get(event.request_method.upper(), 4) / 4.0 if event.request_method else 0.0
            features.append(method_val)
            
        elif event.subsystem == 'ips':
            # Rule ID hash (converted to feature)
            rule_hash = float(hash(event.rule_id) % 256) / 255.0 if event.rule_id else 0.0
            features.append(rule_hash)
            # Has rule name
            features.append(1.0 if event.rule_name else 0.0)
            # Attack type length
            attack_len = min(len(event.attack_type) / 50.0, 1.0) if event.attack_type else 0.0
            features.append(attack_len)
            
        elif event.subsystem == 'vpn':
            # VPN bytes in (normalized, log scale)
            vpn_bytes_in = min(np.log1p(event.vpn_bytes_in) / 20.0, 1.0) if event.vpn_bytes_in > 0 else 0.0
            features.append(vpn_bytes_in)
            # VPN bytes out (normalized, log scale)
            vpn_bytes_out = min(np.log1p(event.vpn_bytes_out) / 20.0, 1.0) if event.vpn_bytes_out > 0 else 0.0
            features.append(vpn_bytes_out)
            # Has VPN user
            features.append(1.0 if event.vpn_user else 0.0)
            # Has VPN hub
            features.append(1.0 if event.vpn_hub else 0.0)
            # VPN protocol type: IPSec=0, SSL=1, L2TP=2, OTHER=3
            proto_map = {'IPSEC': 0, 'SSL': 1, 'L2TP': 2}
            proto_val = proto_map.get(event.vpn_protocol.upper(), 3) / 3.0 if event.vpn_protocol else 0.0
            features.append(proto_val)
            
        elif event.subsystem == 'mail' or event.subsystem == 'dlp':
            # Has sender
            features.append(1.0 if event.sender else 0.0)
            # Has recipient
            features.append(1.0 if event.recipient else 0.0)
            # Subject length
            subj_len = min(len(event.subject) / 200.0, 1.0) if event.subject else 0.0
            features.append(subj_len)
            # Attachment count (normalized)
            attach_norm = min(event.attachment_count / 20.0, 1.0) if event.attachment_count > 0 else 0.0
            features.append(attach_norm)
            # Has file hash
            features.append(1.0 if event.file_hash else 0.0)
            
        elif event.subsystem == 'proxy':
            # URL length
            url_len = min(len(event.url) / 200.0, 1.0) if event.url else 0.0
            features.append(url_len)
            # User agent type: Mobile=0, Bot=1, Browser=2, OTHER=3
            ua_lower = event.user_agent.lower() if event.user_agent else ""
            ua_type = 0 if 'mobile' in ua_lower else (1 if 'bot' in ua_lower else (2 if 'mozilla' in ua_lower or 'chrome' in ua_lower else 3))
            features.append(ua_type / 3.0)
            # Has referer
            features.append(1.0 if event.referer else 0.0)
            # Content type encoding
            ct_lower = event.content_type.lower() if event.content_type else ""
            ct_type = (0 if 'html' in ct_lower else (1 if 'json' in ct_lower else (2 if 'image' in ct_lower else (3 if 'video' in ct_lower else 4))))
            features.append(ct_type / 4.0)
            
        elif event.subsystem == 'dns':
            # DNS query length
            query_len = min(len(event.dns_query) / 100.0, 1.0) if event.dns_query else 0.0
            features.append(query_len)
            # Has DNS response
            features.append(1.0 if event.dns_response else 0.0)
            # Query type: A=0, AAAA=1, MX=2, TXT=3, NS=4, OTHER=5
            qt_map = {'A': 0, 'AAAA': 1, 'MX': 2, 'TXT': 3, 'NS': 4}
            query_type_val = qt_map.get(event.query_type.upper(), 5) / 5.0 if event.query_type else 0.0
            features.append(query_type_val)
            
        elif event.subsystem == 'sandbox' or event.subsystem == 'antivirus':
            # Has malware name
            features.append(1.0 if event.malware_name else 0.0)
            # Malware family length
            family_len = min(len(event.malware_family) / 50.0, 1.0) if event.malware_family else 0.0
            features.append(family_len)
            # Detection method type: Engine=0, Heuristic=1, Signature=2, OTHER=3
            dm_lower = event.detection_method.lower() if event.detection_method else ""
            dm_type = (0 if 'engine' in dm_lower else (1 if 'heuristic' in dm_lower else (2 if 'signature' in dm_lower else 3)))
            features.append(dm_type / 3.0)
            # Has file hash
            features.append(1.0 if event.file_hash else 0.0)
            
        elif event.subsystem == 'ddos':
            # Attack vector type: Volumetric=0, Protocol=1, Application=2, OTHER=3
            av_lower = event.attack_vector.lower() if event.attack_vector else ""
            av_type = (0 if 'volumetric' in av_lower else (1 if 'protocol' in av_lower else (2 if 'application' in av_lower else 3)))
            features.append(av_type / 3.0)
            # Packets dropped (normalized log scale)
            packets_norm = min(np.log1p(event.packets_dropped) / 20.0, 1.0) if event.packets_dropped > 0 else 0.0
            features.append(packets_norm)
            # Bandwidth consumed (normalized log scale)
            bw_norm = min(np.log1p(event.bandwidth_consumed) / 15.0, 1.0) if event.bandwidth_consumed > 0 else 0.0
            features.append(bw_norm)
            
        elif event.subsystem == 'firewall':
            # Firewall policy length
            policy_len = min(len(event.firewall_policy) / 100.0, 1.0) if event.firewall_policy else 0.0
            features.append(policy_len)
            # Has zone info
            features.append(1.0 if event.firewall_zone_from else 0.0)
            features.append(1.0 if event.firewall_zone_to else 0.0)
            # Zone pair encoding (simple hash)
            zone_pair = f"{event.firewall_zone_from}-{event.firewall_zone_to}"
            zone_hash = float(hash(zone_pair) % 256) / 255.0 if zone_pair != "-" else 0.0
            features.append(zone_hash)
        
        # Ensure we always return at least some padding if new subsystem
        if len(features) == 0:
            features = [0.0] * 10  # Padding for unknown subsystems
        
        return features
    
    def get_feature_dim(self) -> int:
        """Return the dimension of feature vectors"""
        # Base: 5+5+8+15+4+1+4+6+1+1 = 50
        # Subsystem-specific: varies, estimate max ~12 per subsystem
        # Total: ~62
        return 62


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

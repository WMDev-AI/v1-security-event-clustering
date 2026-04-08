"""
Security Event Parser for Semi-Structured Log Data
Handles key=value format events from various security subsystems with subsystem-specific field extraction
"""
import re
import numpy as np
import hashlib
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
    rule: str = ""
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

    # New schema-aligned subsystem fields
    ddos_attack_type: str = ""
    ddos_ip: str = ""
    ddos_direction: str = ""
    ddos_status: str = ""
    ddos_count: int = 0
    ddos_pps: int = 0
    ddos_mbps: int = 0

    fw_count: int = 0
    fw_len: int = 0
    fw_ttl: int = 0
    fw_tos: int = 0
    fw_initf: str = ""
    fw_outitf: str = ""

    ips_groupid: str = ""
    ips_reason: str = ""
    ips_alertcount: int = 0
    ips_dropcount: int = 0

    app_count: int = 0
    app_len: int = 0
    app_ttl: int = 0
    app_tos: int = 0
    app_initf: str = ""
    app_outitf: str = ""
    app_mark: str = ""

    waf_client: str = ""
    waf_server: str = ""
    waf_vhost: str = ""
    waf_count: int = 0

    mail_id: int = 0
    mail_severity: str = ""
    mail_sys: str = ""
    mail_sub: str = ""
    mail_type: int = 0
    mail_from: str = ""
    mail_to: str = ""
    mail_srcuser: str = ""
    mail_srcdomain: str = ""
    mail_dstuser: str = ""
    mail_dstdomain: str = ""
    mail_size: int = 0
    mail_extra: str = ""

    vpn_srcuser: str = ""
    vpn_connection: str = ""
    vpn_dstuser: str = ""
    vpn_count: int = 0


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
        'rule': 'rule',
        'act': 'action',
        'event_action': 'action',
        'sev': 'severity',
        'level': 'severity',
        'priority': 'severity',
        'username': 'user',
        'usr': 'user',
        'account': 'user',
        'serverity': 'mail_severity',
    }
    
    # Subsystem-specific field mappings
    SUBSYSTEM_FIELD_MAPPINGS = {
        'webfilter': {
            'url': ['uri', 'domain', 'destination_url'],
            'response_code': ['http_code', 'status_code'],
            'reason': ['filter_reason', 'category', 'block_reason'],
            'content_type': ['mime_type', 'content_category'],
            'referer': ['referrer', 'ref'],
        },
        'ips': {
            'ips_groupid': ['groupid'],
            'ips_reason': ['reason'],
            'ips_alertcount': ['alertcount'],
            'ips_dropcount': ['dropcount'],
        },
        'vpn': {
            'vpn_hub': ['hub'],
            'vpn_srcuser': ['srcuser'],
            'vpn_connection': ['connection'],
            'vpn_dstuser': ['dstuser'],
            'vpn_count': ['count'],
        },
        'mail': {
            'mail_id': ['id'],
            'mail_severity': ['serverity', 'severity'],
            'mail_sys': ['sys'],
            'mail_sub': ['sub'],
            'mail_type': ['type'],
            'mail_from': ['from'],
            'mail_to': ['to'],
            'subject': ['subject'],
            'mail_srcuser': ['srcuser'],
            'mail_srcdomain': ['srcdomain'],
            'mail_dstuser': ['dstuser'],
            'mail_dstdomain': ['dstdomain'],
            'mail_size': ['size'],
            'mail_extra': ['extra'],
        },
        'ddos': {
            'ddos_attack_type': ['attacktype'],
            'ddos_ip': ['ip'],
            'ddos_direction': ['direction'],
            'ddos_status': ['status'],
            'ddos_count': ['count'],
            'ddos_pps': ['pps'],
            'ddos_mbps': ['mbps'],
        },
        'firewall': {
            'fw_count': ['count'],
            'fw_len': ['len'],
            'fw_ttl': ['ttl'],
            'fw_tos': ['tos'],
            'fw_initf': ['initf'],
            'fw_outitf': ['outitf'],
        },
        'appcontrol': {
            'app_count': ['count'],
            'app_len': ['len'],
            'app_ttl': ['ttl'],
            'app_tos': ['tos'],
            'app_initf': ['initf'],
            'app_outitf': ['outitf'],
            'app_mark': ['mark'],
        },
        'websec': {
            'content': ['content'],
        },
        'waf': {
            'reason': ['reason'],
            'waf_client': ['client'],
            'waf_server': ['server'],
            'waf_vhost': ['vhost'],
            'waf_count': ['count'],
        },
    }
    
    # Known subsystems for one-hot encoding
    KNOWN_SUBSYSTEMS = [
        'ddos', 'firewall', 'ips', 'appcontrol', 'waf', 'websec', 'mail', 'vpn',
        'webfilter', 'proxy', 'dns', 'antivirus', 'sandbox', 'dlp', 'nat', 'router', 'auth'
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

    # Content keyword groups for semantic threat signal extraction
    CONTENT_KEYWORD_GROUPS = [
        # Auth and credential abuse
        ['brute', 'password', 'credential', 'login', 'authentication', 'failed login', 'account lockout'],
        # Malware and payload execution
        ['malware', 'trojan', 'ransomware', 'shellcode', 'payload', 'dropper', 'virus'],
        # Reconnaissance and scanning
        ['scan', 'probe', 'recon', 'enumeration', 'port sweep', 'discovery'],
        # Exfiltration / data movement
        ['exfiltration', 'data leak', 'data transfer', 'download', 'upload', 'staging'],
        # Web attack patterns
        ['sql injection', 'xss', 'csrf', 'directory traversal', 'command injection', 'owasp'],
        # C2 / persistence / lateral movement hints
        ['beacon', 'command and control', 'c2', 'persistence', 'lateral movement', 'privilege escalation'],
    ]
    
    def __init__(self):
        # Regex for parsing key=value pairs, including "key"="value" style.
        self.kv_pattern = re.compile(
            r"(?:\"([^\"]+)\"|(\w+))=(?:\"([^\"]*)\"|'([^']*)'|(\S+))"
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
            key = (match[0] or match[1]).lower()
            value = match[2] or match[3] or match[4]
            normalized_key = self.FIELD_MAPPINGS.get(key, key)
            if normalized_key == 'subsystem':
                temp_subsystem = value.lower()
                break
        
        # Second pass: parse all fields and apply subsystem-specific mappings
        for match in matches:
            key = (match[0] or match[1]).lower()
            value = match[2] or match[3] or match[4]
            
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
            elif normalized_key == 'rule':
                event.rule = value
            elif normalized_key == 'mail_severity':
                event.mail_severity = value.lower()
            
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
            elif field_name == 'ddos_attack_type':
                event.ddos_attack_type = value
            elif field_name == 'ddos_ip':
                event.ddos_ip = value
            elif field_name == 'ddos_direction':
                event.ddos_direction = value.lower()
            elif field_name == 'ddos_status':
                event.ddos_status = value.lower()
            elif field_name == 'ddos_count':
                event.ddos_count = int(value) if value.isdigit() else 0
            elif field_name == 'ddos_pps':
                event.ddos_pps = int(value) if value.isdigit() else 0
            elif field_name == 'ddos_mbps':
                event.ddos_mbps = int(value) if value.isdigit() else 0
            elif field_name == 'fw_count':
                event.fw_count = int(value) if value.isdigit() else 0
            elif field_name == 'fw_len':
                event.fw_len = int(value) if value.isdigit() else 0
            elif field_name == 'fw_ttl':
                event.fw_ttl = int(value) if value.isdigit() else 0
            elif field_name == 'fw_tos':
                event.fw_tos = int(value) if value.isdigit() else 0
            elif field_name == 'fw_initf':
                event.fw_initf = value
            elif field_name == 'fw_outitf':
                event.fw_outitf = value
            elif field_name == 'ips_groupid':
                event.ips_groupid = value
            elif field_name == 'ips_reason':
                event.ips_reason = value
            elif field_name == 'ips_alertcount':
                event.ips_alertcount = int(value) if value.isdigit() else 0
            elif field_name == 'ips_dropcount':
                event.ips_dropcount = int(value) if value.isdigit() else 0
            elif field_name == 'app_count':
                event.app_count = int(value) if value.isdigit() else 0
            elif field_name == 'app_len':
                event.app_len = int(value) if value.isdigit() else 0
            elif field_name == 'app_ttl':
                event.app_ttl = int(value) if value.isdigit() else 0
            elif field_name == 'app_tos':
                event.app_tos = int(value) if value.isdigit() else 0
            elif field_name == 'app_initf':
                event.app_initf = value
            elif field_name == 'app_outitf':
                event.app_outitf = value
            elif field_name == 'app_mark':
                event.app_mark = value
            elif field_name == 'waf_client':
                event.waf_client = value
            elif field_name == 'waf_server':
                event.waf_server = value
            elif field_name == 'waf_vhost':
                event.waf_vhost = value
            elif field_name == 'waf_count':
                event.waf_count = int(value) if value.isdigit() else 0
            elif field_name == 'mail_id':
                event.mail_id = int(value) if value.isdigit() else 0
            elif field_name == 'mail_severity':
                event.mail_severity = value.lower()
            elif field_name == 'mail_sys':
                event.mail_sys = value
            elif field_name == 'mail_sub':
                event.mail_sub = value
            elif field_name == 'mail_type':
                event.mail_type = int(value) if value.isdigit() else 0
            elif field_name == 'mail_from':
                event.mail_from = value
            elif field_name == 'mail_to':
                event.mail_to = value
            elif field_name == 'mail_srcuser':
                event.mail_srcuser = value
            elif field_name == 'mail_srcdomain':
                event.mail_srcdomain = value
            elif field_name == 'mail_dstuser':
                event.mail_dstuser = value
            elif field_name == 'mail_dstdomain':
                event.mail_dstdomain = value
            elif field_name == 'mail_size':
                event.mail_size = int(value) if value.isdigit() else 0
            elif field_name == 'mail_extra':
                event.mail_extra = value
            elif field_name == 'vpn_srcuser':
                event.vpn_srcuser = value
            elif field_name == 'vpn_connection':
                event.vpn_connection = value
            elif field_name == 'vpn_dstuser':
                event.vpn_dstuser = value
            elif field_name == 'vpn_count':
                event.vpn_count = int(value) if value.isdigit() else 0
        except Exception:
            pass  # Silently skip conversion errors
    
    def _is_float(self, value: str) -> bool:
        """Check if string can be converted to float"""
        try:
            float(value)
            return True
        except ValueError:
            return False

    def _stable_hash_to_unit(self, value: str, modulo: int = 4096) -> float:
        """Deterministic hash to [0, 1] for stable categorical projection."""
        if not value:
            return 0.0
        digest = hashlib.md5(value.encode('utf-8', errors='ignore')).hexdigest()
        bucket = int(digest, 16) % modulo
        return float(bucket) / float(modulo - 1)
    
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
            
            # Cyclic hour features are more expressive than raw normalized hour.
            hour_angle = (2.0 * np.pi * dt.hour) / 24.0
            hour_sin = float(np.sin(hour_angle))
            hour_cos = float(np.cos(hour_angle))
            day_of_week = dt.weekday() / 6.0
            is_business_hours = 1.0 if 9 <= dt.hour <= 17 else 0.0

            return [hour_sin, hour_cos, day_of_week, is_business_hours]
        except Exception:
            return [0.0, 0.0, 0.0, 0.0]

    def content_to_features(self, content: str) -> list[float]:
        """Extract compact semantic threat features from event content."""
        if not content:
            return [0.0] * (len(self.CONTENT_KEYWORD_GROUPS) + 2)

        c = content.lower()
        token_count = len(c.split())
        exclamation_density = min(c.count('!') / 5.0, 1.0)
        keyword_group_hits = []

        for group in self.CONTENT_KEYWORD_GROUPS:
            hit = 1.0 if any(k in c for k in group) else 0.0
            keyword_group_hits.append(hit)

        token_feature = min(token_count / 80.0, 1.0)
        return keyword_group_hits + [token_feature, exclamation_density]
    
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

        # Semantic content features (keyword groups + structure hints)
        features.extend(self.content_to_features(event.content))
        
        # Subsystem-specific features (varies by subsystem)
        subsys_features = self._extract_subsystem_features(event)
        features.extend(subsys_features)
        
        return features
    
    def _extract_subsystem_features(self, event: SecurityEvent) -> list[float]:
        """Extract subsystem-specific numerical features"""
        features = []
        
        if event.subsystem == 'webfilter':
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
            
        elif event.subsystem == 'ips_legacy':
            # Rule ID hash (converted to feature)
            rule_hash = self._stable_hash_to_unit(event.rule_id, modulo=1024)
            features.append(rule_hash)
            # Has rule name
            features.append(1.0 if event.rule_name else 0.0)
            # Attack type length
            attack_len = min(len(event.attack_type) / 50.0, 1.0) if event.attack_type else 0.0
            features.append(attack_len)
            
        elif event.subsystem == 'vpn_legacy':
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
            
        elif event.subsystem == 'dlp':
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
            at = event.ddos_attack_type.upper()
            at_val = 0.0 if at == "DOS" else (1.0 if at == "DDOS" else 0.5)
            features.append(at_val)
            features.append(1.0 if event.ddos_direction == 'in' else (0.0 if event.ddos_direction == 'out' else 0.5))
            features.append(1.0 if event.ddos_status == 'end' else 0.0)
            features.append(min(np.log1p(event.ddos_count) / 12.0, 1.0) if event.ddos_count > 0 else 0.0)
            features.append(min(np.log1p(event.ddos_pps) / 12.0, 1.0) if event.ddos_pps > 0 else 0.0)
            features.append(min(np.log1p(event.ddos_mbps) / 12.0, 1.0) if event.ddos_mbps > 0 else 0.0)
            
        elif event.subsystem == 'firewall':
            features.append(min(np.log1p(event.fw_count) / 10.0, 1.0) if event.fw_count > 0 else 0.0)
            features.append(min(event.fw_len / 9000.0, 1.0) if event.fw_len > 0 else 0.0)
            features.append(min(event.fw_ttl / 255.0, 1.0) if event.fw_ttl > 0 else 0.0)
            features.append(min(event.fw_tos / 255.0, 1.0) if event.fw_tos > 0 else 0.0)
            features.append(1.0 if event.fw_initf else 0.0)
            features.append(1.0 if event.fw_outitf else 0.0)
            features.append(self._stable_hash_to_unit(f"{event.fw_initf}->{event.fw_outitf}", modulo=1024))

        elif event.subsystem == 'ips':
            features.append(self._stable_hash_to_unit(event.ips_groupid, modulo=2048))
            features.append(1.0 if event.ips_reason else 0.0)
            features.append(min(np.log1p(event.ips_alertcount) / 10.0, 1.0) if event.ips_alertcount > 0 else 0.0)
            features.append(min(np.log1p(event.ips_dropcount) / 10.0, 1.0) if event.ips_dropcount > 0 else 0.0)

        elif event.subsystem == 'appcontrol':
            features.append(min(np.log1p(event.app_count) / 10.0, 1.0) if event.app_count > 0 else 0.0)
            features.append(min(event.app_len / 9000.0, 1.0) if event.app_len > 0 else 0.0)
            features.append(min(event.app_ttl / 255.0, 1.0) if event.app_ttl > 0 else 0.0)
            features.append(min(event.app_tos / 255.0, 1.0) if event.app_tos > 0 else 0.0)
            features.append(1.0 if event.app_initf else 0.0)
            features.append(1.0 if event.app_outitf else 0.0)
            features.append(self._stable_hash_to_unit(event.app_mark, modulo=1024))

        elif event.subsystem == 'waf':
            features.append(1.0 if event.reason else 0.0)
            features.append(1.0 if event.waf_client else 0.0)
            features.append(1.0 if event.waf_server else 0.0)
            features.append(1.0 if event.waf_vhost else 0.0)
            features.append(min(np.log1p(event.waf_count) / 10.0, 1.0) if event.waf_count > 0 else 0.0)

        elif event.subsystem == 'websec':
            features.extend(self.content_to_features(event.content)[:4])

        elif event.subsystem == 'mail':
            features.append(min(np.log1p(event.mail_id) / 10.0, 1.0) if event.mail_id > 0 else 0.0)
            features.append(1.0 if event.mail_severity in ('critical', 'high', 'warn', 'warning') else (0.5 if event.mail_severity else 0.0))
            features.append(1.0 if event.mail_sys else 0.0)
            features.append(1.0 if event.mail_sub else 0.0)
            features.append(min(np.log1p(event.mail_type) / 8.0, 1.0) if event.mail_type > 0 else 0.0)
            features.append(1.0 if event.mail_from else 0.0)
            features.append(1.0 if event.mail_to else 0.0)
            features.append(min(np.log1p(event.mail_size) / 15.0, 1.0) if event.mail_size > 0 else 0.0)

        elif event.subsystem == 'vpn':
            is_virtualfirewall = 1.0 if event.rule.lower() == 'virtualfirewall' else 0.0
            is_accesslist = 1.0 if event.rule.lower() == 'accesslist' else 0.0
            features.append(is_virtualfirewall)
            features.append(is_accesslist)
            features.append(1.0 if event.vpn_hub else 0.0)
            features.append(1.0 if event.vpn_srcuser else 0.0)
            features.append(1.0 if event.vpn_connection else 0.0)
            features.append(1.0 if event.vpn_dstuser else 0.0)
            features.append(min(np.log1p(event.vpn_count) / 10.0, 1.0) if event.vpn_count > 0 else 0.0)
        
        # Pad all subsystem features to exactly 12 dimensions for consistency
        # This ensures all feature vectors are the same length (50 base + 12 subsystem = 62 total)
        while len(features) < 12:
            features.append(0.0)
        
        # Trim to 12 if somehow exceeded (shouldn't happen, but safety check)
        if len(features) > 12:
            features = features[:12]
        
        return features
    
    def get_feature_dim(self) -> int:
        """Return the dimension of feature vectors"""
        # Base: 5+5+8+15+4+1+4+6+1+1 + (6 keyword groups + 2 content structure) = 58
        # Subsystem-specific: fixed to 12
        # Total: 70
        return 70


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

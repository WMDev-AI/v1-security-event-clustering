"""
Sample Security Event Generator for Testing
Generates realistic security events for demonstration purposes
"""
import random
from datetime import datetime, timedelta
from typing import Generator

# Configuration
SUBSYSTEMS = ['firewall', 'ips', 'ddos', 'waf', 'webfilter', 'mail', 'vpn', 'dns', 'proxy', 'antivirus']
ACTIONS = ['allow', 'block', 'drop', 'alert', 'quarantine', 'log']
SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SMTP', 'SSH', 'RDP']

# IP ranges
INTERNAL_IPS = ['192.168.1.', '10.0.0.', '172.16.0.']
EXTERNAL_IPS = ['203.0.113.', '198.51.100.', '8.8.8.', '1.1.1.', '185.220.101.']
MALICIOUS_IPS = ['45.33.32.', '185.220.101.', '89.163.247.', '193.56.28.']

# Common ports
COMMON_PORTS = [22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443]
SUSPICIOUS_PORTS = [4444, 5555, 6666, 31337, 12345]

# Users
USERS = ['admin', 'john.doe', 'jane.smith', 'guest', 'service_account', 'backup_user', 'developer', 'analyst', '']

# Event content templates
CONTENT_TEMPLATES = {
    'firewall': [
        'Connection established',
        'Connection blocked by policy',
        'Rate limit exceeded',
        'Invalid packet dropped',
        'Port scan detected',
        'Unusual traffic pattern'
    ],
    'ips': [
        'Signature match: SQL injection attempt',
        'Signature match: XSS attack detected',
        'Brute force attack detected',
        'Buffer overflow attempt blocked',
        'Command injection detected',
        'Path traversal attempt'
    ],
    'ddos': [
        'SYN flood attack mitigated',
        'UDP amplification attack blocked',
        'HTTP flood detected',
        'Slowloris attack mitigated',
        'DNS amplification blocked',
        'ICMP flood detected'
    ],
    'waf': [
        'SQL injection blocked',
        'XSS attempt blocked',
        'CSRF token violation',
        'Remote file inclusion blocked',
        'Local file inclusion blocked',
        'HTTP parameter pollution'
    ],
    'webfilter': [
        'Malware site blocked',
        'Phishing URL blocked',
        'Adult content filtered',
        'Gambling site blocked',
        'Social media restricted',
        'Streaming site limited'
    ],
    'mail': [
        'Spam email detected',
        'Phishing email quarantined',
        'Malicious attachment blocked',
        'SPF check failed',
        'DKIM verification failed',
        'Suspicious sender blocked'
    ],
    'vpn': [
        'VPN tunnel established',
        'Authentication successful',
        'Authentication failed',
        'Session timeout',
        'Invalid certificate',
        'Policy violation detected'
    ],
    'dns': [
        'DNS query resolved',
        'DNS query blocked (malware domain)',
        'DNS tunneling detected',
        'NXDOMAIN for suspicious domain',
        'High query rate detected',
        'DNS cache poisoning attempt'
    ],
    'proxy': [
        'Request forwarded',
        'Request blocked by policy',
        'Content filtered',
        'Bandwidth limit reached',
        'Anonymous proxy detected',
        'SSL inspection performed'
    ],
    'antivirus': [
        'Malware detected and quarantined',
        'Virus signature matched',
        'Suspicious file blocked',
        'Ransomware activity detected',
        'Trojan removed',
        'Clean scan completed'
    ]
}


def generate_ip(ip_type: str = 'random') -> str:
    """Generate an IP address"""
    if ip_type == 'internal':
        base = random.choice(INTERNAL_IPS)
    elif ip_type == 'malicious':
        base = random.choice(MALICIOUS_IPS)
    elif ip_type == 'external':
        base = random.choice(EXTERNAL_IPS)
    else:
        base = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    return base + str(random.randint(1, 254))


def generate_event(timestamp: datetime, event_type: str = 'random') -> str:
    """Generate a single security event"""
    subsys = random.choice(SUBSYSTEMS) if event_type == 'random' else event_type
    
    # Determine action and severity based on subsystem
    if subsys in ['ips', 'ddos', 'waf']:
        action = random.choice(['block', 'alert', 'drop'])
        severity = random.choices(['critical', 'high', 'medium', 'low'], weights=[0.1, 0.3, 0.4, 0.2])[0]
        src_ip = generate_ip('external' if random.random() > 0.3 else 'malicious')
        dst_ip = generate_ip('internal')
    elif subsys in ['firewall', 'proxy']:
        action = random.choices(['allow', 'block', 'drop', 'log'], weights=[0.5, 0.2, 0.1, 0.2])[0]
        severity = random.choices(['low', 'info', 'medium'], weights=[0.3, 0.5, 0.2])[0]
        src_ip = generate_ip('random')
        dst_ip = generate_ip('random')
    elif subsys == 'vpn':
        action = random.choices(['allow', 'block', 'log'], weights=[0.6, 0.2, 0.2])[0]
        severity = 'info' if action == 'allow' else 'medium'
        src_ip = generate_ip('external')
        dst_ip = generate_ip('internal')
    else:
        action = random.choice(ACTIONS)
        severity = random.choice(SEVERITIES)
        src_ip = generate_ip('random')
        dst_ip = generate_ip('random')
    
    # Ports
    if action in ['block', 'drop', 'alert']:
        dst_port = random.choice(SUSPICIOUS_PORTS + COMMON_PORTS[:7])
    else:
        dst_port = random.choice(COMMON_PORTS)
    
    src_port = random.randint(1024, 65535)
    
    # Protocol
    if dst_port in [80, 8080]:
        protocol = 'HTTP'
    elif dst_port in [443, 8443]:
        protocol = 'HTTPS'
    elif dst_port == 53:
        protocol = 'DNS'
    elif dst_port == 22:
        protocol = 'SSH'
    elif dst_port == 3389:
        protocol = 'RDP'
    else:
        protocol = random.choice(['TCP', 'UDP'])
    
    # User
    user = random.choice(USERS)
    
    # Content
    content = random.choice(CONTENT_TEMPLATES.get(subsys, ['Event logged']))
    
    # Build event string
    parts = [
        f"timestamp={timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"sourceip={src_ip}",
        f"destip={dst_ip}",
        f"srcport={src_port}",
        f"destport={dst_port}",
        f"proto={protocol}",
        f"subsys={subsys}",
        f"action={action}",
        f"severity={severity}",
    ]
    
    if user:
        parts.append(f"user={user}")
    
    parts.append(f"content='{content}'")
    
    return ' '.join(parts)


def generate_attack_cluster(
    timestamp: datetime,
    attack_type: str,
    source_ip: str,
    n_events: int = 50
) -> list[str]:
    """Generate a cluster of related attack events"""
    events = []
    
    attack_configs = {
        'bruteforce': {
            'subsys': 'ips',
            'ports': [22, 23, 3389],
            'actions': ['block', 'alert'],
            'contents': [
                'SSH brute force attempt',
                'Failed authentication',
                'Multiple login failures',
                'Password guessing detected'
            ]
        },
        'ddos': {
            'subsys': 'ddos',
            'ports': [80, 443],
            'actions': ['block', 'drop'],
            'contents': [
                'SYN flood detected',
                'Rate limit exceeded',
                'Traffic spike mitigated',
                'Connection flood blocked'
            ]
        },
        'webattack': {
            'subsys': 'waf',
            'ports': [80, 443, 8080],
            'actions': ['block', 'alert'],
            'contents': [
                'SQL injection attempt',
                'XSS payload detected',
                'Path traversal blocked',
                'Command injection attempt'
            ]
        },
        'malware': {
            'subsys': 'antivirus',
            'ports': [445, 139, 3389],
            'actions': ['quarantine', 'block', 'alert'],
            'contents': [
                'Ransomware activity detected',
                'Suspicious executable blocked',
                'C2 communication detected',
                'Lateral movement attempt'
            ]
        }
    }
    
    config = attack_configs.get(attack_type, attack_configs['webattack'])
    
    for i in range(n_events):
        ts = timestamp + timedelta(seconds=i * random.randint(1, 10))
        
        event = ' '.join([
            f"timestamp={ts.strftime('%Y-%m-%d %H:%M:%S')}",
            f"sourceip={source_ip}",
            f"destip={generate_ip('internal')}",
            f"destport={random.choice(config['ports'])}",
            f"subsys={config['subsys']}",
            f"action={random.choice(config['actions'])}",
            f"severity={random.choices(['critical', 'high'], weights=[0.3, 0.7])[0]}",
            f"content='{random.choice(config['contents'])}'"
        ])
        events.append(event)
    
    return events


def generate_dataset(
    n_events: int = 1000,
    include_attacks: bool = True,
    start_time: datetime = None
) -> list[str]:
    """Generate a complete dataset of security events"""
    if start_time is None:
        start_time = datetime.now() - timedelta(days=7)
    
    events = []
    
    # Generate normal background events
    normal_count = int(n_events * 0.7) if include_attacks else n_events
    
    for i in range(normal_count):
        ts = start_time + timedelta(
            minutes=random.randint(0, 60 * 24 * 7)  # Spread over a week
        )
        events.append(generate_event(ts))
    
    # Generate attack clusters
    if include_attacks:
        attack_events = n_events - normal_count
        
        # Brute force attack
        bf_events = attack_events // 4
        bf_source = generate_ip('malicious')
        bf_time = start_time + timedelta(days=random.randint(1, 5))
        events.extend(generate_attack_cluster(bf_time, 'bruteforce', bf_source, bf_events))
        
        # DDoS attack
        ddos_events = attack_events // 4
        ddos_source = generate_ip('malicious')
        ddos_time = start_time + timedelta(days=random.randint(1, 5))
        events.extend(generate_attack_cluster(ddos_time, 'ddos', ddos_source, ddos_events))
        
        # Web attack
        web_events = attack_events // 4
        web_source = generate_ip('malicious')
        web_time = start_time + timedelta(days=random.randint(1, 5))
        events.extend(generate_attack_cluster(web_time, 'webattack', web_source, web_events))
        
        # Malware
        mal_events = attack_events - bf_events - ddos_events - web_events
        mal_source = generate_ip('internal')  # Infected internal host
        mal_time = start_time + timedelta(days=random.randint(1, 5))
        events.extend(generate_attack_cluster(mal_time, 'malware', mal_source, mal_events))
    
    # Shuffle and return
    random.shuffle(events)
    return events


if __name__ == "__main__":
    # Generate sample dataset
    events = generate_dataset(500, include_attacks=True)
    
    print(f"Generated {len(events)} events")
    print("\nSample events:")
    for event in events[:10]:
        print(event)

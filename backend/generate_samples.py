"""Sample event generator aligned to the 8-subsystem schema."""

import random
from datetime import datetime, timedelta
from typing import Optional

SUBSYSTEMS = ["ddos", "firewall", "ips", "appcontrol", "waf", "websec", "mail", "vpn"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SMTP"]
ACTIONS = ["pass", "block"]
RULES = [
    "bannedextension",
    "bannedMIME",
    "site_unreachable",
    "virus",
    "spam",
    "shellcode_error",
    "neterror",
    "virtualfirewall",
    "accesslist",
]

INTERNAL_IPS = ["192.168.1.", "10.0.0.", "172.16.0."]
EXTERNAL_IPS = ["203.0.113.", "198.51.100.", "8.8.8.", "1.1.1."]
COMMON_PORTS = [22, 25, 53, 80, 443, 445, 3389, 8080, 8443]
IFACES = ["eth0", "eth1"]


def generate_ip(ip_type: str = "random") -> str:
    if ip_type == "internal":
        base = random.choice(INTERNAL_IPS)
    elif ip_type == "external":
        base = random.choice(EXTERNAL_IPS)
    else:
        base = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    return f"{base}{random.randint(1, 254)}"


def _q(value: str) -> str:
    return f"'{value}'"

def _kv(raw_pair: str) -> str:
    key, value = raw_pair.split("=", 1)
    v = value.strip()
    if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
        v = v[1:-1]
    v = v.replace('"', '\\"')
    return f"\"{key}\"=\"{v}\""


def _common_parts(
    timestamp: datetime,
    subsystem: str,
    rule: Optional[str] = None,
    source_ip_override: Optional[str] = None,
) -> list[str]:
    src_port = "" if random.random() < 0.1 else str(random.randint(1024, 65535))
    dst_port = "" if random.random() < 0.1 else str(random.choice(COMMON_PORTS))
    protocol = random.choice(PROTOCOLS)
    selected_rule = rule or random.choice(RULES)
    srcip_value = source_ip_override or generate_ip(
        "external" if subsystem in ("ddos", "waf", "ips", "websec") else "random"
    )
    return [
        f"timestamp={timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"subsys={subsystem}",
        f"proto={protocol}",
        f"srcip={srcip_value}",
        f"dstip={generate_ip('internal')}",
        f"srcport={src_port}",
        f"dstport={dst_port}",
        f"rule={selected_rule}",
        f"action={random.choice(ACTIONS)}",
    ]


def _ddos_fields() -> list[str]:
    common = [
        f"attacktype={random.choice(['DDoS', 'DoS'])}",
        f"ip={generate_ip('external')}",
        "status=end",
        f"count={random.randint(1, 10000)}",
    ]
    if random.random() < 0.5:
        return common + [f"direction={random.choice(['in', 'out'])}"]
    return common + [f"pps={random.randint(1000, 200000)}", f"mbps={random.randint(10, 4000)}"]


def _firewall_fields() -> list[str]:
    return [
        f"count={random.randint(1, 5000)}",
        f"len={random.randint(60, 9000)}",
        f"ttl={random.randint(1, 255)}",
        f"tos={random.randint(0, 255)}",
        f"initf={random.choice(IFACES)}",
        f"outitf={random.choice(IFACES)}",
    ]


def _ips_fields() -> list[str]:
    return [
        f"groupid={random.randint(1000, 9999)}",
        f"reason={_q(random.choice(['shellcode_error', 'overflow_attempt', 'sqli_pattern', 'xss_payload']))}",
        f"alertcount={random.randint(1, 200)}",
        f"dropcount={random.randint(0, 150)}",
    ]


def _appcontrol_fields() -> list[str]:
    return [
        f"count={random.randint(1, 3000)}",
        f"len={random.randint(60, 9000)}",
        f"ttl={random.randint(1, 255)}",
        f"tos={random.randint(0, 255)}",
        f"initf={random.choice(IFACES)}",
        f"outitf={random.choice(IFACES)}",
        f"mark=0x{random.randint(4096, 65535):x}",
    ]


def _waf_fields() -> list[str]:
    vhost = f"{generate_ip('internal')}:{random.choice([80, 443, 8080])}"
    return [
        f"reason={_q(random.choice(['banned extension', 'banned MIME', 'neterror', 'site_unreachable']))}",
        f"client={generate_ip('external')}",
        f"server={generate_ip('internal')}",
        f"vhost={_q(vhost)}",
        f"count={random.randint(1, 500)}",
    ]


def _websec_fields() -> list[str]:
    samples = [
        "http 34.2.34.1 http://3.4.2.3/test/1.jpg /Denied/Banned File Extension .jpg",
        "http 3.1.2.4 http://3.1.2.4/test/1.pdf /Denied/Banned File MIME type text/pdf",
        "http 3.1.2.4 http://3.1.2.4/work /NetError/The site requested is not responding",
    ]
    return [f"content={_q(random.choice(samples))}"]


def _mail_fields() -> list[str]:
    sender = random.choice(["alice@example.com", "it@corp.local", "alerts@securemail.local"])
    recipient = random.choice(["bob@example.com", "ops@corp.local", "admin@corp.local"])
    return [
        f"id={random.randint(1, 1000000)}",
        f"serverity={random.choice(['info', 'warn', 'high'])}",
        "sys=securemail",
        "sub=smtp",
        f"type={random.randint(1, 10)}",
        f"from={sender}",
        f"to={recipient}",
        f"subject={_q(random.choice(['Invoice update', 'Security warning', 'Delivery report']))}",
        f"srcuser={sender.split('@')[0]}",
        f"srcdomain={sender.split('@')[1]}",
        f"dstuser={recipient.split('@')[0]}",
        f"dstdomain={recipient.split('@')[1]}",
        f"size={random.randint(200, 5000000)}",
        f"extra={_q(random.choice(['attachment=none', 'spf=pass', 'dkim=fail']))}",
    ]


def _vpn_fields(rule: str) -> list[str]:
    base = [
        f"hub={_q(random.choice(['HQ-HUB', 'BRANCH-HUB']))}",
        f"srcuser={_q(random.choice(['john', 'jane', 'svc_vpn']))}",
        f"connection={_q(f'CID-{random.randint(100, 999)}')}",
        f"count={random.randint(1, 1000)}",
    ]
    if rule == "virtualfirewall":
        base.insert(3, f"dstuser={_q(random.choice(['remoteA', 'remoteB', 'remoteC']))}")
    return base


def generate_event(timestamp: datetime, event_type: str = "random", source_ip: Optional[str] = None) -> str:
    subsystem = random.choice(SUBSYSTEMS) if event_type == "random" else event_type
    rule = random.choice(["virtualfirewall", "accesslist"]) if subsystem == "vpn" else None
    parts = _common_parts(timestamp, subsystem, rule=rule, source_ip_override=source_ip)

    if subsystem == "ddos":
        parts.extend(_ddos_fields())
    elif subsystem == "firewall":
        parts.extend(_firewall_fields())
    elif subsystem == "ips":
        parts.extend(_ips_fields())
    elif subsystem == "appcontrol":
        parts.extend(_appcontrol_fields())
    elif subsystem == "waf":
        parts.extend(_waf_fields())
    elif subsystem == "websec":
        parts.extend(_websec_fields())
    elif subsystem == "mail":
        parts.extend(_mail_fields())
    elif subsystem == "vpn":
        parts.extend(_vpn_fields(rule or "accesslist"))

    return " ".join(_kv(p) for p in parts)


def generate_attack_cluster(timestamp: datetime, attack_type: str, source_ip: str, n_events: int = 50) -> list[str]:
    """Generate related events while preserving the new schema."""
    attack_to_subsystem = {
        "bruteforce": "ips",
        "ddos": "ddos",
        "webattack": "waf",
        "malware": "mail",
    }
    subsystem = attack_to_subsystem.get(attack_type, "waf")
    events: list[str] = []
    for i in range(n_events):
        ts = timestamp + timedelta(seconds=i * random.randint(1, 10))
        e = generate_event(ts, subsystem, source_ip=source_ip)
        events.append(e)
    return events


def generate_dataset(
    n_events: int = 1000,
    include_attacks: bool = True,
    start_time: Optional[datetime] = None,
) -> list[str]:
    if start_time is None:
        start_time = datetime.now() - timedelta(days=7)

    events: list[str] = []
    normal_count = int(n_events * 0.7) if include_attacks else n_events
    for _ in range(normal_count):
        ts = start_time + timedelta(minutes=random.randint(0, 60 * 24 * 7))
        events.append(generate_event(ts))

    if include_attacks:
        attack_events = n_events - normal_count
        bf_events = attack_events // 4
        ddos_events = attack_events // 4
        web_events = attack_events // 4
        mal_events = attack_events - bf_events - ddos_events - web_events
        events.extend(generate_attack_cluster(start_time + timedelta(days=1), "bruteforce", generate_ip("external"), bf_events))
        events.extend(generate_attack_cluster(start_time + timedelta(days=2), "ddos", generate_ip("external"), ddos_events))
        events.extend(generate_attack_cluster(start_time + timedelta(days=3), "webattack", generate_ip("external"), web_events))
        events.extend(generate_attack_cluster(start_time + timedelta(days=4), "malware", generate_ip("external"), mal_events))

    random.shuffle(events)
    return events


if __name__ == "__main__":
    sample = generate_dataset(5000, include_attacks=True)
    print(f"Generated {len(sample)} events")
    for event in sample:
        print(event)

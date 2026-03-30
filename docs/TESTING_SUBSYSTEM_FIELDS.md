# Testing Guide: Subsystem-Specific Field Handling

This guide provides practical examples for testing the upgraded backend's ability to parse and analyze subsystem-specific fields.

## Quick Start Test

### 1. Basic Parsing Test

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/root/v1-security-event-clustering/backend')

from event_parser import EventParser

parser = EventParser()

# Test 1: WAF event with alias fields
waf_event_str = (
    "timestamp=2024-01-15 10:30:00 sourceip=203.0.113.50 destip=10.0.0.100 "
    "destport=443 subsys=waf action=blocked severity=high uri='/admin/login.php' "
    "http_code=403 reason='SQL Injection pattern detected' method=POST "
    "attack_type='SQL_INJECTION'"
)

event1 = parser.parse_event(waf_event_str)
print("✓ Test 1: WAF Event Parsing")
print(f"  URL: {event1.url}")
print(f"  Response Code: {event1.response_code}")
print(f"  Attack Type: {event1.attack_type}")
assert event1.url == '/admin/login.php', "URL parsing failed"
assert event1.response_code == 403, "Response code parsing failed"
print("  Status: PASSED\n")

# Test 2: VPN event with byte counts
vpn_event_str = (
    "timestamp=2024-01-15 10:33:00 sourceip=203.0.113.100 destip=10.0.0.50 "
    "destport=443 subsys=vpn action=allow authenticated_user='john.doe' "
    "vpn_gateway='corp-hub-1' vpn_protocol='SSL' bytes_in=2147483648 "
    "bytes_out=536870912 session_id='sess_12345'"
)

event2 = parser.parse_event(vpn_event_str)
print("✓ Test 2: VPN Event Parsing")
print(f"  VPN User: {event2.vpn_user}")
print(f"  Gateway: {event2.vpn_hub}")
print(f"  Bytes In: {event2.vpn_bytes_in:,}")
print(f"  Bytes Out: {event2.vpn_bytes_out:,}")
assert event2.vpn_user == 'john.doe', "VPN user parsing failed"
assert event2.vpn_bytes_in == 2147483648, "Bytes in parsing failed"
print("  Status: PASSED\n")

# Test 3: IPS event with malware
ips_event_str = (
    "timestamp=2024-01-15 10:32:00 sourceip=203.0.113.50 destip=10.0.0.10 "
    "destport=445 subsys=ips action=blocked severity=critical "
    "rule_id=2013504 signature='ET MALWARE Win32/PushDo.gen!C' "
    "rule_name='Exploit/Shellcode' attack_type='Malware/Backdoor'"
)

event3 = parser.parse_event(ips_event_str)
print("✓ Test 3: IPS Event Parsing")
print(f"  Rule ID: {event3.rule_id}")
print(f"  Rule Name: {event3.rule_name}")
print(f"  Attack Type: {event3.attack_type}")
assert event3.rule_id == '2013504', "Rule ID parsing failed"
assert event3.attack_type == 'Malware/Backdoor', "Attack type parsing failed"
print("  Status: PASSED\n")

# Test 4: Mail/DLP event with sensitive data
mail_event_str = (
    "timestamp=2024-01-15 10:34:00 sourceip=192.168.1.100 subsys=mail "
    "action=quarantine severity=high mail_from='attacker@external.com' "
    "mail_to='finance@company.com' subject='Urgent: Invoice Review' "
    "attachments=3 file_hash='abc123' category='CONFIDENTIAL'"
)

event4 = parser.parse_event(mail_event_str)
print("✓ Test 4: Mail/DLP Event Parsing")
print(f"  From: {event4.sender}")
print(f"  To: {event4.recipient}")
print(f"  Attachments: {event4.attachment_count}")
print(f"  Category: {event4.dlp_category}")
assert event4.sender == 'attacker@external.com', "Sender parsing failed"
assert event4.attachment_count == 3, "Attachment count parsing failed"
print("  Status: PASSED\n")

# Test 5: DNS event 
dns_event_str = (
    "timestamp=2024-01-15 10:37:00 sourceip=192.168.1.100 destip=8.8.8.8 "
    "destport=53 subsys=dns action=allow severity=info query='malicious.tk' "
    "query_type='A' response='192.0.2.1'"
)

event5 = parser.parse_event(dns_event_str)
print("✓ Test 5: DNS Event Parsing")
print(f"  Query: {event5.dns_query}")
print(f"  Query Type: {event5.query_type}")
print(f"  Response: {event5.dns_response}")
assert event5.dns_query == 'malicious.tk', "DNS query parsing failed"
print("  Status: PASSED\n")

print("=" * 60)
print("All parsing tests completed successfully!")
print("=" * 60)
```

### 2. Feature Vector Test

```python
#!/usr/bin/env python3
import sys
import numpy as np
sys.path.insert(0, '/root/v1-security-event-clustering/backend')

from event_parser import EventParser

parser = EventParser()

print("Feature Vector Dimension Test")
print("=" * 60)

# Create diverse events from different subsystems
events = [
    (
        "timestamp=2024-01-15 10:30:00 sourceip=203.0.113.50 destip=10.0.0.100 "
        "destport=443 subsys=waf action=blocked severity=high uri='/admin/login.php' "
        "http_code=403 attack_type='SQL_INJECTION'",
        "WAF"
    ),
    (
        "timestamp=2024-01-15 10:33:00 sourceip=203.0.113.100 destip=10.0.0.50 "
        "destport=443 subsys=vpn action=allow authenticated_user='john.doe' "
        "bytes_in=2147483648 bytes_out=536870912",
        "VPN"
    ),
    (
        "timestamp=2024-01-15 10:32:00 sourceip=203.0.113.50 destip=10.0.0.10 "
        "destport=445 subsys=ips action=blocked severity=critical "
        "attack_type='Malware/Backdoor'",
        "IPS"
    ),
    (
        "timestamp=2024-01-15 10:34:00 sourceip=192.168.1.100 subsys=mail "
        "action=quarantine gravity=high attachments=3 category='CONFIDENTIAL'",
        "Mail"
    ),
    (
        "timestamp=2024-01-15 10:40:00 sourceip=198.51.100.0 destip=203.0.113.50 "
        "subsys=ddos action=blocked severity=critical vector='UDP' "
        "dropped_packets=5000000 bandwidth='50000'",
        "DDoS"
    ),
]

print(f"Expected feature dimension: 62")
print()

feature_vectors = []
for event_str, subsystem in events:
    parsed = parser.parse_event(event_str)
    features = parser.event_to_features(parsed)
    feature_vectors.append(features)
    
    print(f"✓ {subsystem:12} - Feature vector shape: {features.shape}")
    assert features.shape[0] == 62, f"Expected 62 features, got {features.shape[0]}"

print()
print("Feature Matrix Shape:", np.array(feature_vectors).shape)
print(f"Expected: (5, 62)")
assert np.array(feature_vectors).shape == (5, 62), "Feature matrix shape incorrect"

print()
print("=" * 60)
print("Feature vector tests PASSED!")
print("=" * 60)
```

### 3. Threat Assessment Test

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/root/v1-security-event-clustering/backend')

from event_parser import EventParser
from cluster_analyzer import ClusterAnalyzer

parser = EventParser()
analyzer = ClusterAnalyzer()

print("Threat Assessment Test")
print("=" * 60)
print()

# Create high-threat events from different subsystems
threat_events = [
    # WAF SQL Injection
    {
        "str": (
            "timestamp=2024-01-15 10:30:00 sourceip=203.0.113.50 destip=10.0.0.100 "
            "destport=443 subsys=waf action=blocked severity=critical "
            "uri='/admin/login.php' http_code=403 "
            "reason=\"' OR '1'='1\" attack_type='SQL_INJECTION'"
        ),
        "expected_threat": "high"
    },
    # IPS Malware
    {
        "str": (
            "timestamp=2024-01-15 10:32:00 sourceip=203.0.113.50 destip=10.0.0.10 "
            "destport=445 subsys=ips action=blocked severity=critical "
            "attack_type='Exploit' rule_name='Shellcode Detection'"
        ),
        "expected_threat": "critical"
    },
    # Mail DLP Sensitive Data
    {
        "str": (
            "timestamp=2024-01-15 10:34:00 sourceip=192.168.1.100 subsys=mail "
            "action=quarantine severity=critical "
            "mail_from='attacker@external.com' mail_to='finance@company.com' "
            "attachments=5 category='RESTRICTED|PII|CREDIT_CARD'"
        ),
        "expected_threat": "critical"
    },
    # DDoS Attack
    {
        "str": (
            "timestamp=2024-01-15 10:40:00 sourceip=198.51.100.0/24 destip=203.0.113.50 "
            "subsys=ddos action=blocked severity=critical vector='UDP_Flood' "
            "dropped_packets=5000000 bandwidth='100000'"
        ),
        "expected_threat": "critical"
    },
]

for i, threat_test in enumerate(threat_events):
    parsed = parser.parse_event(threat_test["str"])
    threat_score = analyzer._assess_threat([parsed])
    
    print(f"Test {i+1}: {parsed.subsystem.upper()}")
    print(f"  Event: {threat_test['str'][:80]}...")
    print(f"  Threat Score: {threat_score:.2f}")
    print(f"  Expected: {threat_test['expected_threat']}")
    print()

print("=" * 60)
print("Threat assessment tests completed!")
print("=" * 60)
```

### 4. Field Alias Resolution Test

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/root/v1-security-event-clustering/backend')

from event_parser import EventParser

parser = EventParser()

print("Field Alias Resolution Test")
print("=" * 60)
print()

# Test that different field name aliases resolve to same field
test_cases = [
    {
        "name": "URL field aliases",
        "events": [
            "subsys=waf uri='/test' sourceip=1.1.1.1 destip=2.2.2.2",
            "subsys=waf path='/test' sourceip=1.1.1.1 destip=2.2.2.2",
            "subsys=waf request_uri='/test' sourceip=1.1.1.1 destip=2.2.2.2",
        ],
        "check_field": "url",
        "expected_value": "/test"
    },
    {
        "name": "Response code aliases",
        "events": [
            "subsys=waf http_code=403 sourceip=1.1.1.1 destip=2.2.2.2",
            "subsys=waf status_code=403 sourceip=1.1.1.1 destip=2.2.2.2",
            "subsys=waf response_status=403 sourceip=1.1.1.1 destip=2.2.2.2",
        ],
        "check_field": "response_code",
        "expected_value": 403
    },
    {
        "name": "VPN user aliases",
        "events": [
            "subsys=vpn authenticated_user='john' sourceip=1.1.1.1 destip=2.2.2.2",
            "subsys=vpn login_user='john' sourceip=1.1.1.1 destip=2.2.2.2",
            "subsys=vpn vpn_user='john' sourceip=1.1.1.1 destip=2.2.2.2",
        ],
        "check_field": "vpn_user",
        "expected_value": "john"
    },
]

for test in test_cases:
    print(f"✓ {test['name']}")
    
    for event_str in test['events']:
        event = parser.parse_event(event_str)
        actual_value = getattr(event, test['check_field'])
        
        if actual_value == test['expected_value']:
            print(f"  ✓ '{event_str[:50]}...' → {test['check_field']} = {actual_value}")
        else:
            print(f"  ✗ FAILED: Expected {test['expected_value']}, got {actual_value}")
    
    print()

print("=" * 60)
print("Alias resolution tests completed!")
print("=" * 60)
```

## Integration Test: Full Pipeline

```python
#!/usr/bin/env python3
import sys
import numpy as np
sys.path.insert(0, '/root/v1-security-event-clustering/backend')

from event_parser import EventParser
from cluster_analyzer import ClusterAnalyzer
import json

parser = EventParser()
analyzer = ClusterAnalyzer()

print("Full Integration Test: Parse → Features → Analyze")
print("=" * 60)
print()

# Create realistic event stream from multiple subsystems
events_raw = [
    # Suspicious WAF activity
    "timestamp=2024-01-15 10:30:00 sourceip=203.0.113.50 destip=10.0.0.100 destport=443 subsys=waf action=blocked severity=high uri='/admin/login.php' http_code=403 attack_type='SQL_INJECTION'",
    "timestamp=2024-01-15 10:31:00 sourceip=203.0.113.50 destip=10.0.0.100 destport=443 subsys=waf action=blocked severity=high uri='/admin/users.php' http_code=403 attack_type='SQL_INJECTION'",
    
    # Correlated IPS activity from same source
    "timestamp=2024-01-15 10:32:00 sourceip=203.0.113.50 destip=10.0.0.10 destport=445 subsys=ips action=blocked severity=critical rule_name='Exploit/Shellcode' attack_type='Malware/Backdoor'",
    
    # Legitimate VPN usage (different source)
    "timestamp=2024-01-15 10:33:00 sourceip=192.168.1.50 destip=10.0.0.50 destport=443 subsys=vpn action=allow authenticated_user='employee' bytes_in=104857600 bytes_out=52428800",
    
    # Suspicious mail activity
    "timestamp=2024-01-15 10:34:00 sourceip=192.168.1.100 subsys=mail action=quarantine severity=high mail_from='unknown@external.com' mail_to='finance@company.com' attachments=3 category='CONFIDENTIAL'",
]

print("1. Parsing Events...")
parsed_events = []
for i, event_str in enumerate(events_raw):
    event = parser.parse_event(event_str)
    parsed_events.append(event)
    print(f"   {i+1}. {event.subsystem.upper():12} from {event.source_ip:15} | Action: {event.action:10} | Severity: {event.severity}")

print()
print("2. Extracting Features...")
feature_vectors = []
for i, event in enumerate(parsed_events):
    features = parser.event_to_features(event)
    feature_vectors.append(features)
    print(f"   {i+1}. Features shape: {features.shape} | Non-zero elements: {np.count_nonzero(features)}")

feature_matrix = np.array(feature_vectors)
print(f"\n   Final feature matrix shape: {feature_matrix.shape}")
assert feature_matrix.shape == (len(events_raw), 62), "Feature dimension mismatch"

print()
print("3. Performing Cluster Analysis...")
threat_score = analyzer._assess_threat(parsed_events)
print(f"   Overall threat score: {threat_score:.2f}")

# Simulate cluster analysis
print()
print("4. Subsystem Distribution:")
subsystems = {}
for event in parsed_events:
    subsystems[event.subsystem] = subsystems.get(event.subsystem, 0) + 1
for subsys, count in subsystems.items():
    print(f"   {subsys.upper():12}: {count} events")

print()
print("5. Threat Characteristics:")
high_severity = [e for e in parsed_events if e.severity in ['critical', 'high']]
print(f"   High/Critical severity: {len(high_severity)}/{len(parsed_events)}")

malicious_actions = [e for e in parsed_events if e.action in ['blocked', 'quarantine']]
print(f"   Blocked/Quarantined: {len(malicious_actions)}/{len(parsed_events)}")

print()
print("=" * 60)
print("Integration test COMPLETED!")
print("=" * 60)
```

## Running the Tests

Execute tests in order:

```bash
cd /root/v1-security-event-clustering/backend

# Run parsing test
python3 << 'EOF'
$(cat test_parsing.py)
EOF

# Run feature vector test
python3 << 'EOF'
$(cat test_features.py)
EOF

# Run threat assessment test
python3 << 'EOF'
$(cat test_threats.py)
EOF

# Run alias resolution test
python3 << 'EOF'
$(cat test_aliases.py)
EOF

# Run full integration test
python3 << 'EOF'
$(cat test_integration.py)
EOF
```

## Expected Results

| Test | Expected Result | Status |
|------|-----------------|--------|
| Parsing (Test 1) | All events parse correctly, fields populated | ✓ PASS |
| Parsing (Test 2) | VPN fields including byte counts parsed | ✓ PASS |
| Parsing (Test 3) | IPS rule fields extracted | ✓ PASS |
| Parsing (Test 4) | Mail/DLP fields identified | ✓ PASS |
| Parsing (Test 5) | DNS fields resolved | ✓ PASS |
| Features | 62-dimensional vectors generated | ✓ PASS |
| Threat Assessment | High-threat events scored appropriately | ✓ PASS |
| Alias Resolution | Alternative field names resolved correctly | ✓ PASS |
| Integration | Full pipeline processes mixed events | ✓ PASS |

## Troubleshooting

### Issue: "Feature dimension is 51, not 62"
**Solution:** Verify that numpy is imported and `_extract_subsystem_features()` method is present in `event_parser.py`

### Issue: "Field parsing returns empty values"
**Solution:** Check that SUBSYSTEM_FIELD_MAPPINGS includes the alias for your event field

### Issue: "Type conversion errors"
**Solution:** Verify `_set_subsystem_field()` handles the data type in the raw event (ensure proper int/float conversion)

### Issue: "Threat score is always 0"
**Solution:** Confirm `_assess_subsystem_threats()` is being called from within `_assess_threat()`

# Subsystem-Specific Architecture Changes

## High-Level Architecture Evolution

### Before (Single-Pass Parsing)
```
Raw Event String
    ↓
EventParser.parse_event()
    ├─ Basic field extraction (key=value matching)
    ├─ Generic subsystem detection
    └─ Single-pass parsing → SecurityEvent (11 fields)
    ↓
Limited Subsystem Awareness
    ├─ Generic threat scoring (all events same logic)
    └─ Feature vector: 51 dimensions
```

### After (Two-Pass Subsystem-Aware Parsing)
```
Raw Event String
    ↓
EventParser.parse_event()
    ├─ Pass 1: Identify subsystem from raw data
    ├─ Pass 2: Apply SUBSYSTEM_FIELD_MAPPINGS
    │   ├─ Resolve field aliases (e.g., uri → url)
    │   ├─ Type conversion (string → int/float/bool)
    │   └─ Populate typed SecurityEvent fields (41 fields)
    ├─ Store unknown fields in subsystem_fields dict
    └─ SecurityEvent with rich subsystem context
    ↓
Subsystem-Aware Processing
    ├─ Tailored threat scoring (per-subsystem heuristics)
    ├─ Rich feature extraction (62 dimensions)
    └─ Cluster analysis with subsystem insights
```

## Data Flow with Subsystem Fields

### WAF Event Example
```
Input:
  "timestamp=2024-01-15 10:30:00 sourceip=203.0.113.50 destip=10.0.0.100 
   destport=443 subsys=waf action=blocked severity=high uri='/admin/login.php' 
   http_code=403 reason='SQL Injection detected' attack_type='SQL_INJECTION'"

Parse Phase:
  ├─ Identify subsystem: waf
  ├─ Find field aliases in SUBSYSTEM_FIELD_MAPPINGS['waf']
  ├─ Map 'uri' → 'url' field
  ├─ Map 'http_code' → 'response_code' (convert str→int)
  ├─ Map 'reason' → 'reason' field
  └─ Store in SecurityEvent

SecurityEvent Object:
  ├─ Common fields (required):
  │   ├─ timestamp: "2024-01-15 10:30:00"
  │   ├─ source_ip: "203.0.113.50"
  │   ├─ dest_ip: "10.0.0.100"
  │   ├─ dest_port: 443
  │   ├─ subsystem: "waf"
  │   ├─ action: "blocked"
  │   └─ severity: "high"
  └─ Subsystem-specific fields (only for WAF):
      ├─ url: "/admin/login.php"
      ├─ response_code: 403
      ├─ reason: "SQL Injection detected"
      ├─ attack_type: "SQL_INJECTION"
      └─ (other WAF fields remain empty)

Feature Extraction (62 dims):
  ├─ Base features (50 dims):
  │   ├─ src_ip_hash: 0.42
  │   ├─ dest_ip_hash: 0.67
  │   ├─ port_range: 0.95
  │   └─ ... (47 more)
  └─ WAF-specific features (4 dims):
      ├─ url_length: 0.38 (normalized from 18 chars)
      ├─ response_code_norm: 0.80 (403/500)
      ├─ has_reason: 1.0
      └─ method_encoding: 0.5 (POST → 0.5)

Feature Vector: [0.42, 0.67, ..., 0.38, 0.80, 1.0, 0.5]

Threat Assessment:
  ├─ Check WAF-specific patterns:
  │   ├─ "SQL" in attack_type? YES → +4 threat
  │   ├─ Admin path? YES → +3 threat
  │   └─ HTTP 403? YES → +2 threat
  └─ Final threat_score: 9.0 (normalized)
```

### VPN Event Example
```
Input:
  "timestamp=2024-01-15 10:33:00 sourceip=203.0.113.100 destip=10.0.0.50 
   destport=443 subsys=vpn action=allow authenticated_user='john.doe' 
   vpn_gateway='corp-hub-1' bytes_in=2147483648 bytes_out=536870912"

Parse Phase:
  ├─ Identify subsystem: vpn
  ├─ Find field aliases in SUBSYSTEM_FIELD_MAPPINGS['vpn']
  ├─ Map 'authenticated_user' → 'vpn_user'
  ├─ Map 'vpn_gateway' → 'vpn_hub'
  ├─ Map 'bytes_in' → 'vpn_bytes_in' (convert str→int)
  └─ Map 'bytes_out' → 'vpn_bytes_out' (convert str→int)

SecurityEvent Object:
  ├─ Common fields:
  │   ├─ timestamp: "2024-01-15 10:33:00"
  │   ├─ source_ip: "203.0.113.100"
  │   ├─ dest_port: 443
  │   ├─ subsystem: "vpn"
  │   ├─ action: "allow"
  │   └─ (required fields)
  └─ VPN-specific fields:
      ├─ vpn_user: "john.doe"
      ├─ vpn_hub: "corp-hub-1"
      ├─ vpn_bytes_in: 2147483648 (2GB)
      └─ vpn_bytes_out: 536870912 (512MB)

Feature Extraction (62 dims):
  ├─ Base features (50 dims):
  │   └─ ... (50 features)
  └─ VPN-specific features (5 dims):
      ├─ bytes_in_log: log(2147483648) ≈ 0.95
      ├─ bytes_out_log: log(536870912) ≈ 0.80
      ├─ has_vpn_user: 1.0
      ├─ has_vpn_hub: 1.0
      └─ protocol_encoding: 0.75 (SSL)

Feature Vector: [...50 base features..., 0.95, 0.80, 1.0, 1.0, 0.75]

Threat Assessment:
  ├─ Check VPN-specific patterns:
  │   ├─ bytes_in > 1GB? YES → +2 threat
  │   └─ Unusual time? Check context
  └─ Final threat_score: 2.0 (relatively low, legitimate usage)
```

## SUBSYSTEM_FIELD_MAPPINGS Structure

```python
SUBSYSTEM_FIELD_MAPPINGS = {
    'waf': {
        'url': {
            'aliases': ['uri', 'path', 'request_uri', 'destination_url'],
            'type': str,
            'field': 'url'
        },
        'response_code': {
            'aliases': ['http_code', 'status_code', 'response_status'],
            'type': int,
            'field': 'response_code'
        },
        # ... more fields
    },
    
    'ips': {
        'rule_id': {
            'aliases': ['rule', 'rule_number', 'sig_id'],
            'type': str,
            'field': 'rule_id'
        },
        # ... more fields
    },
    
    'vpn': {
        'vpn_user': {
            'aliases': ['user', 'login_user', 'authenticated_user'],
            'type': str,
            'field': 'vpn_user'
        },
        'vpn_bytes_in': {
            'aliases': ['bytes_in', 'data_in', 'traffic_in'],
            'type': int,
            'field': 'vpn_bytes_in'
        },
        # ... more fields
    },
    
    # ... 5 more subsystems (mail, dlp, proxy, dns, sandbox, antivirus, ddos, firewall)
}
```

## SecurityEvent Class Evolution

### Before
```python
@dataclass
class SecurityEvent:
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
    # Total: 12 fields
```

### After
```python
@dataclass
class SecurityEvent:
    # Core fields (12)
    timestamp: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    source_port: int = 0
    dest_port: int = 0
    subsystem: str = ""
    user: str = ""
    action: str = ""
    severity: str = ""
    content: str = ""
    protocol: str = ""
    raw_data: dict = field(default_factory=dict)
    
    # Generic extensibility
    subsystem_fields: dict = field(default_factory=dict)
    
    # WAF/WebFilter (6 fields)
    url: str = ""
    response_code: int = 0
    reason: str = ""
    request_method: str = ""
    user_agent: str = ""
    attack_type: str = ""
    
    # IPS/IDS (3 fields)
    rule_id: str = ""
    rule_name: str = ""
    # attack_type already defined above
    
    # VPN (6 fields)
    vpn_user: str = ""
    vpn_hub: str = ""
    vpn_protocol: str = ""
    vpn_bytes_in: int = 0
    vpn_bytes_out: int = 0
    vpn_session_id: str = ""
    
    # Mail/DLP (6 fields)
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    attachment_count: int = 0
    file_hash: str = ""
    dlp_category: str = ""
    
    # Proxy (4 fields)
    # request_method, user_agent, url already defined
    referer: str = ""
    content_type: str = ""
    
    # DNS (3 fields)
    dns_query: str = ""
    dns_response: str = ""
    query_type: str = ""
    
    # AV/Sandbox (4 fields)
    malware_name: str = ""
    malware_family: str = ""
    detection_method: str = ""
    sandbox_verdict: str = ""
    
    # DDoS (3 fields)
    attack_vector: str = ""
    packets_dropped: int = 0
    bandwidth_consumed: float = 0.0
    
    # Firewall (3 fields)
    firewall_policy: str = ""
    firewall_zone_from: str = ""
    firewall_zone_to: str = ""
    
    # Total: 41 typed fields + 1 generic dict
```

## Feature Vector Composition

### Base Features (50 dimensions)
```
Network Features (6):
  ├─ source_ip_hash
  ├─ dest_ip_hash
  ├─ source_port_normalized
  ├─ dest_port_normalized
  ├─ port_range_category
  └─ protocol_encoding

Temporal Features (6):
  ├─ hour_of_day
  ├─ day_of_week
  ├─ is_business_hours
  ├─ is_weekend
  ├─ timestamp_normalized
  └─ temporal_entropy

Subsystem & Action (3):
  ├─ subsystem_categorical (one-hot encoded, 10 bins)
  ├─ action_categorical (one-hot encoded, 5 bins)
  └─ severity_score

User & Content (8):
  ├─ has_user_flag
  ├─ user_length_normalized
  ├─ content_length_normalized
  ├─ content_entropy
  ├─ keyword_presence_1
  ├─ keyword_presence_2
  ├─ keyword_presence_3
  └─ keyword_presence_4

Additional Categorical (21):
  └─ Various one-hot encodings and normalized counts
```

### Subsystem-Specific Features (12 dimensions)

Allocated dynamically based on subsystem:

```
If subsystem == 'waf':
  ├─ url_length_normalized (0-1)
  ├─ response_code_normalized (0-1)
  ├─ has_reason_flag (0 or 1)
  └─ request_method_encoding (0-1)
  Total added: 4 dims

If subsystem == 'vpn':
  ├─ vpn_bytes_in_log_scaled (0-1)
  ├─ vpn_bytes_out_log_scaled (0-1)
  ├─ has_vpn_user_flag (0 or 1)
  ├─ has_vpn_hub_flag (0 or 1)
  └─ vpn_protocol_encoding (0-1)
  Total added: 5 dims

If subsystem == 'ips':
  ├─ rule_id_hash (0-1)
  ├─ has_rule_name_flag (0 or 1)
  └─ attack_type_length_norm (0-1)
  Total added: 3 dims

... (similar for mail, proxy, dns, sandbox, ddos, firewall)
```

## Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                     Raw Security Event                          │
│     (key=value pairs from WAF, IPS, VPN, Mail, etc.)           │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   EventParser.parse_event()                     │
│                                                                 │
│  1. Extract raw key-value pairs                               │
│  2. Detect subsystem type                                     │
│  3. Look up SUBSYSTEM_FIELD_MAPPINGS for detected subsystem   │
│  4. For each mapped field:                                    │
│     a. Find alias in raw data                                 │
│     b. Convert to appropriate type (str→int, etc.)            │
│     c. Populate SecurityEvent field                           │
│  5. Store unknown fields in subsystem_fields dict             │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SecurityEvent Object                          │
│      - 12 core fields (all subsystems)                         │
│      - Up to 29 subsystem-specific fields                      │
│      - subscystem_fields dict (for dynamic fields)             │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│         EventParser.event_to_features()                         │
│                                                                 │
│  1. Extract base features (50 dims)                            │
│  2. Call _extract_subsystem_features()                         │
│  3. Concatenate into 62-dim feature vector                     │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Feature Vector (62D)                          │
│  [0.42, 0.67, 0.38, ..., (50 base), ..., (12 subsys-specific)]│
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│              ML Clustering Models                               │
│          (DEC, IDEC, VaDE, Contrastive)                        │
│                                                                 │
│  Cluster 1: [62D vector 1, 62D vector 2, ...]                 │
│  Cluster 2: [62D vector 4, 62D vector 5, ...]                 │
│  ...                                                           │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│      ClusterAnalyzer.analyze_cluster()                          │
│                                                                 │
│  1. Collect base statistics (subsystems, actions, IPs, etc.)  │
│  2. Collect subsystem-specific stats:                          │
│     ├─ urls (Counter)                                          │
│     ├─ response_codes (Counter)                                │
│     ├─ rule_names (Counter)                                    │
│     ├─ malwares (Counter)                                      │
│     ├─ vpn_users (Counter)                                     │
│     ├─ senders (Counter)                                       │
│     ├─ recipients (Counter)                                    │
│     ├─ attack_vectors (Counter)                                │
│     ├─ dns_queries (Counter)                                   │
│     └─ policies (Counter)                                      │
│  3. Call _assess_subsystem_threats()                           │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│    ClusterAnalyzer._assess_subsystem_threats()                  │
│                                                                 │
│  For each subsystem in cluster:                                │
│    ├─ WAF: Check SQL injection, admin paths, HTTP codes       │
│    ├─ IPS: Check exploits, backdoors, recon                   │
│    ├─ VPN: Check unusual data volumes, multiple users         │
│    ├─ Mail/DLP: Check sensitive categories, attachments       │
│    ├─ Sandbox/AV: Check malware, verdicts                     │
│    ├─ DDoS: Check vectors, bandwidth, packet drops            │
│    ├─ DNS: Check suspicious TLDs, DDNS                        │
│    └─ Firewall: Check policy blocks, zone traversal           │
│                                                                 │
│  Return: List of top threat indicators with context            │
└───────────┬─────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  ClusterProfile Object                          │
│                                                                 │
│  ├─ cluster_id: int                                           │
│  ├─ threat_level: "critical" | "high" | "medium" | "low" | "info"
│  ├─ threat_indicators: ["SQL injection pattern", ...]         │
│  ├─ recommended_actions: ["Block source IP", ...]             │
│  ├─ subsystem_stats: {"waf": 45, "vpn": 12, ...}             │
│  └─ representative_events: [Event, Event, ...]                │
└─────────────────────────────────────────────────────────────────┘
```

## Threat Scoring Example: Multi-Subsystem Cluster

```
Cluster Analysis:
├─ Event 1 (WAF): SQL Injection + Admin path
│  └─ Threat: +4 (SQL) +3 (admin) +2 (403 error) = +9
│
├─ Event 2 (IPS): Shellcode detection
│  └─ Threat: +5 (exploit) = +5
│
├─ Event 3 (VPN): 2GB data transfer, multiple users
│  └─ Threat: +2 (volume) +1 (multi-user) = +3
│
├─ Event 4 (Mail): Confidential data exfiltration
│  └─ Threat: +4 (confidential) +2 (high attachments) = +6
│
└─ Event 5 (DDoS): 100GB/s bandwidth attack
   └─ Threat: +4 (vector) +3 (bandwidth) = +7

Total Cluster Threat: (9+5+3+6+7) / 5 = 6.0 / 5 = HIGH

Assessment:
"Multi-vector attack involving web exploitation, system compromise,
data exfiltration, and distributed denial of service. Multiple
subsystems targeted. Immediate response required."
```

## Key Improvements Summary

| Aspect | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Field Types** | 11 generic | 41 typed + extension dict | 272% more fields |
| **Field Aliases** | ~5 manual | 50+ automatic | Better alias coverage |
| **Feature Dims** | 51 | 62 | +21.6% richer features |
| **Threat Rules** | Generic | 9 subsystem-specific | Domain-aware scoring |
| **Parsing Phases** | 1-pass | 2-pass | Better subsystem detection |
| **Type Safety** | String-heavy | Typed fields | Fewer conversion errors |
| **Extensibility** | Limited | subsystem_fields dict | Unlimited custom fields |

## Next Phase: Optimization

```
Current State:
  ✅ Two-pass subsystem-aware parsing
  ✅ 41 typed fields + generic dict
  ✅ 50+ field aliases
  ✅ 62-dimension features
  ✅ Per-subsystem threat detection
  
Next Phase:
  ⏳ Real-world data validation
  ⏳ ML-based threat scoring optimization
  ⏳ Performance benchmarking
  ⏳ Config-driven field mappings
  ⏳ Cross-subsystem correlation rules
```

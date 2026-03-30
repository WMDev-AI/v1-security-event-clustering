# Backend Architecture & Workflow Explanation

This document provides a comprehensive overview of how the backend works end-to-end, including architecture, components, data flow, and known issues.

```
uvicorn main:root_app --reload
```

## System Overview

The backend is a **FastAPI application** that implements a **deep learning-based security event clustering pipeline**. It processes raw security event logs, converts them into numerical embeddings, clusters them using various deep learning models, and extracts security insights.

```
User Input (Raw Events)
        ↓
Event Parser (feature extraction)
        ↓
Deep Clustering Models (DEC/IDEC/VaDE/Contrastive)
        ↓
Cluster Analysis (threat assessment)
        ↓
Security Insights Engine (MITRE mapping, IOCs, etc.)
        ↓
API Responses (visualizations, recommendations)
```

## Core Components

### 1. Event Parser (`backend/event_parser.py`)

**Purpose:** Convert raw security log strings → `SecurityEvent` objects with numerical features.

**How it works:**
- Parses **key=value formatted logs** (e.g., `sourceip=192.168.1.100 destport=443 action=blocked`)
- Normalizes field names (maps `sourceip`, `src_ip`, `srcip` → unified `source_ip`)
- **Extracts features** from each event:
  - **Network:** Source/dest IPs (5 features each), ports (4 features each)
  - **Security:** Subsystem (15 one-hot features), action (4 features), severity (1 feature)
  - **Temporal:** Hour, day-of-week, weekend flag, business hours flag (4 features)
  - **Protocol:** TCP/UDP/ICMP/HTTP/HTTPS (6 features)
  - **Metadata:** User presence, content length (2 features)

**Output:** 51-dimensional feature vector per event

**Key Methods:**
- `parse_event(raw_event: str) -> SecurityEvent` - Parse single event
- `parse_events(raw_events: list[str]) -> list[SecurityEvent]` - Batch parse
- `event_to_features(event: SecurityEvent) -> list[float]` - Convert to feature vector
- `ip_to_features(ip: str)` - Network feature extraction
- `port_to_features(port: int)` - Port classification
- `subsystem_to_features(subsystem: str)` - One-hot encoding
- `severity_to_feature(severity: str)` - Severity normalization

**Supported Subsystems (15 total):**
- firewall, ips, ddos, waf, webfilter, mail, vpn, proxy, dns, antivirus, sandbox, dlp, nat, router, auth

---

### 2. Deep Clustering Models (`backend/deep_clustering.py`)

**Purpose:** Learn cluster assignments from unlabeled data using deep learning.

The system supports **4 clustering approaches**:

#### Model Comparison

| Model | Algorithm | Use Case | Advantages |
|-------|-----------|----------|------------|
| **DEC** | KL divergence + Student's t-distribution | General purpose | Fast, convergent, simple |
| **IDEC** | DEC + reconstruction loss | Better representations | Combines clustering + quality |
| **VaDE** | VAE + Gaussian Mixture Model | Probabilistic clustering | Handles uncertainty, robust |
| **Contrastive** | Contrastive learning (SimCLR-style) | Robust features | Learns invariant representations |

#### Deep Embedded Clustering (DEC)

```
Autoencoder
    ↓ (encode)
Latent Space (z)
    ↓ (clustering layer)
Soft Cluster Assignments (Q)
    ↓ (refine targets)
Target Distribution (P)
    ↓ (KL divergence)
Loss → Update clusters & encoder
```

- Uses Student's t-distribution kernel for soft assignments
- Iteratively hardens cluster assignments
- Formula: `q_ij = (1 + ||z_i - μ_j||²/α)^(-(α+1)/2) / normalization`

#### Improved DEC (IDEC)

Combines DEC with reconstruction loss:
```
Total Loss = KL(Q || P) + γ * MSE(x || x_recon)
```

- `γ` controls balance between clustering and reconstruction
- Better feature learning than pure DEC

#### Variational Deep Embedding (VaDE)

Probabilistic approach:
```
VAE ELBO Loss = Reconstruction + β * KL(encoder || prior)
    + 
GMM Posterior Loss = -log P(z|c) * P(c)
```

- Handles uncertainty in latent space
- Cluster responsibilities via Gaussian mixture model
- More robust to outliers

#### Contrastive Deep Clustering

```
Augment data → Two views (x₁, x₂)
    ↓
Encoder produces projections (proj₁, proj₂)
    ↓
Contrastive Loss (NT-Xent: Normalized Temperature-scaled Cross Entropy)
    ↓
Consistency Loss (same input → similar clusters)
    ↓
Entropy Regularization (avoid degenerate solutions)
```

**Key Loss Functions:**

```python
reconstruction_loss(x, x_recon) = MSE(x, x_recon)

kl_divergence_loss(Q, P) = Σ P * log(P / (Q + ε))

vae_loss(x, x_recon, μ, logvar) = MSE(x, x_recon) + β * KL(N(μ,σ) || N(0,1))

cluster_assignment_entropy(Q) = -Σ avg_probs * log(avg_probs)
```

---

### 3. Trainer (`backend/trainer.py`)

**Purpose:** Orchestrate the end-to-end training process.

#### Two-Phase Training Pipeline

**Phase 1: Pretraining (50 epochs default)**
```
Mini-batches of raw events
    ↓
Autoencoder forward pass
    ↓
Reconstruction loss (MSE or VAE ELBO)
    ↓
Backprop & update encoder/decoder
    ↓
Result: Learned latent representations
```

- Optimizer: Adam with learning rate 1e-3
- Scheduler: StepLR (reduce LR every 20 epochs by 0.5x)
- Batch size: 256 (configurable)
- Dropout: 0.2 for regularization

**Phase 2: Fine-tuning (100 epochs default)**
```
Compute Target Distribution P from current Q:
  p_ij = (q_ij² / Σ_i q_ij) / normalization
    ↓
Mini-batches of events
    ↓
DEC/IDEC/VaDE/Contrastive forward pass
    ↓
Clustering loss (KL divergence / VAE / Contrastive)
    ↓
Backprop & update encoder + cluster centers
    ↓
Every 5 epochs: check convergence (cluster assignment delta < 0.001)
    ↓
If converged or max epochs reached: stop
```

- Optimizer: Adam with learning rate 1e-4 (lower than pretraining)
- Batch size: 256
- Convergence check: Stop if < 0.1% of cluster assignments change

#### Cluster Initialization

```
After pretraining:
  Get all latent vectors Z from encoder
    ↓
  Run K-Means (k=n_clusters)
    ↓
  Place cluster centers at K-Means centroids
    ↓
  Compute initial soft assignments Q
```

#### Key Training Config Parameters

```python
@dataclass
class TrainingConfig:
    hidden_dims: list[int] = [256, 128, 64]    # Autoencoder layer sizes
    latent_dim: int = 32                        # Latent space dimension
    n_clusters: int = 10                        # Target number of clusters
    dropout: float = 0.2                        # Regularization
    
    pretrain_epochs: int = 50                   # Phase 1
    pretrain_lr: float = 1e-3                  
    pretrain_batch_size: int = 256              
    
    finetune_epochs: int = 100                  # Phase 2
    finetune_lr: float = 1e-4                  
    finetune_batch_size: int = 256              
    
    alpha: float = 1.0                          # Student's t df (DEC/IDEC)
    gamma: float = 0.1                          # Reconstruction weight (IDEC)
    beta: float = 1.0                           # KL weight (VaDE)
    temperature: float = 0.5                    # Contrastive temperature
    
    update_interval: int = 5                    # Update target P every N epochs
    tol: float = 0.001                          # Convergence tolerance
```

---

### 4. Cluster Analyzer (`backend/cluster_analyzer.py`)

**Purpose:** Extract human-readable security intelligence from clusters.

#### Per-Cluster Analysis

For each cluster, computes:

**Dominant Characteristics:**
- Top 3 subsystems (firewall, IPS, WAF, etc.)
- Top 3 actions (block, allow, alert, etc.)
- Severity distribution (critical, high, medium, low, info counts)

**Network Patterns:**
- Top 5 source IPs with event counts
- Top 5 destination IPs with event counts
- Top 5 destination ports with event counts

**Temporal Patterns:**
- Peak 3 activity hours (0-23)
- Weekend activity ratio (fraction of events on Sat/Sun)
- Business hours ratio (fraction of events 9-17)

**User Patterns:**
- Top 5 users with event counts
- User presence ratio (fraction of events with user field)

**Threat Assessment Scoring:**

| Factor | Score | Condition |
|--------|-------|-----------|
| Blocked/denied actions | +2 | If primary action is block/deny/drop/reject |
| High severity events | +3 | If >10% of events are critical or high |
| Suspicious port | +2 | Ports: 22, 23, 25, 445, 3306, 3389, etc. |
| Threat keywords | +1 each | attack, exploit, malware, brute, ddos, etc. |
| IPS/IDS/DDoS subsystem | +2 | If subsystem is security detection system |
| Weekend activity | +1 | If >50% of events on weekends |
| Night-time activity | +2 | If peak hours are 22-6 and <30% business hours |
| Single source scanning | +2 | If 1 source IP targeting >3 dest IPs |

**Threat Levels:**
- `critical` - Score ≥ 8
- `high` - Score 5-7
- `medium` - Score 3-4
- `low` - Score 1-2
- `info` - Score 0

#### Recommendations Generation

**Automatic Recommendations Based on Threat Level & Characteristics:**

- **Critical:** "URGENT: Immediate investigation required", "Consider isolating affected systems"
- **High:** "Escalate to security operations team", "Preserve logs for forensic analysis"
- **Port-specific:**
  - Port 3389 (RDP): "Review RDP access policies and enable NLA"
  - Port 22 (SSH): "Implement key-based SSH authentication"
  - Port 445 (SMB): "Audit SMB shares and disable SMBv1"
  - Databases: "Ensure databases are not exposed to internet"
- **Subsystem-specific:**
  - VPN: "Review VPN authentication logs"
  - WAF: "Analyze blocked web attack patterns"
  - Mail: "Check for phishing campaign patterns"

#### ClusterProfile Data Structure

```python
@dataclass
class ClusterProfile:
    cluster_id: int
    size: int                                      # Event count
    
    primary_subsystems: list[str]                  # Top 3
    primary_actions: list[str]                     # Top 3
    severity_distribution: dict                    # {level: count}
    
    top_source_ips: list[tuple]                    # [(ip, count), ...]
    top_dest_ips: list[tuple]
    top_dest_ports: list[tuple]
    
    peak_hours: list[int]                          # Top 3 hours
    weekend_ratio: float                           # 0.0 - 1.0
    business_hours_ratio: float
    
    top_users: list[tuple]                         # [(user, count), ...]
    content_keywords: list[str]                    # Common words in logs
    
    threat_level: str                              # critical/high/medium/low/info
    threat_indicators: list[str]                   # Explanation of threat level
    recommended_actions: list[str]                 # Up to 5 actions
    representative_events: list[dict]              # 5 sample events
```

---

### 5. Security Insights Engine (`backend/security_insights.py`)

**Purpose:** Generate rich threat intelligence including MITRE ATT&CK mapping and IOCs.

#### Insight Analysis Per Cluster

**Attack Detection Categories:**

1. **Brute Force Attacks**
   - Indicators: High block rate on auth ports (22, 3389, 23, 21)
   - MITRE: T1110 - Brute Force
   - Actions: Rate limit, enable MFA, lock accounts

2. **Web Application Attacks**
   - Indicators: WAF blocks, SQL injection/XSS keywords
   - MITRE: T1190 - Exploit Public-Facing Application
   - Actions: Enable strict WAF, patch applications

3. **DDoS Attacks**
   - Indicators: High volume from multiple sources or single source to many targets
   - MITRE: T1498 - Network Denial of Service
   - Actions: Rate limiting, DDoS protection, traffic filtering

4. **Lateral Movement / Reconnaissance**
   - Indicators: Port scanning (many dest ports from same source)
   - MITRE: T1046 - Network Service Scanning
   - Actions: Network segmentation, IDS tuning

5. **Data Exfiltration**
   - Indicators: Large outbound transfers, DNS queries to unknown domains
   - MITRE: T1567 - Exfiltration Over Web Service
   - Actions: Monitor outbound, DLP policies

#### Indicators of Compromise (IOCs)

```python
# Malicious IPs
{
    "ip": "203.0.113.50",
    "severity": "high",
    "contexts": ["brute force source", "attacking SSH port"],
    "event_count": 1204,
    "recommendation": "Block at firewall"
}

# Attack Patterns
{
    "pattern": "SSH Brute Force Attack",
    "description": "Multiple failed SSH authentication attempts",
    "mitre_techniques": ["T1110 - Brute Force"],
    "source_ips": ["203.0.113.50", "198.51.100.25"],
    "severity": "high"
}

# Suspicious Users
{
    "user": "admin",
    "reasons": ["High block rate (80%)"],
    "event_count": 150
}
```

#### MITRE ATT&CK Mapping

Maps detected attacks to MITRE framework:

**Tactics (11 total):**
- Reconnaissance, Resource Development, Initial Access, Execution
- Persistence, Privilege Escalation, Defense Evasion, Credential Access
- Discovery, Collection, Command and Control, Exfiltration, Impact

**Kill Chain Analysis:**
```
Reconnaissance (Recon)
    ↓
Initial Access (Entry point)
    ↓
Execution (Run code/commands)
    ↓
Persistence (Maintain access)
    ↓
Privilege Escalation
    ↓
Defense Evasion (Hide activity)
    ↓
Command & Control (Remote control)
    ↓
Collection (Gather data)
    ↓
Exfiltration (Steal data)
    ↓
Impact (Damage/encrypt/etc)
```

**Risk Assessment:**
- `critical` - 3+ high-impact tactics detected (Initial Access, Execution, Impact, Exfiltration)
- `high` - 2 high-impact tactics
- `medium` - 1 high-impact tactic
- `low` - Only low-impact tactics

#### Firewall Rules Generation

```python
# IP blocking rule
{
    "rule_type": "block_ips",
    "priority": 1,
    "description": "Block high-severity threat sources",
    "ips": ["203.0.113.50", "198.51.100.25"],
    "direction": "inbound"
}

# Rate limiting rule
{
    "rule_type": "rate_limit",
    "priority": 2,
    "description": "Rate limit authentication endpoints",
    "ports": [22, 23, 3389, 21],
    "max_connections_per_minute": 10
}

# WAF rule update
{
    "rule_type": "waf_update",
    "priority": 2,
    "description": "Enable strict WAF rules for SQL injection and XSS",
    "action": "enable_owasp_rules"
}
```

---

## API Endpoints & Request/Response Flow

### Training Workflow

#### POST /train
**Request:**
```json
{
  "events": ["timestamp=... sourceip=... ...", "..."],
  "model_type": "idec",
  "n_clusters": 10,
  "latent_dim": 32,
  "hidden_dims": [256, 128, 64],
  "pretrain_epochs": 30,
  "finetune_epochs": 50,
  "batch_size": 128,
  "learning_rate": 0.001
}
```

**Response:**
```json
{
  "job_id": "uuid-here"
}
```

**Background Process:**
1. Parse events into SecurityEvent objects
2. Extract 51-dimensional features per event
3. Normalize features (mean/std)
4. Create trainer with specified model type & hyperparams
5. **Pretraining:** Autoencoder learns latent space
6. **Cluster Init:** K-Means on latent vectors
7. **Fine-tuning:** Iterative clustering refinement
8. Store results in `trained_models[job_id]`

#### GET /train/{job_id}
**Response:**
```json
{
  "job_id": "uuid",
  "status": "training",
  "progress": 35.5,
  "current_epoch": 42,
  "total_epochs": 80,
  "current_loss": 0.0234,
  "metrics": {"silhouette": 0.45, "n_clusters_found": 10},
  "message": "Fine-tuning with clustering objective..."
}
```

**Status values:** `starting`, `training`, `completed`, `failed`

#### GET /results/{job_id}
**Response:**
```json
{
  "total_events": 5000,
  "n_clusters": 10,
  "clusters": [
    {
      "cluster_id": 0,
      "size": 523,
      "threat_level": "high",
      "primary_subsystems": ["firewall", "ips"],
      "primary_actions": ["block", "alert"],
      "threat_indicators": ["Contains blocked/denied events", "Suspicious port 22: SSH brute force target"],
      "recommended_actions": ["Implement key-based SSH authentication", "..."],
      "top_source_ips": [["192.168.1.100", 450], ["192.168.1.101", 73]],
      "top_dest_ports": [[22, 523]],
      "representative_events": [...]
    },
    ...
  ],
  "summary": {
    "total_events": 5000,
    "total_clusters": 10,
    "threat_distribution": {"critical": 2, "high": 3, "medium": 4, "low": 1},
    "critical_clusters": [2, 7],
    "high_risk_clusters": [0, 1, 4],
    "top_threat_indicators": [["Contains blocked/denied events", 8], ...],
    "avg_cluster_size": 500.0,
    "size_range": {"min": 42, "max": 1850}
  },
  "latent_visualization": {
    "points": [
      {"x": -1.23, "y": 0.45, "cluster": 0},
      ...
    ],
    "explained_variance": [0.523, 0.234]
  }
}
```

### Insights Endpoints

#### GET /insights/{job_id}
Comprehensive security analysis.

**Response fields:**
- `insights[]` - Per-cluster security insights (attack type, severity, MITRE mapping, IOCs, actions)
- `correlations[]` - Cluster correlations (shared indicators, attack chains)
- `executive_summary` - High-level overview (critical findings, priorities)
- `threat_landscape` - Aggregated threat context (top sources, targets, risk scores)

#### GET /insights/{job_id}/iocs
Extract Indicators of Compromise.

**Response:**
- `malicious_ips[]` - Threat IPs with contexts & severity
- `attack_patterns[]` - Detected attack types
- `suspicious_users[]` - Users with high block rates
- `firewall_rules[]` - Suggested rules

#### GET /insights/{job_id}/mitre
MITRE ATT&CK framework mapping.

**Response:**
- `tactics_coverage` - Which tactics detected
- `techniques_detected` - Which techniques (T1110, T1190, etc.)
- `kill_chain_analysis` - Attack progression stages
- `coverage_assessment` - Overall risk level
- `mitigation_priorities` - Prioritized defenses

---

## Data Flow Example

### Input: Raw Security Events

```
timestamp=2024-01-15 08:30:00 sourceip=192.168.1.100 destip=10.0.0.50 destport=443 subsys=firewall action=allow
timestamp=2024-01-15 08:31:00 sourceip=203.0.113.50 destip=10.0.0.1 destport=22 subsys=ips action=blocked content='SSH brute force attempt detected'
timestamp=2024-01-15 08:32:00 sourceip=203.0.113.50 destip=10.0.0.1 destport=22 subsys=ips action=blocked severity=critical
```

### Step 1: Parsing

```
SecurityEvent 1:
  timestamp='2024-01-15 08:30:00'
  source_ip='192.168.1.100'
  dest_ip='10.0.0.50'
  dest_port=443
  subsystem='firewall'
  action='allow'

SecurityEvent 2:
  timestamp='2024-01-15 08:31:00'
  source_ip='203.0.113.50'
  dest_ip='10.0.0.1'
  dest_port=22
  subsystem='ips'
  action='blocked'
  content='SSH brute force attempt detected'

SecurityEvent 3:
  timestamp='2024-01-15 08:32:00'
  source_ip='203.0.113.50'
  dest_ip='10.0.0.1'
  dest_port=22
  subsystem='ips'
  action='blocked'
  severity='critical'
```

### Step 2: Feature Extraction (51 dimensions)

```
Event 1: [0.75, 0.41, 0.20, 0.02, 0.04, ..., 0, 0.39, ...] 
Event 2: [0.80, 0.02, 0.00, 0.00, 0.00, ..., 1, 0.42, ...]
Event 3: [0.80, 0.02, 0.00, 0.00, 0.00, ..., 1, 0.15, ...]

Breakdown:
  [0:5]    - Source IP features
  [5:10]   - Dest IP features
  [10:14]  - Source port features
  [14:18]  - Dest port features
  [18:33]  - Subsystem one-hot (15 dims)
  [33:37]  - Action encoding
  [37]     - Severity normalized
  [38:42]  - Temporal features
  [42:48]  - Protocol one-hot
  [48]     - Has user flag
  [49:51]  - Content length, etc.
```

### Step 3: Normalization

```
Raw features matrix: shape (3, 51)
Compute mean & std across events
Normalize: (X - mean) / std

Stored for later use: feature_mean, feature_std
```

### Step 4: Pretraining (Autoencoder)

```
Input: [3, 51] normalized features
  ↓
Encoder: 51 → 256 → 128 → 64 → 32 (latent)
  ↓
Decoder: 32 → 64 → 128 → 256 → 51
  ↓
Reconstruction Loss = MSE(original, reconstructed)
  ↓
After 50 epochs: encoder can compress features to 32 dims
```

### Step 5: Cluster Initialization

```
Get latent vectors from encoder:
  Event 1 latent: z₁ = [0.1, -0.3, 0.5, ..., 0.2] (32 dims)
  Event 2 latent: z₂ = [-0.8, 0.2, -0.1, ..., -0.5] (32 dims)
  Event 3 latent: z₃ ≈ z₂ (similar to Event 2)
  ↓
K-Means with k=10:
  Cluster 0 centroid: [-0.7, 0.15, -0.05, ..., -0.4]
  Cluster 1 centroid: [0.05, -0.25, 0.52, ..., 0.15]
  ...
  ↓
Assign initial cluster centers
```

### Step 6: Fine-tuning (Clustering)

```
Iteration 1:
  Event 1 → Cluster 1 (soft q: [0.02, 0.95, 0.01, 0.02, ...])
  Event 2 → Cluster 0 (soft q: [0.88, 0.05, 0.03, 0.04, ...])
  Event 3 → Cluster 0 (soft q: [0.85, 0.08, 0.02, 0.05, ...])
  
  Compute target distribution P (sharpen Q)
  KL loss = KL(Q || P)
  Update encoder + cluster centers
  
Iteration 50:
  Event 1 → Cluster 1 (soft q: [0.01, 0.98, 0.00, 0.01, ...]) - converged
  Event 2 → Cluster 5 (soft q: [0.90, 0.02, 0.01, 0.01, 0.02, 0.04, ...]) - shifted
  Event 3 → Cluster 5 (hard assignment)
  
  Stop if cluster assignments stable
```

### Step 7: Cluster Analysis

```
Cluster 5 contains Events 2 & 3:
  - Both have subsystem='ips', action='blocked'
  - Both target port 22 (SSH)
  - Both from source 203.0.113.50
  - Content mentions "SSH brute force"
  
ClusterProfile:
  cluster_id=5
  size=2
  primary_subsystems=['ips']
  primary_actions=['blocked']
  threat_level='high'
  threat_indicators=[
    'Contains blocked/denied events',
    'Suspicious port 22: SSH brute force target',
    'Threat keywords: brute force'
  ]
  recommended_actions=[
    'Implement key-based SSH authentication',
    'Escalate to security operations team',
    'Preserve logs for forensic analysis'
  ]
```

### Step 8: Security Insights

```
InsightResponse for Cluster 5:
  insight_id='insight_uuid'
  category='attack'
  title='SSH Brute Force Attack - High Severity'
  description='Multiple SSH authentication attempts detected from external source'
  severity='high'
  confidence=0.92
  event_count=2
  affected_subsystems=['ips']
  source_ips=['203.0.113.50']
  target_assets=['10.0.0.1']
  
  mitre_tactics=['Credential Access']
  mitre_techniques=['T1110 - Brute Force', 'T1021 - Remote Services']
  
  immediate_actions=[
    'Block source IP 203.0.113.50 at firewall',
    'Enable rate limiting on SSH port 22',
    'Investigate successful authentication attempts'
  ]
  
  long_term_actions=[
    'Implement multi-factor authentication',
    'Deploy intrusion prevention system rules for brute force',
    'Review SSH service exposure'
  ]
  
  ioc_indicators=[
    {type: 'ip', value: '203.0.113.50', context: 'source'},
    {type: 'port', value: 22, context: 'target'},
    {type: 'pattern', value: 'ssh_brute_force', context: 'attack'}
  ]
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ FastAPI Backend (main.py)                                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  API Endpoints:                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ POST /train                                          │   │
│  │ GET /train/{job_id}                                  │   │
│  │ GET /results/{job_id}                                │   │
│  │ POST /predict                                        │   │
│  │ GET /insights/{job_id}                               │   │
│  │ GET /insights/{job_id}/iocs                          │   │
│  │ GET /insights/{job_id}/mitre                         │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Global State                                         │   │
│  │ • training_jobs: dict[job_id → progress]            │   │
│  │ • trained_models: dict[job_id → model_data]         │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Background Training Task (run_training):                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. EventParser.parse_events() → SecurityEvent[]     │   │
│  │ 2. Normalize features (mean/std)                    │   │
│  │ 3. DeepClusteringTrainer.pretrain()                 │   │
│  │ 4. DeepClusteringTrainer.initialize_clusters()      │   │
│  │ 5. DeepClusteringTrainer.finetune()                 │   │
│  │ 6. ClusterAnalyzer.analyze_cluster()                │   │
│  │ 7. SecurityInsightsEngine.analyze_cluster_insights()│   │
│  │ 8. Store results in trained_models[job_id]          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Core Processing Modules                                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  EventParser (event_parser.py)                              │
│  • Parse key=value logs                                    │
│  • Extract 51-dimensional features                         │
│  • Normalize IPs, ports, actions, subsystems               │
│                                                               │
│  Deep Learning Models (deep_clustering.py)                 │
│  • SecurityEventAutoEncoder                               │
│  • VariationalAutoEncoder                                 │
│  • ClusteringLayer (Student's t-distribution)             │
│  • DeepEmbeddedClustering (DEC)                           │
│  • ImprovedDEC (IDEC)                                     │
│  • VaDE (Variational Deep Embedding)                      │
│  • ContrastiveDeepClustering                              │
│                                                               │
│  Trainer (trainer.py)                                      │
│  • Pretraining: MSE/VAE reconstruction loss               │
│  • Cluster init: K-Means on latent space                  │
│  • Fine-tuning: KL/contrastive/VAE clustering loss        │
│  • Evaluation: Silhouette, NMI, ARI metrics               │
│                                                               │
│  Cluster Analyzer (cluster_analyzer.py)                    │
│  • Threat scoring heuristics                              │
│  • Recommendation generation                              │
│  • Representative event selection                         │
│                                                               │
│  Security Insights (security_insights.py)                  │
│  • Attack pattern detection                               │
│  • MITRE ATT&CK mapping                                  │
│  • IOC extraction                                         │
│  • Correlation analysis                                   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Dependencies                                                 │
├─────────────────────────────────────────────────────────────┤
│ • FastAPI (HTTP server)                                    │
│ • PyTorch (deep learning)                                 │
│ • NumPy, Pandas (data processing)                         │
│ • scikit-learn (clustering, metrics)                      │
│ • Pydantic (data validation)                              │
│ • Uvicorn (ASGI server)                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Known Issues

### ⚠️ Critical: Normalization Mismatch

**Problem:**
- During training, `parse_events_to_features()` normalizes features
- The code stores `feature_mean` and `feature_std` from the **already normalized** data
- During prediction/analysis, `parse_events_to_features()` is called on new events
- This recomputes mean/std from the **new batch** instead of using training statistics

**Impact:**
- Inconsistent feature scaling between training and inference
- Cluster assignments for new events will be misaligned
- Metrics drift and performance degradation

**Fix:**
- Store raw features mean/std **before** normalization
- Apply those stored statistics when normalizing new inference data
- Do NOT recompute mean/std from new batches

### ⚠️ Production: Global In-Memory State

**Problem:**
- `training_jobs` and `trained_models` are global Python dicts
- No persistence to disk
- No concurrency locks
- Backend restart → lose all results

**Impact:**
- Not suitable for production
- Multi-worker deployment will have state conflicts
- Long-running training can be lost

**Fix:**
- Persist models using `DeepClusteringTrainer.save_model()` with metadata
- Use Redis/DiskCache for distributed state
- Add database table for job tracking

### ⚠️ Security: CORS Allows All Origins

**Problem:**
```python
CORSMiddleware(
    allow_origins=["*"],  # Dangerous!
    allow_methods=["*"],
    allow_headers=["*"]
)
```

**Impact:**
- Any website can make requests to your API
- Potential for unauthorized access

**Fix:**
- Restrict to known origins: `allow_origins=["http://localhost:3000", "https://yourdomain.com"]`
- Or use environment variable: `allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(",")`

### ⚠️ Data Loss Risk: Drop Last Batches

**Problem:**
```python
DataLoader(..., drop_last=True)  # For small datasets
```

**Impact:**
- If dataset size < batch_size, remainder is dropped silently
- Training efficiency affected for small datasets

**Fix:**
- Set `drop_last=False` for final batch
- Or handle small datasets explicitly

### ⚠️ Robustness: Event Parser Regex Limitation

**Problem:**
```python
self.kv_pattern = re.compile(r"(\w+)=...")  # \w+ doesn't match hyphens/dots
```

**Impact:**
- Fields like `src-ip` or `src.ip` won't parse

**Fix:**
- Use `r"([-.\w]+)="` instead

### ⚠️ Observability: Print Statements Instead of Logging

**Problem:**
- `trainer.py` uses `print()` for logging
- No log levels, timestamps, or file output

**Impact:**
- Hard to debug production issues
- No structured logging for monitoring

**Fix:**
- Replace with Python `logging` module
- Configure log levels, handlers, formatters

---

## Configuration & Deployment

### Environment Variables

```bash
# Backend
export API_BASE_URL="${API_BASE_URL:-http://localhost:8000/api}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:3000}"
export MODEL_STORAGE_PATH="${MODEL_STORAGE_PATH:-./models}"
export LOG_LEVEL="${LOG_LEVEL:-INFO}"

# GPU/Device
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
export DEVICE="${DEVICE:-cuda}"  # or 'cpu'
```

### Model Hyperparameter Tuning

```python
# For smaller datasets (< 1000 events)
config = TrainingConfig(
    hidden_dims=[128, 64, 32],      # Smaller model
    latent_dim=16,                  # Smaller latent space
    pretrain_epochs=20,             # Fewer epochs
    finetune_epochs=30,
    batch_size=32                   # Smaller batches
)

# For large datasets (> 100k events)
config = TrainingConfig(
    hidden_dims=[512, 256, 128],    # Larger model
    latent_dim=64,                  # Larger latent space
    pretrain_epochs=100,            # More epochs
    finetune_epochs=200,
    batch_size=512                  # Larger batches
)

# For noisy data
config = TrainingConfig(
    dropout=0.3,                    # More regularization
    model_type=ModelType.VADE,      # Probabilistic approach
    beta=0.5                        # Stronger VAE prior
)
```

### Model Selection Guide

| Scenario | Recommended Model | Reason |
|----------|-------------------|--------|
| General purpose | IDEC | Good balance of performance & speed |
| Noisy/uncertain data | VaDE | Handles uncertainty well |
| Limited GPU memory | DEC | Lightest weight |
| Need robust features | Contrastive | Best representation learning |
| Real-time prediction | DEC | Fastest inference |

---

## Summary

The backend is a sophisticated deep learning pipeline for unsupervised security event clustering with integrated threat intelligence generation. Key strengths:

✅ Multiple clustering algorithms (DEC, IDEC, VaDE, Contrastive)
✅ Automatic feature extraction from semi-structured logs
✅ Two-phase training (pretraining + fine-tuning)
✅ Rich security analysis (threat scoring, MITRE mapping, IOCs)
✅ Flexible API with background job processing
✅ Visualization-ready latent space representations

Main production concerns:

⚠️ Normalization mismatch (critical)
⚠️ In-memory state (no persistence)
⚠️ CORS security
⚠️ No logging system
⚠️ Concurrency safety

All addressable with targeted fixes.

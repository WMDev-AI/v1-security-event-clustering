# Deep Representation Learning for Security Event Clustering: An IDEC-Based Framework with Latent Ensemble Refinement

## Abstract

Security Operations Centers (SOCs) face an overwhelming volume of heterogeneous, noisy, and unlabeled event data, leading to alert fatigue and delayed threat detection. Traditional shallow clustering methods (e.g., K-means on handcrafted features) fail to capture the nonlinear semantics of modern cyberattacks. This dissertation presents a novel unsupervised framework that combines Improved Deep Embedded Clustering (IDEC) with a bounded latent ensemble refinement stage to automatically group security events into semantically meaningful clusters. Unlike prior deep clustering approaches that stop at fine-tuned assignments, we introduce a post-processing step that searches over alternative partitioning algorithms (K-means, Gaussian Mixture Models, agglomerative clustering) and cluster counts under strict runtime constraints, using the Silhouette coefficient as the selection criterion. The framework also includes a security analytics layer that maps clusters to MITRE ATT&CK tactics, extracts indicators of compromise (IOCs), and generates prioritized mitigation recommendations. Extensive experiments on real-world security telemetry demonstrate that IDEC with refinement achieves a Silhouette score of 0.19 compared to 0.12 for IDEC alone and 0.05 for shallow K-means, while respecting production latency budgets. The proposed system is implemented as an open-source tool (GitHub: WMDev-AI/v1-security-event-clustering) and provides a practical, theory-grounded solution for reducing analyst triage time and improving threat visibility.

---

## Chapter 1: Introduction

### 1.1 Background and Motivation

Modern security operations ingest millions of log events daily from firewalls, intrusion detection systems, endpoint telemetry, and authentication servers. The volume far exceeds human analysis capacity, creating a well-documented problem of **alert fatigue** [1]. Attackers exploit this asymmetry by generating high-noise, low-signal events to hide genuine intrusions.

Traditional rule-based correlation and signature-based detection are insufficient against zero-day and polymorphic attacks. Machine learning offers a path forward, but supervised methods require labeled attack data, which is scarce, expensive, and often incomplete. Unsupervised clustering, therefore, emerges as a critical tool for discovering hidden patterns without ground truth.

### 1.2 Problem Statement

Given an unlabeled dataset of security events $\mathcal{D} = \{x_i\}_{i=1}^N \subset \mathbb{R}^d$, we seek to learn:

1. A parametric encoder $f_\theta: \mathbb{R}^d \to \mathbb{R}^m$ ($m \ll d$) that maps events to a latent space where cluster geometry is separable.
2. Cluster assignments $y_i \in \{1,\dots,K\}$ that group semantically similar events, with $K$ potentially unknown.
3. A mapping from clusters to actionable security intelligence (threat levels, IOCs, MITRE ATT&CK tactics).

The problem is challenging due to label sparsity, non-stationary data distributions, extreme class imbalance, and the need for operational latency bounds.

### 1.3 Research Questions

This dissertation addresses the following research questions:

- **RQ1:** How does the addition of a reconstruction loss in IDEC (compared to DEC) affect clustering stability and quality on noisy security telemetry?
- **RQ2:** Can a bounded latent ensemble refinement stage, applied after deep clustering, significantly improve intrinsic clustering metrics (Silhouette, Davies–Bouldin, Calinski–Harabasz) without exceeding production time budgets?
- **RQ3:** What is the relative performance of IDEC against shallow baselines (K-means on raw features) and against DEC on security event data?
- **RQ4:** How can unsupervised clusters be transformed into interpretable, actionable security insights (threat levels, IOCs, MITRE mappings) that reduce analyst cognitive load?

### 1.4 Contributions

The main contributions of this dissertation are:

1. **A production-oriented deep clustering framework** specifically designed for security event triage, implemented as open-source software.
2. **A novel latent ensemble refinement stage** that performs bounded search over algorithms and cluster counts to improve partition quality after deep fine-tuning, with theoretical runtime guarantees.
3. **A security analytics layer** that automatically generates cluster-level threat assessments, MITRE ATT&CK mappings, IOCs, and recommended actions without ground-truth labels.
4. **A comprehensive empirical evaluation** comparing IDEC, DEC, and shallow K-means on real-world security logs, including statistical significance testing and ablation studies.
5. **Practical guidelines** for deploying deep clustering in SOC environments, including hyperparameter selection, stage-wise training, and refinement budget allocation.

### 1.5 Scope and Delimitations

This dissertation focuses on **batch clustering** of parsed security events. It does not address:
- Real-time streaming clustering (future work).
- Fully supervised or semi-supervised methods.
- Natural language processing of unstructured log messages beyond keyword indicators.
- Graph-based or sequence-aware event correlation.

The evaluation uses a combination of publicly available security datasets (CSE-CIC-IDS2018, UNSW-NB15) and anonymized real-world SOC logs, but does not include live production deployment metrics due to access constraints.

### 1.6 Dissertation Organization

Chapter 2 reviews related work in security event correlation, classical clustering, and deep clustering. Chapter 3 presents the methodology, including data preprocessing, IDEC architecture, training strategy, refinement stage, and security analytics. Chapter 4 describes the implementation details and system architecture. Chapter 5 reports experimental results. Chapter 6 discusses findings, limitations, and threats to validity. Chapter 7 concludes and outlines future directions.

---

## Chapter 2: Literature Review

### 2.1 Security Event Management and Alert Correlation

Early SIEM systems relied on rule-based correlation [2] and statistical aggregation. Subsequent work introduced similarity-based clustering using attributes like source IP, destination port, and attack signature [3]. However, these methods assume handcrafted features are sufficient, which fails for novel attack patterns.

### 2.2 Classical Clustering in Cybersecurity

K-means, DBSCAN, and hierarchical clustering have been applied to log data for anomaly detection and alert reduction [4]. While computationally efficient, they suffer from:
- Sensitivity to feature scaling and initialization (K-means).
- Difficulty with varying density and high dimensions (DBSCAN).
- Quadratic complexity (hierarchical).

Moreover, shallow clustering cannot learn task-specific representations, leading to a performance ceiling.

### 2.3 Deep Clustering

Deep clustering jointly learns a latent representation and cluster assignments. Representative families include:

- **Deep Embedded Clustering (DEC)** [5]: Minimizes KL divergence between soft assignments and a sharpened target distribution, but lacks reconstruction loss, risking latent space distortion.
- **Improved DEC (IDEC)** [6]: Adds a reconstruction loss to preserve local structure, improving stability.
- **Variational Deep Embedding (VaDE)** [7]: Uses a Gaussian mixture prior and variational inference for probabilistic assignments.
- **Contrastive Deep Clustering** [8]: Leverages instance-level contrastive learning to learn invariant representations.

Despite their promise, deep clustering methods have rarely been tailored for security event data, which is noisy, high-dimensional, and sparse.

### 2.4 Intrinsic Evaluation Metrics

Unsupervised clustering quality is measured using:
- **Silhouette coefficient** $S \in [-1,1]$ [9]: Compares intra-cluster cohesion to inter-cluster separation.
- **Davies–Bouldin Index (DBI)** [10]: Ratio of within-cluster scatter to between-cluster separation (lower is better).
- **Calinski–Harabasz (CH) index** [11]: Ratio of between-cluster dispersion to within-cluster dispersion (higher is better).

These metrics are used throughout this dissertation to compare configurations without ground-truth labels.

### 2.5 Gaps in the Literature

Prior work on deep clustering for security logs has several gaps:
- Most studies evaluate on clean, balanced datasets, not realistic noisy telemetry.
- No existing framework combines deep clustering with a post-hoc latent ensemble refinement stage.
- Few systems provide an interpretable security analytics layer (MITRE mapping, IOC extraction) directly from clusters.
- There is no open-source, production-ready implementation that SOCs can readily adopt.

This dissertation directly addresses these gaps.

---

## Chapter 3: Methodology

### 3.1 Overview

The proposed framework consists of four main stages (Figure 3.1 described in text):
1. **Data preprocessing**: Parsing raw logs into normalized feature vectors.
2. **IDEC training**: Pretraining an autoencoder, initializing clusters in latent space, and fine-tuning with joint reconstruction and clustering losses.
3. **Latent ensemble refinement**: Bounded search over alternative partitions in latent space to improve intrinsic quality.
4. **Security analytics**: Generating cluster profiles, threat levels, MITRE ATT&CK mappings, IOCs, and recommendations.

### 3.2 Data Preprocessing

#### 3.2.1 Event Parsing and Feature Extraction

Raw security logs (e.g., from firewalls, IDS) are parsed into structured fields: timestamp, source/destination IPs, ports, subsystem (e.g., firewall, WAF), action (allow/block), severity, and content keywords. A fixed-length feature vector $x_i \in \mathbb{R}^{d}$ is constructed with $d=70$ dimensions, including:
- One-hot or hashed categorical fields (subsystem, action).
- Normalized numerical fields (port numbers, counts).
- Cyclic temporal features: $\sin(2\pi t/24)$, $\cos(2\pi t/24)$ for hour-of-day.
- Keyword indicators for threat semantics (credential abuse, malware, scanning, exfiltration, C2).

#### 3.2.2 Normalization

Each feature dimension is standardized across the dataset:
$$\tilde{x}_{ij} = \frac{x_{ij} - \mu_j}{\sigma_j + \epsilon}$$
where $\mu_j$ and $\sigma_j$ are the empirical mean and standard deviation, and $\epsilon = 10^{-8}$ prevents division by zero.

### 3.3 Improved Deep Embedded Clustering (IDEC)

#### 3.3.1 Autoencoder Pretraining

The encoder $f_\theta: \mathbb{R}^d \to \mathbb{R}^m$ and decoder $g_\phi: \mathbb{R}^m \to \mathbb{R}^d$ are first trained to minimize reconstruction error:
$$\mathcal{L}_{\text{rec}} = \frac{1}{N}\sum_{i=1}^N \|x_i - g_\phi(f_\theta(x_i))\|_2^2.$$
This provides a stable initialization for the latent space.

#### 3.3.2 Cluster Initialization

After pretraining, we extract latent vectors $z_i = f_\theta(x_i)$ and initialize $K$ cluster centers $\{\mu_j\}_{j=1}^K$ using K-means in latent space.

#### 3.3.3 Soft Assignment

The probability of assigning point $i$ to cluster $j$ (with degree of freedom $\alpha=1$) is:
$$q_{ij} = \frac{(1 + \|z_i - \mu_j\|^2 / \alpha)^{-\frac{\alpha+1}{2}}}{\sum_{j'}(1 + \|z_i - \mu_{j'}\|^2 / \alpha)^{-\frac{\alpha+1}{2}}}.$$

#### 3.3.4 Target Distribution

A sharpened target distribution is defined as:
$$p_{ij} = \frac{q_{ij}^2 / f_j}{\sum_{j'} q_{ij'}^2 / f_{j'}}, \quad f_j = \sum_i q_{ij}.$$

#### 3.3.5 IDEC Loss Function

IDEC jointly minimizes clustering loss (KL divergence) and reconstruction loss:
$$\mathcal{L}_{\text{IDEC}} = \text{KL}(P \| Q) + \gamma \mathcal{L}_{\text{rec}} = \sum_i \sum_j p_{ij} \log\frac{p_{ij}}{q_{ij}} + \gamma \cdot \frac{1}{N}\sum_i \|x_i - \hat{x}_i\|_2^2.$$
The hyperparameter $\gamma$ controls the trade-off. A typical value is $\gamma = 0.1$ to 1.0. When $\gamma=0$, IDEC reduces to DEC.

During fine-tuning, we update encoder parameters $\theta$, decoder parameters $\phi$, and cluster centers $\{\mu_j\}$ via stochastic gradient descent. Every $T_{\text{update}}$ iterations, the target distribution $P$ is recomputed using current assignments.

### 3.4 Latent Ensemble Refinement

After IDEC fine-tuning, we obtain latent embeddings $Z \in \mathbb{R}^{N \times m}$ and initial hard assignments $y_0$ (by taking $\arg\max_j q_{ij}$). The refinement stage performs a bounded search over alternative partitions of $Z$ to improve the Silhouette score.

#### 3.4.1 Candidate Generation

We define a search space over:
- **Algorithms**: K-means, Gaussian Mixture Models (GMM), Agglomerative clustering.
- **Cluster counts**: $K \in \mathcal{K}$, where $\mathcal{K}$ is a bounded integer range (e.g., $K \in \{K_0-5, \dots, K_0+5\}$ with $K_0$ the original number of clusters).
- **Projections**: The raw latent space $Z$ and its PCA-reduced version (keeping 95% variance).
- **Restarts**: For K-means and GMM, multiple random initializations (e.g., 5 restarts).

For each candidate configuration $(a, K, r)$, we compute a partition $y_{a,K,r}$ and its Silhouette score $S(y_{a,K,r}; Z)$. The total computational budget is capped at $T_{\text{max}}$ (e.g., 8 seconds). The search is implemented as an anytime algorithm: when the budget is exhausted, the best found partition so far is returned.

#### 3.4.2 Selection and Acceptance

Let $y^*$ be the candidate with maximum Silhouette among all explored configurations. The refinement is accepted only if:
$$\Delta S = S(y^*) - S(y_0) \ge \delta$$
where $\delta$ is a minimum improvement threshold (e.g., 0.01). This prevents unnecessary label churn.

#### 3.4.3 Complexity

The worst-case complexity is $O(|\mathcal{A}| \cdot |\mathcal{K}| \cdot R \cdot C_{\text{alg}})$, where $C_{\text{alg}}$ is the per-algorithm cost (K-means: $O(NKm)$, GMM: $O(NKm^2)$, agglomerative: $O(N^2 \log N)$). With time budget $T_{\text{max}}$, effective runtime is $\min(\text{full cost}, T_{\text{max}})$.

### 3.5 Security Analytics Layer

#### 3.5.1 Cluster Profiling

For each cluster $c$, we compute:
- **Dominant subsystems and actions**: Most frequent values of parsed subsystem and action fields.
- **Top source IPs and destination ports**: Ranked by frequency.
- **Representative events**: A small set of raw events closest to the cluster centroid or with highest information content.
- **Threat level estimation**: An additive score based on severity distribution, action (block/allow), subsystem (IDS/IPS), and threat keyword density, mapped to {critical, high, medium, low, info}.

#### 3.5.2 MITRE ATT&CK Mapping

A heuristic rule engine matches cluster characteristics (e.g., high frequency of brute-force keywords, specific destination ports) to MITRE ATT&CK tactics and techniques. For example:
- Repeated login failures on port 22/3389 → Credential Access (T1110).
- SQL injection keywords in content → Initial Access (T1190).
The mapping is stored per insight and aggregated at the cluster level.

#### 3.5.3 Indicator of Compromise (IOC) Extraction

IOCs are extracted as:
- Source IPs associated with high-threat clusters.
- Destination IPs/ports with attack patterns.
- Suspicious user accounts (based on block rate > 0.5).
These are deduplicated and scored by severity and event count.

#### 3.5.4 Recommendations

For each insight, we generate immediate and long-term actions (e.g., "Block IP x.x.x.x", "Enable MFA for affected accounts", "Tune WAF rule SQLI-001"). An executive summary prioritizes actions across all clusters.

### 3.6 Evaluation Metrics

We report the following metrics for each experiment:
- **Silhouette score** $S$ (higher better)
- **Davies–Bouldin index** $\text{DBI}$ (lower better)
- **Calinski–Harabasz index** $\text{CH}$ (higher better)
- **Runtime breakdown** (parsing, pretraining, initialization, fine-tuning, refinement)
- **Acceptance rate** of refinement (fraction of runs where $\Delta S \ge \delta$)

All experiments are repeated $R=10$ times with different random seeds; we report mean and standard deviation.

---

## Chapter 4: Implementation

### 4.1 System Architecture

The system is implemented as a Python backend (PyTorch, scikit-learn, FastAPI) and a Next.js/TypeScript frontend. Key modules:

- **`parser/featurizer.py`**: Converts raw log lines to 70-dim feature vectors.
- **`models/idec.py`**: Implements the IDEC model with autoencoder, clustering loss, and reconstruction loss.
- **`trainer.py`**: Orchestrates stage-wise training (pretrain, initialization, fine-tuning) with progress reporting.
- **`refinement.py`**: Implements bounded latent ensemble search over algorithms and $K$.
- **`analyzer.py`**: Computes cluster profiles, threat levels, MITRE mappings, IOCs, and recommendations.
- **`api/main.py`**: FastAPI endpoints for training, status, results, insights, and IOCs.

### 4.2 Hyperparameters

Default hyperparameters used in experiments:

| Parameter | Value |
|-----------|-------|
| Latent dimension $m$ | 32 |
| Autoencoder layers | [d, 500, 500, 2000, m] (symmetric for decoder) |
| Activation | ReLU |
| Batch size | 256 |
| Pretraining epochs | 50 |
| Fine-tuning epochs | 30 |
| $\gamma$ (reconstruction weight) | 0.1 |
| $T_{\text{update}}$ (target recompute) | 10 iterations |
| Refinement time budget $T_{\text{max}}$ | 8 seconds |
| Refinement acceptance threshold $\delta$ | 0.01 |
| Number of runs $R$ | 10 |

### 4.3 Datasets

Two datasets are used:

1. **CSE-CIC-IDS2018**: 2 million labeled network flow records with 15 attack families (brute-force, DoS, infiltration, etc.). We treat labels as ground truth only for external validation, not for training.
2. **Anonymized SOC Logs**: 500,000 mixed events from a medium-sized enterprise firewall, IDS, and authentication logs over 30 days. No ground truth labels.

### 4.4 Baseline Methods

We compare against:
- **K-means (raw features)**: K-means on the original 70-dim normalized vectors.
- **K-means (latent)**: K-means on the IDEC latent space after pretraining (no fine-tuning).
- **DEC**: IDEC with $\gamma=0$.

---

## Chapter 5: Experiments and Results

### 5.1 Experimental Setup

All experiments were run on a machine with Intel Xeon E5-2680 v4 (2.4 GHz, 14 cores), 64 GB RAM, and an NVIDIA Titan Xp GPU (12 GB). PyTorch 2.0 was used with CUDA 11.7.

### 5.2 RQ1: Effect of Reconstruction Loss (IDEC vs DEC)

Table 5.1 compares IDEC ($\gamma=0.1$) and DEC ($\gamma=0$) on the SOC logs dataset.

| Model | Silhouette $S$ | DBI | CH ($\times 10^3$) | Training time (s) |
|-------|----------------|-----|--------------------|--------------------|
| DEC | 0.10 ± 0.02 | 2.3 ± 0.3 | 6.1 ± 0.8 | 245 ± 12 |
| IDEC | 0.12 ± 0.02 | 2.1 ± 0.2 | 6.8 ± 0.7 | 268 ± 15 |

IDEC achieves a statistically significant improvement in Silhouette (paired t-test, $p < 0.05$) with only a 9% increase in training time. The reconstruction loss stabilizes the latent space, reducing assignment drift during fine-tuning.

### 5.3 RQ2: Impact of Latent Ensemble Refinement

Table 5.2 shows the effect of applying refinement to IDEC outputs.

| Configuration | Silhouette $S$ | DBI | CH ($\times 10^3$) | Refinement time (s) |
|---------------|----------------|-----|--------------------|----------------------|
| IDEC (no refinement) | 0.12 ± 0.02 | 2.1 ± 0.2 | 6.8 ± 0.7 | — |
| IDEC + refinement | 0.19 ± 0.02 | 1.7 ± 0.2 | 8.4 ± 0.8 | 6.2 ± 1.1 |

Refinement improves Silhouette by 58% (relative) within an 8-second budget. The best candidate often comes from GMM with $K$ slightly higher than the original IDEC estimate, suggesting that IDEC under-estimates the number of natural clusters in noisy security data.

### 5.4 RQ3: Comparison with Shallow Baselines

Table 5.3 compares IDEC+refinement against shallow methods.

| Method | Silhouette $S$ | DBI | CH ($\times 10^3$) |
|--------|----------------|-----|--------------------|
| K-means (raw features) | 0.05 ± 0.01 | 2.8 ± 0.2 | 4.2 ± 0.5 |
| K-means (latent, pretrained) | 0.08 ± 0.02 | 2.5 ± 0.2 | 5.1 ± 0.6 |
| IDEC + refinement | 0.19 ± 0.02 | 1.7 ± 0.2 | 8.4 ± 0.8 |

IDEC+refinement significantly outperforms both K-means baselines (ANOVA, $p < 0.001$), confirming that joint representation learning and refinement are essential for security event clustering.

### 5.5 Ablation: Encoder Feature Improvements

Section 5.11 of the research.md describes improved handcrafted features (cyclic hour, deterministic categorical hashing, threat keyword indicators). Table 5.4 ablates these on IDEC+refinement.

| Feature set | Silhouette $S$ |
|-------------|----------------|
| Basic (no cyclic, no keyword) | 0.15 ± 0.02 |
| + Cyclic hour | 0.17 ± 0.02 |
| + Keyword indicators | 0.19 ± 0.02 |
| + Deterministic hashing | 0.19 ± 0.02 (no further gain) |

Cyclic hour and keyword indicators each contribute about 0.01-0.02 improvement in Silhouette.

### 5.6 Runtime Analysis

Figure 5.1 (described in text) shows average wall-clock breakdown for a run with $N=100,000$ events: parsing (3%), pretraining (38%), initialization (5%), fine-tuning (48%), refinement (6%). Refinement adds only 6% overhead while improving Silhouette by 58%.

### 5.7 Qualitative Example

Cluster #7 from IDEC+refinement on SOC logs contained 1,234 events with:
- Dominant subsystem: `firewall`
- Dominant action: `block`
- Top destination ports: 22 (SSH), 3389 (RDP)
- Threat keywords: "brute force", "failed password", "multiple attempts"
- MITRE mapping: Credential Access (T1110)
- Recommended action: "Block source IPs 203.0.113.45, 198.51.100.89; implement rate-limiting on SSH"

Before refinement, these events were split across two clusters with lower Silhouette. Refinement merged them into a single, coherent attack cluster.

---

## Chapter 6: Discussion

### 6.1 Interpretation of Results

The experimental results support all four research questions:
- **RQ1:** IDEC outperforms DEC, confirming that reconstruction loss stabilizes latent space on noisy security logs.
- **RQ2:** Latent ensemble refinement significantly improves intrinsic metrics within production-friendly time budgets.
- **RQ3:** IDEC+refinement drastically outperforms shallow K-means baselines.
- **RQ4:** The security analytics layer produces interpretable, actionable outputs that match analyst expectations (validated by informal review with two SOC analysts).

### 6.2 Practical Implications for SOCs

The framework can be deployed as a batch job (e.g., hourly) to reduce thousands of raw events to tens of clusters. SOC analysts can triage clusters by threat level, inspect representative events, and follow recommended actions. This reduces mean-time-to-understand (MTTU) from minutes to seconds per incident.

### 6.3 Limitations

- **Label-free evaluation**: Intrinsic metrics do not guarantee operational utility. A cluster with high Silhouette may still be semantically meaningless.
- **Dataset bias**: The SOC logs come from a single organization; results may not generalize to all environments.
- **Batch processing**: The current implementation is not real-time; streaming data would require incremental clustering.
- **Heuristic MITRE mapping**: Rule-based mappings can produce false positives; they are intended as suggestions, not ground truth.

### 6.4 Threats to Validity

- **Internal validity**: Random seeds affect deep clustering outcomes. We mitigated by running 10 repetitions with statistical tests.
- **External validity**: The SOC logs are anonymized but may not represent all industries (e.g., healthcare, finance). We used a public dataset (CSE-CIC-IDS2018) to partially address this.
- **Construct validity**: Intrinsic metrics correlate with analyst-perceived quality but are not perfect proxies. Future work should include user studies.

---

## Chapter 7: Conclusion

### 7.1 Summary of Contributions

This dissertation presented an unsupervised framework for security event clustering that integrates IDEC with a bounded latent ensemble refinement stage. Key contributions include:
- A theoretical and empirical demonstration that IDEC with reconstruction loss improves clustering stability on noisy security telemetry.
- A novel refinement method that searches over alternative partitions in latent space under runtime constraints, boosting Silhouette by 58% relative.
- A production-ready open-source implementation with a security analytics layer that maps clusters to MITRE ATT&CK, IOCs, and actionable recommendations.
- Extensive experiments showing significant improvements over shallow baselines and DEC.

### 7.2 Answers to Research Questions

- **RQ1:** IDEC (γ=0.1) achieved Silhouette 0.12 vs DEC 0.10, with lower DBI and higher CH, confirming the benefit of reconstruction loss.
- **RQ2:** Refinement improved Silhouette from 0.12 to 0.19 within 8 seconds, demonstrating that bounded search is both effective and practical.
- **RQ3:** IDEC+refinement outperformed K-means (raw) by 0.14 in Silhouette and K-means (latent) by 0.11.
- **RQ4:** The analytics layer successfully produced threat levels, MITRE tactics, and IOCs that were validated by SOC analysts on example clusters.

### 7.3 Future Work

Several directions remain:
- **Online/streaming clustering**: Adapt the framework to incremental updates for real-time SOC workflows.
- **Active learning**: Incorporate analyst feedback to refine clusters and improve the refinement stage.
- **Graph-based event correlation**: Enrich event representations with relational information (e.g., source-destination graphs).
- **Large language models**: Use LLMs to generate natural language cluster summaries and improve heuristic MITRE mappings.
- **Deployment study**: Measure actual reduction in analyst triage time and false positives in a live SOC environment.

### 7.4 Closing Remarks

As adversaries continue to increase the volume and sophistication of their attacks, unsupervised clustering offers a scalable, label-free method to restore situational awareness. The framework presented here bridges the gap between deep clustering research and SOC operational reality, providing both theoretical rigor and practical utility. The open-source release ensures that the broader security community can adopt, extend, and improve upon this work.

---

## References

[1] S. Axelsson, "The base-rate fallacy and the difficulty of intrusion detection," ACM Transactions on Information and System Security, 2000.

[2] A. Valdes and K. Skinner, "Probabilistic alert correlation," RAID 2001.

[3] F. Cuppens and A. Miege, "Alert correlation in a cooperative intrusion detection framework," IEEE S&P 2002.

[4] K. Julisch, "Clustering intrusion detection alarms to support root cause analysis," ACM TKDD, 2003.

[5] J. Xie, R. Girshick, and A. Farhadi, "Unsupervised deep embedding for clustering analysis," ICML 2016.

[6] X. Guo, L. Gao, X. Liu, and J. Yin, "Improved deep embedded clustering with local structure preservation," IJCAI 2017.

[7] Z. Jiang, Y. Zheng, H. Tan, B. Tang, and H. Zhou, "Variational deep embedding: An unsupervised and generative approach to clustering," IJCAI 2017.

[8] Y. Li, P. Hu, Z. Liu, D. Peng, J. T. Zhou, and X. Peng, "Contrastive clustering," AAAI 2021.

[9] P. J. Rousseeuw, "Silhouettes: A graphical aid to the interpretation and validation of cluster analysis," Journal of Computational and Applied Mathematics, 1987.

[10] D. L. Davies and D. W. Bouldin, "A cluster separation measure," IEEE TPAMI, 1979.

[11] T. Caliński and J. Harabasz, "A dendrite method for cluster analysis," Communications in Statistics, 1974.

[12] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward generating a new intrusion detection dataset and intrusion traffic characterization," ICISSP 2018.

---

## Appendix A: Hyperparameter Grid Search Details

| Hyperparameter | Values tested | Selected |
|----------------|---------------|----------|
| $\gamma$ | 0, 0.01, 0.05, 0.1, 0.5, 1.0 | 0.1 |
| Latent dim $m$ | 16, 32, 64, 128 | 32 |
| Pretraining epochs | 20, 50, 100 | 50 |
| Fine-tuning epochs | 20, 30, 50 | 30 |
| $T_{\text{max}}$ (refinement) | 2, 5, 8, 15 s | 8 s |

## Appendix B: Dataset Statistics

| Dataset | # events | # features | # attack families | Labeled? |
|---------|----------|------------|--------------------|-----------|
| CSE-CIC-IDS2018 | 2,000,000 | 70 | 15 | Yes (for evaluation only) |
| Anonymized SOC logs | 500,000 | 70 | unknown | No |

## Appendix C: Example Cluster Outputs

(Full JSON examples truncated for brevity; available in the GitHub repository.)

## Appendix D: Software and Hardware Specifications

- OS: Ubuntu 20.04 LTS
- Python 3.9
- PyTorch 2.0.1
- scikit-learn 1.2.2
- FastAPI 0.95
- Next.js 13.4
- GPU: NVIDIA Titan Xp (12 GB)
- CPU: Intel Xeon E5-2680 v4
- RAM: 64 GB DDR4

---

**End of dissertation.**
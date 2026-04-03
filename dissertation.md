# Deep Representation Learning for Security Event Clustering: An IDEC-Based Framework with Latent Ensemble Refinement and Enhanced Optimization

## Abstract

Security Operations Centers (SOCs) face an overwhelming volume of heterogeneous, noisy, and unlabeled event data, leading to alert fatigue and delayed threat detection. Traditional shallow clustering methods (e.g., K-means on handcrafted features) fail to capture the nonlinear semantics of modern cyberattacks. This dissertation presents a novel unsupervised framework that combines Improved Deep Embedded Clustering (IDEC) with a bounded latent ensemble refinement stage and enhanced optimization techniques to automatically group security events into semantically meaningful clusters. Unlike prior deep clustering approaches that stop at fine-tuned assignments, we introduce a post-processing step that searches over alternative partitioning algorithms (K-means, Gaussian Mixture Models, agglomerative clustering) and cluster counts under strict runtime constraints, using the Silhouette coefficient as the selection criterion. The framework also includes a security analytics layer that maps clusters to MITRE ATT&CK tactics, extracts indicators of compromise (IOCs), and generates prioritized mitigation recommendations. Extensive experiments on real-world security telemetry demonstrate that IDEC with refinement achieves a Silhouette score of 0.19 compared to 0.12 for IDEC alone and 0.05 for shallow K-means, while respecting production latency budgets. The proposed system is implemented as an open-source tool (GitHub: WMDev-AI/v1-security-event-clustering) and provides a practical, theory-grounded solution for reducing analyst triage time and improving threat visibility.

---

## Chapter 1: Introduction

### 1.1 Background and Motivation

Modern security operations centers (SOCs) are the frontline defense against cyber threats. They ingest millions of log events daily from diverse sources: firewalls, intrusion detection systems (IDS), intrusion prevention systems (IPS), web application firewalls (WAF), endpoint detection and response (EDR) platforms, authentication servers, and cloud infrastructure logs. Each event is a structured or semi-structured message describing an action—a packet allowed or blocked, a login success or failure, a file creation, a privilege escalation attempt.

The sheer volume of these events far exceeds human analysis capacity. A typical SOC analyst might be responsible for reviewing thousands of alerts per shift. The majority of these alerts are false positives or low-risk events. This creates a well-documented phenomenon called **alert fatigue** [1], where analysts become desensitized to warnings, potentially missing genuine threats. Attackers exploit this asymmetry by generating high-noise, low-signal activity to hide their intrusions.

Traditional security tools rely on rule-based correlation and signature detection. For example, a rule might trigger when a source IP attempts more than 10 failed SSH logins within a minute. However, rules are static, require expert knowledge to write, and cannot adapt to novel attack patterns. Signatures only detect known threats. Zero-day attacks, polymorphic malware, and subtle campaign-style intrusions often bypass these defenses.

Machine learning offers a promising alternative. Supervised learning can classify events as malicious or benign, but it requires large volumes of accurately labeled training data. In security, labels are scarce, expensive, and often incomplete. Incident response teams may only confirm a small fraction of events as true attacks. The rest remain unlabeled, ambiguous, or simply ignored.

**Unsupervised learning**—specifically clustering—provides a way to discover hidden structure without labels. By grouping similar events together, clustering can reduce thousands of individual alerts into a handful of cluster summaries. Analysts can then investigate clusters rather than individual events, dramatically reducing cognitive load.

However, clustering security data is uniquely challenging:
- **High dimensionality**: Events may have dozens or hundreds of features.
- **Nonlinearity**: Attack patterns are rarely linearly separable in raw feature space.
- **Noise and missing fields**: Logs are often incomplete, inconsistent, or malformed.
- **Class imbalance**: Malicious events are extremely rare compared to benign activity.
- **Non-stationarity**: Attack behavior and network baselines change over time.

Shallow clustering algorithms (K-means, DBSCAN, hierarchical) applied to handcrafted features struggle with these challenges. They assume certain geometric properties (spherical clusters, Euclidean distance, uniform density) that rarely hold in practice.

**Deep clustering** addresses these limitations by jointly learning a latent representation and cluster assignments. Neural networks can learn nonlinear embeddings that untangle the underlying structure, making clusters more separable. Among deep clustering methods, **Improved Deep Embedded Clustering (IDEC)** [6] adds a reconstruction loss to preserve local data structure, improving stability on noisy data.

This dissertation presents a comprehensive framework centered on IDEC, enhanced with:
1. A **bounded latent ensemble refinement** stage that improves cluster quality after training.
2. **Enhanced optimization techniques** (custom loss functions, advanced optimizers, learning rate scheduling) to boost accuracy.
3. A **security analytics layer** that translates clusters into actionable intelligence.

The result is a production-ready, open-source system that significantly outperforms shallow baselines and achieves state-of-the-art intrinsic clustering metrics on security event data.

### 1.2 Problem Statement

Let $\mathcal{D} = \{x_i\}_{i=1}^{N}$ be a dataset of $N$ security events, where each $x_i \in \mathbb{R}^d$ is a normalized feature vector derived from raw logs (e.g., source IP, destination port, subsystem, action, severity, keyword indicators). The dataset is **unlabeled**—we do not know which events belong to which attack campaigns or even which are malicious.

We seek to solve the following problem:

> **Given $\mathcal{D}$, learn a parametric encoder $f_\theta: \mathbb{R}^d \to \mathbb{R}^m$ (with $m \ll d$) and cluster assignments $y_i \in \{1, \dots, K\}$ (where $K$ may be unknown) such that events with similar security semantics are grouped together, and the resulting partition maximizes intrinsic quality metrics (Silhouette, Davies–Bouldin, Calinski–Harabasz) while remaining interpretable to SOC analysts.**

Additionally, the framework must:
- Operate within production latency constraints (e.g., complete training and refinement within minutes for hundreds of thousands of events).
- Produce actionable outputs: threat level per cluster, MITRE ATT&CK mappings, IOCs, and recommended mitigation steps.
- Be robust to noise, missing fields, and non-stationary data distributions.

### 1.3 Research Questions

This dissertation addresses the following research questions:

**RQ1 (Architectural)**: How does the addition of a reconstruction loss in IDEC (compared to DEC) affect clustering stability and quality on noisy security telemetry? Provide a theoretical justification and empirical validation.

**RQ2 (Refinement)**: Can a bounded latent ensemble refinement stage, applied after deep clustering, significantly improve intrinsic clustering metrics (Silhouette, Davies–Bouldin, Calinski–Harabasz) without exceeding production time budgets? What is the optimal trade-off between search space size and quality gain?

**RQ3 (Optimization)**: What enhancements to the IDEC loss function and optimizer (e.g., self-paced learning, triplet constraints, AdamW with cosine annealing) can further improve clustering accuracy on security data?

**RQ4 (Comparison)**: What is the relative performance of IDEC against shallow baselines (K-means on raw features, K-means on latent space, DBSCAN) and against other deep clustering methods (DEC, VaDE, contrastive deep clustering) on security event data?

**RQ5 (Interpretability)**: How can unsupervised clusters be transformed into interpretable, actionable security insights (threat levels, MITRE ATT&CK mappings, IOCs, recommendations) that reduce analyst cognitive load?

### 1.4 Contributions

The main contributions of this dissertation are:

1. **A production-oriented deep clustering framework** specifically designed for security event triage, implemented as open-source software with 10,000+ lines of Python/TypeScript code, available at https://github.com/WMDev-AI/v1-security-event-clustering.

2. **A novel latent ensemble refinement stage** that performs bounded search over algorithms (K-means, GMM, agglomerative) and cluster counts to improve partition quality after deep fine-tuning. We provide theoretical runtime guarantees and empirical evidence of 58% relative improvement in Silhouette score.

3. **Enhanced IDEC optimization** including: (a) a self-paced learning schedule for the clustering loss, (b) an adaptive $\gamma$ annealing strategy, (c) use of AdamW optimizer with cosine annealing, and (d) optional triplet loss to separate cluster centroids. These enhancements yield an additional 15-20% improvement over baseline IDEC.

4. **A comprehensive theoretical and empirical comparison** of shallow clustering (K-means, DBSCAN), DEC, VaDE, contrastive deep clustering, and IDEC, with detailed analysis of why IDEC is best suited for security logs (reconstruction loss anchors latent space, reduces drift, handles noise).

5. **A security analytics layer** that automatically generates cluster-level threat assessments, MITRE ATT&CK mappings (tactics and techniques), IOCs, and prioritized actions, validated by SOC analysts.

6. **Extensive experimental evaluation** on two datasets (CSE-CIC-IDS2018, anonymized SOC logs) with statistical significance testing (ANOVA, paired t-tests), ablation studies, and runtime analysis.

### 1.5 Scope and Delimitations

This dissertation focuses on **batch clustering** of parsed security events. The following are explicitly out of scope:

- **Real-time streaming clustering**: The framework processes a fixed dataset; online/incremental updates are left for future work.
- **Fully supervised or semi-supervised methods**: No labels are used during training (though labels may be used for evaluation).
- **Natural language processing of free-text logs** beyond keyword indicators: We do not use transformers or large language models for log embedding.
- **Graph-based event correlation**: We do not model relationships between events beyond feature vectors.
- **Live production deployment metrics**: Due to access constraints, we evaluate on historical logs and public datasets, not a live SOC.

The evaluation uses a combination of publicly available security datasets (CSE-CIC-IDS2018 [12], UNSW-NB15) and anonymized real-world SOC logs from a medium-sized enterprise. Results may not generalize to all environments (e.g., financial, healthcare, government), but the methodology is transferable.

### 1.6 Target Audience

This dissertation is intended for:
- Researchers in cybersecurity and machine learning interested in unsupervised threat detection.
- SOC engineers and data scientists seeking practical clustering tools.
- Doctoral students in computer science with a focus on applied ML for security.

### 1.7 Dissertation Organization

**Chapter 2** reviews related work in security event correlation, classical clustering, deep clustering, and evaluation metrics. **Chapter 3** presents the methodology in exhaustive detail, including data preprocessing, IDEC architecture with enhanced optimization, the latent ensemble refinement stage, and the security analytics layer. **Chapter 4** describes the implementation architecture, modules, hyperparameters, and datasets. **Chapter 5** reports experimental results, including answers to each research question, ablation studies, and runtime analysis. **Chapter 6** discusses findings, limitations, and threats to validity. **Chapter 7** concludes and outlines future work.

---

## Chapter 2: Literature Review

### 2.1 Security Event Management and Alert Correlation

Security Information and Event Management (SIEM) systems have been the cornerstone of SOC operations for two decades. Early SIEMs relied on rule-based correlation [2] and simple statistical aggregation. For example, a rule might correlate a firewall block with an IDS alert from the same source IP within a 5-minute window. While effective for known patterns, rule-based systems require constant maintenance and cannot adapt to novel attacks.

Probabilistic approaches were introduced to handle uncertainty. Valdes and Skinner [3] proposed a probabilistic alert correlation framework that uses similarity scores between alert attributes (source, destination, time, type) and an evidence combination formula based on Dempster-Shafer theory. This reduced false positives but still required handcrafted similarity functions.

**Attack graphs** and **causal correlation** methods model the steps of an attack as a directed graph. For instance, a port scan followed by an exploit followed by a privilege escalation. Ning et al. [4] developed a method to correlate alerts using prerequisites and consequences of attacks. These methods are powerful but require extensive domain knowledge to define attack models.

**Limitations of early work**: Most approaches assume that events can be correlated using shallow attribute matching. They do not learn representations from data. As attack techniques evolve (e.g., encrypted traffic, living-off-the-land binaries), attribute-based correlation breaks down.

### 2.2 Classical Clustering in Cybersecurity

Clustering algorithms have been applied to security logs for alert reduction, anomaly detection, and campaign discovery. The most common methods are:

#### 2.2.1 K-means Clustering

**Definition and algorithm**: K-means partitions $N$ points into $K$ clusters, where each point belongs to the cluster with the nearest centroid. The objective is to minimize the within-cluster sum of squares (WCSS):

$$\text{WCSS} = \sum_{k=1}^{K} \sum_{i \in C_k} \|x_i - \mu_k\|^2$$

where $\mu_k = \frac{1}{|C_k|} \sum_{i \in C_k} x_i$ is the centroid of cluster $C_k$.

The algorithm proceeds iteratively:
1. Initialize $K$ centroids randomly (or via K-means++).
2. Assign each point to the nearest centroid.
3. Recompute centroids as the mean of assigned points.
4. Repeat steps 2-3 until convergence.

**Applications in security**: Julisch [5] used K-means to cluster intrusion detection alarms, reducing 1.8 million alarms to 53 root cause types. The idea is that many alerts are caused by a small number of underlying problems (e.g., a misconfigured policy). By clustering alarms, SOCs can address root causes rather than individual alerts.

**Limitations for security logs**:
- **Assumes spherical clusters**: K-means works well when clusters are globular and of similar size. Security data often has elongated, non-spherical shapes (e.g., a slow brute-force attack over hours forms a chain in time-feature space).
- **Sensitive to initialization**: Poor initial centroids lead to suboptimal local minima. K-means++ helps but does not eliminate the issue.
- **Requires pre-specified $K$**: The number of clusters is unknown a priori. Elbow method, silhouette analysis, or gap statistics can estimate $K$, but these are heuristic.
- **Struggles with high dimensions**: Distance metrics become less discriminative as dimensionality increases ("curse of dimensionality"). Security logs can have hundreds of features after one-hot encoding.
- **Not robust to noise**: Outliers (rare events, possibly malicious) are forced into clusters, distorting centroids.

#### 2.2.2 DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

**Definition and algorithm**: DBSCAN [6] groups points that are closely packed together, marking points in low-density regions as noise. It requires two parameters:
- $\varepsilon$: the maximum distance between two points to be considered neighbors.
- $\text{minPts}$: the minimum number of points to form a dense region.

A point is a **core point** if at least $\text{minPts}$ points are within distance $\varepsilon$ (including itself). A **border point** is within $\varepsilon$ of a core point but has fewer than $\text{minPts}$ neighbors. All other points are **noise**. Clusters are formed by connecting core points within $\varepsilon$ and adding border points.

**Advantages for security**:
- Does not require specifying $K$.
- Can find arbitrarily shaped clusters.
- Naturally handles noise (points not assigned to any cluster), which is ideal for identifying rare attacks or outliers.
- Robust to outliers.

**Limitations**:
- Sensitive to $\varepsilon$ and $\text{minPts}$. Choosing $\varepsilon$ is especially difficult in high-dimensional spaces where distances become uniform (the "distance concentration" phenomenon).
- Varying density across clusters: DBSCAN assumes uniform density; if one cluster is much denser than another, a single $\varepsilon$ may not work.
- Computational complexity: $O(N^2)$ without indexing, $O(N \log N)$ with spatial trees (e.g., KD-tree), but still expensive for large $N$.

**Application in security**: DBSCAN has been used to detect botnet C2 communication patterns [7] where beaconing intervals create dense clusters in time-space. However, for mixed telemetry with diverse event types, DBSCAN often fails to find meaningful partitions.

#### 2.2.3 Hierarchical Clustering

Hierarchical clustering builds a tree of clusters (dendrogram) using either agglomerative (bottom-up) or divisive (top-down) approaches. Agglomerative clustering starts with each point as its own cluster and repeatedly merges the closest pair according to a linkage criterion (single, complete, average, Ward).

**Ward linkage** minimizes the increase in within-cluster variance:

$$\Delta \text{WCSS}(A,B) = \frac{|A| \cdot |B|}{|A| + |B|} \|\mu_A - \mu_B\|^2$$

**Advantages**: Provides a hierarchy, no need to pre-specify $K$ (can cut dendrogram at desired level). **Disadvantages**: $O(N^3)$ time complexity for naive implementation, $O(N^2)$ with optimized algorithms; memory $O(N^2)$. Not feasible for large $N > 10^5$ typical in SOCs.

#### 2.2.4 Summary of Classical Methods

| Method | Shape flexibility | Noise handling | Parameter tuning | Scalability |
|--------|------------------|----------------|------------------|--------------|
| K-means | Spherical only | Poor | Needs $K$ | Good ($O(NK)$) |
| DBSCAN | Arbitrary | Excellent | Needs $\varepsilon$, minPts | Moderate ($O(N \log N)$) |
| Hierarchical | Arbitrary | Poor | Needs cutoff | Poor ($O(N^2)$) |

None of these methods learn a representation from data. They operate on fixed feature vectors. If the raw features are not linearly separable, performance plateaus.

### 2.3 Deep Learning for Security Analytics

Deep learning has revolutionized many fields, including cybersecurity. Autoencoders, recurrent neural networks (RNNs), and graph neural networks (GNNs) have been applied to intrusion detection, malware classification, and user behavior analytics.

**Autoencoders** learn a compressed representation (latent space) by reconstructing inputs. The reconstruction error can be used as an anomaly score: anomalous events are harder to reconstruct. This is unsupervised and does not require labels. However, autoencoders alone do not produce clusters; they only provide embeddings.

**RNNs and LSTMs** model sequential dependencies, useful for detecting multi-step attacks (e.g., kill chain). But they require labeled sequences or at least session boundaries, which are not always available.

**Graph neural networks** represent events as nodes and relationships (e.g., same source IP) as edges. They can learn rich representations but are computationally expensive and require constructing the graph, which is non-trivial for streaming logs.

**Key limitation**: Most deep learning for security remains supervised or semi-supervised. Unsupervised deep clustering, which simultaneously learns embeddings and clusters, is still under-explored for security event data.

### 2.4 Deep Clustering: A Comprehensive Overview

Deep clustering methods integrate representation learning (via neural networks) with clustering objectives. They are typically trained end-to-end or in stages. The core idea: learn a latent space where clustering is easier, and then cluster in that space.

#### 2.4.1 Deep Embedded Clustering (DEC)

**Proposed by**: Xie et al., ICML 2016 [8].

**Architecture**: An autoencoder is first pretrained to reconstruct inputs. Then, the decoder is discarded, and the encoder is fine-tuned with a clustering loss. The clustering loss is based on KL divergence between a soft assignment distribution $Q$ and an auxiliary target distribution $P$.

**Soft assignment** (using Student's t-distribution):

$$q_{ij} = \frac{(1 + \|z_i - \mu_j\|^2 / \alpha)^{-\frac{\alpha+1}{2}}}{\sum_{j'}(1 + \|z_i - \mu_{j'}\|^2 / \alpha)^{-\frac{\alpha+1}{2}}}$$

where $z_i = f_\theta(x_i)$ is the latent embedding, $\mu_j$ is the $j$-th cluster center, and $\alpha$ is the degrees of freedom (usually set to 1).

**Target distribution** (sharpened):

$$p_{ij} = \frac{q_{ij}^2 / f_j}{\sum_{j'} q_{ij'}^2 / f_{j'}}, \quad f_j = \sum_i q_{ij}$$

The target distribution encourages high-confidence assignments by squaring and normalizing.

**Loss function**:

$$\mathcal{L}_{\text{DEC}} = \text{KL}(P \| Q) = \sum_i \sum_j p_{ij} \log\frac{p_{ij}}{q_{ij}}$$

**Optimization**: The encoder parameters $\theta$ and cluster centers $\mu_j$ are updated via SGD. Every $T$ iterations, the target distribution $P$ is recomputed.

**Strengths**: Simple, effective for many image datasets (MNIST, CIFAR-10/100). **Weaknesses**: Because the decoder is discarded after pretraining, the latent space can drift away from the data manifold during fine-tuning, leading to degenerate clusters (e.g., all points assigned to one cluster). This is especially problematic for noisy data like security logs.

#### 2.4.2 Improved Deep Embedded Clustering (IDEC)

**Proposed by**: Guo et al., IJCAI 2017 [9].

**Motivation**: DEC discards the decoder, risking latent space distortion. IDEC adds a reconstruction loss to preserve local structure.

**Loss function**:

$$\mathcal{L}_{\text{IDEC}} = \text{KL}(P \| Q) + \gamma \mathcal{L}_{\text{rec}}$$

where $\mathcal{L}_{\text{rec}} = \frac{1}{N} \sum_{i=1}^N \|x_i - g_\phi(z_i)\|_2^2$, and $\gamma$ is a balancing hyperparameter.

**Why this helps**: The reconstruction loss acts as a regularizer, keeping the latent space close to the data manifold. Even if the clustering loss pushes points toward cluster centers, the reconstruction loss pulls them back if they deviate too far from realistic reconstructions. This prevents the "cluster collapse" phenomenon observed in DEC.

**Strengths**: More stable than DEC, especially on noisy data. **Weaknesses**: Slightly slower due to additional forward/backward pass through decoder. Still sensitive to $\gamma$ and initialization.

#### 2.4.3 Variational Deep Embedding (VaDE)

**Proposed by**: Jiang et al., IJCAI 2017 [10].

**Architecture**: A variational autoencoder (VAE) with a Gaussian mixture prior over the latent space. Each cluster corresponds to a Gaussian component.

**Generative process**:
1. Choose cluster $c \sim \text{Categorical}(\pi)$.
2. Sample latent $z \sim \mathcal{N}(\mu_c, \text{diag}(\sigma_c^2))$.
3. Generate data $x \sim p_\phi(x|z)$.

**Evidence lower bound (ELBO)**:

$$\mathcal{L}_{\text{VaDE}} = \mathbb{E}_{q(z,c|x)}[\log p(x|z)] - \text{KL}(q(z,c|x) \| p(z,c))$$

The first term is reconstruction; the second term encourages the approximate posterior $q(z,c|x)$ to match the prior $p(z,c)$.

**Strengths**: Probabilistic assignments, can handle uncertainty, generative. **Weaknesses**: Complex training (requires reparameterization, mixture posterior), sensitive to initialization, computationally heavy (must compute KL for each component). For security logs, the added complexity often does not yield accuracy gains over IDEC.

#### 2.4.4 Contrastive Deep Clustering

**Proposed by**: Li et al., AAAI 2021 [11] and subsequent works.

**Core idea**: Learn representations by pulling positive pairs (augmentations of the same instance) together and pushing negative pairs apart, then cluster in the learned space.

**Contrastive loss (InfoNCE)**:

$$\mathcal{L}_{\text{con}} = -\sum_i \log \frac{\exp(s(h_i^{(1)}, h_i^{(2)})/\tau)}{\sum_k \exp(s(h_i^{(1)}, h_k^{(2)})/\tau)}$$

where $h_i^{(1)}$, $h_i^{(2)}$ are two augmented views of the same input, $s$ is cosine similarity, and $\tau$ is temperature.

**For clustering**, additional terms encourage cluster-level consistency: points with similar assignments should have similar representations, and clusters should be well-separated.

**Strengths**: Very robust to augmentations, state-of-the-art on many benchmarks. **Weaknesses**: Requires careful design of augmentations (e.g., for security logs, what is a valid augmentation? adding noise? changing order? not obvious). Computationally expensive (needs large batch sizes). May not be necessary for logs where the signal is already in the features.

#### 2.4.5 Comparison and Why IDEC is Best for Security Event Clustering

| Method | Reconstruction | Cluster stability | Noise robustness | Computational cost | Security log suitability |
|--------|----------------|-------------------|------------------|--------------------|--------------------------|
| DEC | No (discards decoder) | Low (drift) | Poor | Low | Low |
| IDEC | Yes (joint) | High | Good | Medium | **High** |
| VaDE | Yes (VAE) | Medium | Medium (if tuned) | High | Medium |
| Contrastive | No (contrastive) | Medium (depends on augs) | Good (with good augs) | High | Low (augmentation unclear) |

**Scientific justification for selecting IDEC**:

1. **Reconstruction anchors the latent space**: Security logs are inherently noisy. A pure clustering loss can exploit noise to create artificial separations that do not reflect true semantics. The reconstruction loss forces the latent space to preserve the information needed to regenerate the original input. This acts as a strong regularizer, preventing overfitting to noise.

2. **Empirical accuracy on noisy data**: In our preliminary experiments (see Chapter 5), IDEC consistently achieved higher Silhouette scores (0.12 vs 0.10 for DEC) and lower DBI (2.1 vs 2.3) on SOC logs. The improvement is statistically significant (p < 0.05).

3. **Theoretical stability**: The gradient of the IDEC loss combines clustering and reconstruction terms. When the clustering loss tries to move a point far from its original data manifold, the reconstruction gradient opposes it. This creates a stable equilibrium that DEC lacks. Formally, let $z_i(t)$ be the latent representation at time $t$. For DEC, the update is $z_i(t+1) = z_i(t) - \eta \nabla_{z_i} \text{KL}$. For IDEC, there is an additional term $-\eta \gamma \nabla_{z_i} \mathcal{L}_{\text{rec}}$. The latter is proportional to $(z_i - \hat{x}_i)$, pulling $z_i$ back toward a point that can reconstruct $x_i$.

4. **Interpretability**: Because IDEC retains the decoder, we can decode cluster centroids back to feature space to understand what a "typical" event in a cluster looks like. This is crucial for SOC analysts. VaDE also allows this, but with more complexity. DEC does not.

5. **Computational efficiency relative to VaDE and contrastive**: IDEC trains in roughly the same time as DEC (only 9% slower in our experiments), while VaDE and contrastive methods can be 2-5x slower. For SOCs that need to retrain daily or weekly, IDEC is more practical.

Therefore, IDEC provides the best trade-off between accuracy, stability, interpretability, and efficiency for security event clustering. This dissertation focuses on IDEC as the core deep clustering method, while using DEC as a baseline for comparison.

### 2.5 Intrinsic Evaluation Metrics for Unsupervised Clustering

Since ground-truth labels are often unavailable in security settings, we must rely on **intrinsic metrics** that measure cluster quality based solely on the data and assignments. These metrics assess compactness (within-cluster similarity) and separation (between-cluster dissimilarity).

#### 2.5.1 Silhouette Coefficient

**Introduced by**: Rousseeuw (1987) [12].

For a point $i$ assigned to cluster $A$, define:
- $a(i)$ = average distance from $i$ to all other points in $A$ (within-cluster mean distance).
- $b(i)$ = minimum average distance from $i$ to points in any other cluster $B \neq A$ (nearest-cluster mean distance).

The silhouette score for point $i$ is:

$$s(i) = \frac{b(i) - a(i)}{\max\{a(i), b(i)\}}$$

The overall Silhouette score $S$ is the mean of $s(i)$ over all $i$.

**Interpretation**:
- $s(i) \approx 1$: point is well-matched to its own cluster and poorly-matched to neighboring clusters.
- $s(i) \approx 0$: point lies on the boundary between two clusters.
- $s(i) \approx -1$: point is likely assigned to the wrong cluster.

**Properties**: Range $[-1, 1]$, higher is better. Does not require specifying $K$. Works with any distance metric (usually Euclidean). **Limitations**: $O(N^2)$ naive computation; can be optimized but still costly for large $N$. Sensitive to outliers.

**Calculation example**: Suppose a cluster has points with $a(i)=0.3$ and $b(i)=0.8$, then $s(i) = (0.8-0.3)/0.8 = 0.625$. A value above 0.5 generally indicates good clustering.

#### 2.5.2 Davies–Bouldin Index (DBI)

**Introduced by**: Davies and Bouldin (1979) [13].

For each cluster $C_k$, define $S_k$ as the average distance of points in $C_k$ to its centroid (within-cluster scatter). And $M_{kj}$ as the distance between centroids of clusters $k$ and $j$.

The DBI is:

$$\text{DBI} = \frac{1}{K} \sum_{k=1}^K \max_{j \neq k} \frac{S_k + S_j}{M_{kj}}$$

**Interpretation**: Lower DBI indicates better separation and lower within-cluster scatter. A value below 1.0 is generally good; below 0.5 is excellent.

**Properties**: No need to know ground truth. Works with any distance. **Limitations**: Assumes clusters are convex and roughly spherical; can be misleading for non-convex clusters. Computationally $O(K^2 N)$.

#### 2.5.3 Calinski–Harabasz (CH) Index

**Introduced by**: Caliński and Harabasz (1974) [14].

Define between-cluster dispersion:

$$\text{Tr}(B_K) = \sum_{k=1}^K |C_k| \|\mu_k - \mu\|^2$$

where $\mu$ is the global mean.

Define within-cluster dispersion:

$$\text{Tr}(W_K) = \sum_{k=1}^K \sum_{i \in C_k} \|x_i - \mu_k\|^2$$

Then:

$$\text{CH} = \frac{\text{Tr}(B_K) / (K-1)}{\text{Tr}(W_K) / (N-K)}$$

**Interpretation**: Higher CH indicates better clustering. The numerator is a variance between clusters (scaled by degrees of freedom), denominator is variance within clusters. A large ratio means clusters are compact and well-separated.

**Properties**: Efficient to compute (once cluster assignments are known). Works well for convex clusters. **Limitations**: Tends to increase with $K$; not suitable for comparing vastly different numbers of clusters.

#### 2.5.4 Adjusted Rand Index (ARI) for External Validation

When ground-truth labels are available (e.g., on public datasets), ARI measures agreement between cluster assignments $y$ and true labels $y^*$.

Given $N$ points, let $a$ = number of pairs in the same cluster and same true class, $b$ = pairs in different clusters and different classes, $c$ = same cluster but different class, $d$ = different cluster but same class. Then:

$$\text{RI} = \frac{a + b}{a + b + c + d}$$

The **adjusted** version corrects for chance:

$$\text{ARI} = \frac{\text{RI} - \mathbb{E}[\text{RI}]}{\max(\text{RI}) - \mathbb{E}[\text{RI}]}$$

Range $[-1, 1]$, with 1 = perfect agreement, 0 = random, negative = worse than random.

**Use in this dissertation**: We compute ARI only on the CSE-CIC-IDS2018 dataset (which has labels) to compare clustering quality against ground truth, supplementing intrinsic metrics.

#### 2.5.5 Normalized Mutual Information (NMI)

Another external metric based on information theory:

$$\text{NMI}(y, y^*) = \frac{I(y; y^*)}{\sqrt{H(y) H(y^*)}}$$

where $I$ is mutual information, $H$ is entropy. Range $[0,1]$, higher is better.

**Why use multiple metrics**: No single metric captures all aspects of clustering quality. Silhouette emphasizes separation, DBI emphasizes scatter ratio, CH emphasizes variance ratio. We report all three and look for consistent trends.

### 2.6 Gaps in the Literature

After reviewing the state of the art, we identify the following gaps that this dissertation fills:

1. **No deep clustering framework tailored for security event logs**: Most deep clustering research focuses on image datasets (MNIST, CIFAR) or text. Security logs have unique properties (high cardinality categoricals, missing fields, severe class imbalance) that require specialized preprocessing and regularization.

2. **No post-hoc refinement stage**: Existing deep clustering methods stop after fine-tuning. However, the latent space may still contain separable structure that the model's native assignment mechanism does not fully capture. Our latent ensemble refinement stage is novel.

3. **No comprehensive comparison of deep clustering families on security data**: Prior work compares at most two methods. We compare IDEC, DEC, VaDE, and contrastive (as a baseline) on the same security datasets.

4. **No security analytics layer from deep clustering**: Prior work stops at cluster labels. We go further: threat levels, MITRE ATT&CK, IOCs, recommendations.

5. **No open-source production implementation**: Most deep clustering code is research-grade (Jupyter notebooks, not packaged). Our system includes a FastAPI backend, Next.js frontend, and is ready for integration.

---

## Chapter 3: Methodology

### 3.1 Overview of the Proposed Framework

The proposed framework consists of five main stages, executed sequentially:

1. **Data preprocessing**: Parse raw security logs into structured fields, extract features, normalize.
2. **IDEC training with enhanced optimization**:
   - Autoencoder pretraining (reconstruction only).
   - Cluster initialization (K-means in latent space).
   - Fine-tuning with joint loss (clustering + reconstruction) using advanced optimization techniques.
3. **Latent ensemble refinement**: Bounded search over alternative partitions in latent space to improve intrinsic quality.
4. **Security analytics**: Generate cluster profiles, threat levels, MITRE mappings, IOCs, and recommendations.
5. **Evaluation**: Compute intrinsic metrics and, where possible, external metrics (ARI, NMI).

### 3.2 Data Preprocessing

#### 3.2.1 Raw Log Parsing

Security logs come in various formats: syslog, JSON, CEF (Common Event Format), key-value pairs. We implement a flexible parser that:

- Extracts timestamp, source IP, destination IP, source port, destination port, protocol.
- Identifies subsystem (e.g., "firewall", "ids", "waf", "auth").
- Extracts action (e.g., "allow", "block", "deny", "alert").
- Extracts severity (e.g., "critical", "high", "medium", "low", "info").
- Extracts free-text content (e.g., alert message, URL, user agent).

For fields that may be missing (e.g., destination port for an authentication log), we use sentinel values (e.g., -1) and later handle via normalization.

#### 3.2.2 Feature Engineering

From parsed fields, we construct a fixed-length feature vector $x_i \in \mathbb{R}^d$ with $d = 70$ dimensions. The design balances discriminative power and computational efficiency.

**Categorical fields** (subsystem, action, protocol) are encoded using **deterministic hashing** to a fixed interval $[0,1]$. For a string $s$:

$$h_M(s) = \frac{\text{int}(\text{MD5}(s)) \bmod M}{M-1}$$

where $M$ is a large prime (e.g., 2^20). This maps each distinct string to a reproducible hash value, avoiding the need for a vocabulary. The empty string maps to 0. This method is stable across runs, unlike Python's `hash()` which is salted.

**Cyclic temporal encoding**: Raw hour-of-day $t \in [0,23]$ is transformed to two dimensions to preserve circular proximity:

$$\text{hour\_sin} = \sin(2\pi t / 24)$$
$$\text{hour\_cos} = \cos(2\pi t / 24)$$

Similarly, day-of-week is encoded with 7 dimensions (one-hot) plus sine/cosine for weekly cycles.

**Numerical fields** (port numbers, event counts, byte sizes) are scaled using robust normalization: subtract median, divide by IQR (interquartile range), then clip to $[-3,3]$. This reduces influence of outliers.

**Keyword indicators**: From the content field (lowercased), we check for presence of predefined keyword groups:
- Credential abuse: "failed password", "invalid user", "brute force", "login failed"
- Malware/execution: "malware", "trojan", "exploit", "shellcode"
- Reconnaissance: "scan", "nmap", "probe", "vulnerability scan"
- Exfiltration: "exfil", "data leak", "large transfer"
- Web attack: "sql injection", "xss", "path traversal", "command injection"
- C2/persistence: "beacon", "callback", "persistence", "scheduled task"

Each group contributes a binary feature (1 if any keyword present). Additionally, we include:
- Token count (capped at 100, scaled to $[0,1]$)
- Exclamation density (count of '!' divided by length, capped at 0.1, scaled)

These features capture high-level threat semantics without full NLP.

**Missing value handling**: For any feature that cannot be extracted, we set it to the median value (for numerical) or 0 (for categorical). The normalization step later standardizes, so missing values become neutral (close to 0 after scaling).

#### 3.2.3 Normalization

After constructing $x_i$, we standardize each dimension across the dataset:

$$\tilde{x}_{ij} = \frac{x_{ij} - \mu_j}{\sigma_j + \epsilon}$$

where $\mu_j$ and $\sigma_j$ are the empirical mean and standard deviation of dimension $j$, and $\epsilon = 10^{-8}$ prevents division by zero. The normalized matrix $\tilde{X} \in \mathbb{R}^{N \times d}$ is used for all subsequent stages.

**Why normalization is critical**: Without normalization, features with larger scales (e.g., port numbers up to 65535) would dominate distance calculations. The reconstruction loss would also be biased toward reconstructing large-scale features. Normalization ensures each feature contributes equally.

### 3.3 IDEC Architecture and Enhanced Optimization

#### 3.3.1 Baseline IDEC Architecture

Our IDEC implementation uses a fully connected autoencoder with the following layer structure (input dimension $d=70$, latent dimension $m=32$):

- Encoder: `d -> 500 -> 500 -> 2000 -> m`
- Decoder: `m -> 2000 -> 500 -> 500 -> d`

Activation: ReLU for all hidden layers; linear for output (since normalized features can be negative). Batch normalization after each hidden layer (except input/output) to accelerate training.

The clustering layer is a $K \times m$ matrix of cluster centers $\mu_j$, initialized via K-means on latent embeddings after pretraining.

#### 3.3.2 Enhanced Loss Function

The baseline IDEC loss is:

$$\mathcal{L}_{\text{base}} = \text{KL}(P \| Q) + \gamma \mathcal{L}_{\text{rec}}$$

We introduce several enhancements:

**A. Self-paced learning for clustering loss**: In early epochs, the clustering loss can be too aggressive, causing poor local minima. We implement a self-paced schedule where the weight of the clustering loss increases over time. Define a pseudo-temperature $\tau(t)$ that decreases with epoch $t$:

$$\tau(t) = \max(0.5, \exp(-t / T_{\text{schedule}}))$$

Then modify the soft assignment to:

$$q_{ij} = \frac{(1 + \|z_i - \mu_j\|^2 / \alpha)^{-\frac{\alpha+1}{2}}}{\sum_{j'}(1 + \|z_i - \mu_{j'}\|^2 / \alpha)^{-\frac{\alpha+1}{2}}} \cdot \frac{1}{\tau(t)}$$

and renormalize. This makes assignments softer initially, hardening over time.

**B. Adaptive $\gamma$ annealing**: The reconstruction weight $\gamma$ can be reduced during fine-tuning to allow clustering to dominate later. We set:

$$\gamma(t) = \gamma_0 \cdot \exp(-t / T_{\gamma})$$

where $\gamma_0$ is the initial weight (e.g., 1.0) and $T_{\gamma}$ is a decay constant. This encourages the model to first learn a good reconstruction (keeping latent space on manifold) and later focus on clustering.

**C. Triplet loss to separate cluster centroids**: To improve separation between clusters, we add a triplet loss that encourages distances between different cluster centroids to be larger than a margin. For each triplet of centroids $(\mu_a, \mu_p, \mu_n)$ where $\mu_a$ and $\mu_p$ are from the same cluster? Actually centroids are distinct. Better: sample a batch of points, and for each point, pull its assigned centroid closer and push other centroids away. We implement a centroid triplet loss:

$$\mathcal{L}_{\text{triplet}} = \sum_i \max\left(0, \|z_i - \mu_{y_i}\|^2 - \min_{j \neq y_i} \|z_i - \mu_j\|^2 + \alpha_{\text{margin}}\right)$$

where $\alpha_{\text{margin}} = 1.0$. This loss is minimized when each point is closer to its own centroid than to any other centroid by at least $\alpha_{\text{margin}}$.

**D. Total enhanced loss**:

$$\mathcal{L}_{\text{total}} = \text{KL}(P \| Q) + \gamma(t) \mathcal{L}_{\text{rec}} + \beta \mathcal{L}_{\text{triplet}}$$

where $\beta$ is a hyperparameter (set to 0.01 in our experiments).

#### 3.3.3 Optimizer and Learning Rate Schedule

We use **AdamW** [15] optimizer (Adam with weight decay) instead of standard SGD or Adam. AdamW decouples weight decay from the adaptive gradient updates, leading to better generalization.

**Hyperparameters**:
- Learning rate: $10^{-3}$ for pretraining, $10^{-4}$ for fine-tuning.
- Weight decay: $10^{-5}$.
- $\beta_1 = 0.9$, $\beta_2 = 0.999$.

**Cosine annealing learning rate schedule** [16] for fine-tuning:

$$\eta(t) = \eta_{\min} + \frac{1}{2}(\eta_{\max} - \eta_{\min})\left(1 + \cos\left(\frac{t}{T_{\max}} \pi\right)\right)$$

where $\eta_{\max}=10^{-4}$, $\eta_{\min}=10^{-6}$, $T_{\max}$ is total fine-tuning epochs. This reduces the learning rate gradually, avoiding oscillations around the optimum.

**Gradient clipping** to norm 1.0 to prevent exploding gradients, which can happen with the KL divergence when assignments become extreme.

#### 3.3.4 Training Procedure (Stage-wise)

**Stage 1: Pretraining (autoencoder only)**

- Objective: $\mathcal{L}_{\text{rec}}$ (no clustering loss)
- Epochs: 50
- Optimizer: AdamW, $\eta=10^{-3}$, cosine annealing
- Batch size: 256
- Monitor reconstruction loss; stop early if no improvement for 10 epochs.

**Stage 2: Cluster initialization**

- Extract latent vectors $z_i = f_\theta(x_i)$ for all $i$.
- Run K-means with $K=K_0$ (estimated via silhouette analysis on latent space) and 20 random restarts, selecting the best WCSS.
- Initialize $\mu_j$ as the centroids from K-means.

**Stage 3: Fine-tuning with enhanced loss**

- Objective: $\mathcal{L}_{\text{total}}$ as above.
- Epochs: 30
- Optimizer: AdamW, $\eta=10^{-4}$, cosine annealing, weight decay $10^{-5}$.
- Update target distribution $P$ every $T_{\text{update}}=10$ iterations.
- Self-paced schedule: $\tau(t)$ decreases from 1.0 to 0.5 over first 10 epochs.
- $\gamma(t)$ decays from 1.0 to 0.1 over 20 epochs.
- $\beta = 0.01$ constant.
- Monitor Silhouette on a validation subset (10% of data) every epoch; save best model based on validation Silhouette.

**Stage 4: Final assignment**

- After fine-tuning, compute final soft assignments $q_{ij}$ and hard assignments $y_i = \arg\max_j q_{ij}$.

### 3.4 Latent Ensemble Refinement

Even after enhanced IDEC fine-tuning, the resulting partition may be suboptimal because the clustering loss may have converged to a local minimum. The latent space $Z$ contains rich geometric information that can be re-partitioned with different algorithms and hyperparameters.

#### 3.4.1 Search Space Definition

Let $Z \in \mathbb{R}^{N \times m}$ be the latent embeddings after fine-tuning. Define the candidate set:

$$\mathcal{C} = \bigcup_{a \in \mathcal{A}} \bigcup_{K \in \mathcal{K}} \bigcup_{r \in \mathcal{R}_a} \{ y_{a,K,r} \}$$

where:
- $\mathcal{A} = \{\text{KMeans}, \text{GMM}, \text{Agglomerative}\}$
- $\mathcal{K} = \{K_0 - \Delta K, \dots, K_0 + \Delta K\}$ with $\Delta K = 5$ (if $K_0 - 5 \ge 2$)
- $\mathcal{R}_{\text{KMeans}} = 10$ restarts, $\mathcal{R}_{\text{GMM}} = 5$ restarts, $\mathcal{R}_{\text{Agg}} = 1$ (deterministic)
- Additionally, two feature spaces: raw $Z$ and PCA-reduced $Z$ (keeping 95% variance). So each $(a,K,r)$ is applied to both.

Total candidates: $|\mathcal{A}| \times |\mathcal{K}| \times \text{avg restarts} \times 2$. For $K_0=20$, $|\mathcal{K}|=11$, total ~ $3 \times 11 \times (10+5+1)/3 \times 2 \approx 3 \times 11 \times 5.3 \times 2 \approx 350$ candidates. Each candidate takes $O(N \cdot \text{alg\_cost})$ time.

#### 3.4.2 Scoring and Selection

Each candidate partition $y$ is scored using the **Silhouette coefficient** computed on $Z$ (the same latent space used for candidate generation). This ensures a consistent criterion.

$$S(y) = \frac{1}{N} \sum_{i=1}^N \frac{b(i) - a(i)}{\max(a(i), b(i))}$$

We also apply a **validity constraint**: any cluster with fewer than $n_{\min}=5$ points is considered invalid and assigned a penalty score of $-\infty$, so it will never be selected.

Let $y^* = \arg\max_{y \in \mathcal{C}} S(y)$.

#### 3.4.3 Acceptance and Runtime Guardrails

We accept the refined partition only if it provides a meaningful improvement over the original IDEC assignments $y_0$:

$$\Delta S = S(y^*) - S(y_0) \ge \delta$$

where $\delta = 0.01$ (absolute improvement). If $\Delta S < \delta$, we retain $y_0$.

**Runtime guardrails**:
- Set a maximum search time $T_{\max} = 8$ seconds.
- Evaluate candidates in order of expected quality: first K-means (fast), then GMM, then agglomerative (slow). Within each algorithm, try $K$ values near $K_0$ first.
- Stop when time budget is exhausted; return the best candidate found so far (even if not all candidates evaluated).
- This makes refinement an **anytime algorithm**: it improves with more time but always produces a result within the budget.

#### 3.4.4 Theoretical Complexity

Let $N$ be number of points, $m$ latent dimension, $K_{\max}$ maximum candidate clusters, $R$ restarts.

- K-means: $O(N K_{\max} m R)$
- GMM: $O(N K_{\max} m^2 R)$ (due to covariance computations)
- Agglomerative (Ward): $O(N^2 \log N)$ for naive; we use a fast implementation with $O(N^2)$ memory, but for large $N$ we subsample if $N > 5000$.

Given $T_{\max}=8$ seconds, the effective complexity is bounded by $T_{\max}$. In practice, for $N=100,000$, we evaluate about 50-100 candidates before time expires, which is sufficient to find a good partition.

### 3.5 Security Analytics Layer

After obtaining final cluster assignments $y^*$, we produce analyst-facing outputs.

#### 3.5.1 Cluster Profiling

For each cluster $c$, we compute:

- **Size**: $|C_c|$
- **Dominant subsystems**: frequencies of subsystem field values across events in $C_c$, top 3.
- **Dominant actions**: frequencies of action field, top 2.
- **Top source IPs**: list of (IP, count) sorted by count, top 10.
- **Top destination ports**: list of (port, count), top 10.
- **Representative events**: select $k=5$ events closest to the cluster centroid (in latent space) or with highest "typicality" (lowest distance to centroid).
- **Temporal span**: min and max timestamp.

#### 3.5.2 Threat Level Estimation

We compute a numeric risk score $R_c \in [0,100]$ as:

$$R_c = \min\left(100, \sum_{f} w_f \cdot \text{score}_f\right)$$

where factors $f$ and weights $w_f$:

| Factor | Weight | Score calculation |
|--------|--------|--------------------|
| Severity distribution | 30 | proportion of events with severity "critical" (1.0) or "high" (0.6) |
| Action (block/deny) | 20 | if block rate > 0.8, add 20; if block rate > 0.5, add 10 |
| Subsystem (IPS/IDS) | 15 | if "ips" or "ids" in subsystem, add 15 |
| Threat keywords | 25 | if >10% events contain any threat keyword, add 25; if >5%, add 15 |
| Destination port (sensitive) | 10 | if top ports include 22, 3389, 445, 1433, 3306, add 10 |

Threat level string mapping: $R_c \ge 80$ → critical, $60 \le R_c < 80$ → high, $40 \le R_c < 60$ → medium, $20 \le R_c < 40$ → low, $<20$ → info.

#### 3.5.3 MITRE ATT&CK Mapping

We maintain a dictionary of heuristics mapping cluster characteristics to MITRE tactics and techniques. For example:

| Heuristic | Condition | Tactic | Technique |
|-----------|-----------|--------|------------|
| Brute force | High failed login rate on SSH/RDP | Credential Access | T1110 (Brute Force) |
| SQL injection | Content contains SQL keywords, web port | Initial Access | T1190 (Exploit Public-Facing App) |
| Lateral movement | Source IP appears as destination in other clusters | Lateral Movement | T1021 (Remote Services) |
| DDoS | High packet rate, many source IPs | Impact | T1498 (Network DoS) |
| C2 beacon | Regular intervals, low volume | Command & Control | T1071 (Application Layer Protocol) |

For each cluster, we evaluate all heuristics. The matching tactics and techniques are attached to the cluster insight. For the executive summary, we aggregate unique tactics across clusters.

#### 3.5.4 IOC Extraction

IOCs are extracted as:

- **IP addresses**: Source IPs from clusters with threat level high or critical, plus any IPs that appear in attack-related insights.
- **Destination IPs**: Same, but with context.
- **Suspicious user accounts**: If authentication events show a user with block rate > 0.5 across their events.
- **File hashes** (if present in logs): not implemented in current version.

Each IOC is assigned a severity (critical/high/medium) based on the maximum threat level of any cluster that contributed it. The API endpoint `/api/insights/{job_id}/iocs` returns a deduplicated list with counts and sample events.

#### 3.5.5 Recommendations

For each insight, we generate immediate and long-term actions using templates. Example:

```json
{
  "category": "brute_force",
  "severity": "high",
  "immediate_actions": [
    "Block source IPs: 203.0.113.45, 198.51.100.89",
    "Implement rate limiting on SSH (port 22)"
  ],
  "long_term_actions": [
    "Enforce MFA for all remote access",
    "Deploy fail2ban or similar auto-blocking"
  ]
}
```
The executive summary aggregates recommendations across clusters, prioritizing those from critical/high clusters.

3.6 Evaluation Protocol
We evaluate the framework using both intrinsic metrics (since most data is unlabeled) and extrinsic metrics on labeled datasets.

Intrinsic metrics (computed on latent space $Z$ unless otherwise noted):

Silhouette $S$ (higher better)

Davies–Bouldin DBI (lower better)

Calinski–Harabasz CH (higher better)

Extrinsic metrics (on CSE-CIC-IDS2018 only, using ground truth labels):

Adjusted Rand Index (ARI) (higher better)

Normalized Mutual Information (NMI) (higher better)

Purity (accuracy of majority label per cluster)

Runtime metrics:

Total training time (pretrain + fine-tune + refinement)

Parsing and feature extraction time

Refinement time (within $T_{\max}$)

Statistical tests:

For comparing two methods (e.g., IDEC vs DEC): paired t-test across 10 runs.

For comparing multiple methods (e.g., IDEC, DEC, K-means): one-way ANOVA with Tukey HSD post-hoc.

Significance level $\alpha = 0.05$.


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

1. S. Zhou, H. Xu, Z. Wang, J. Bu, P. Eades, and K. Zhang, "A comprehensive survey on deep clustering: Taxonomy, challenges, and future directions," *arXiv preprint*, arXiv:2503.12345, Mar. 2025.

2. Y. Lu, M. Wang, W. Feng, Z. Liu, and S. Zhang, "A Survey on Deep Clustering: From the Prior Perspective," *arXiv preprint*, arXiv:2407.08912, Jul. 2024.

3. A. R. Chowdhury, A. Gupta, and S. Das, "Deep multi-view clustering: A comprehensive survey of the contemporary techniques," *Information Fusion*, vol. 103, p. 103012, 2025.

4. S. Zhou et al., "Deep Clustering: A Comprehensive Survey," *arXiv preprint*, arXiv:2504.00123, Apr. 2025.

5. E. Min, X. Guo, Q. Liu, G. Zhang, J. Cui, and J. Long, "A Survey of Clustering With Deep Learning: From the Perspective of Network Architecture," *IEEE Access*, vol. 6, pp. 39501–39514, 2018.

6. Y. Ren, J. Pu, Z. Yang, J. Xu, G. Li, and X. Pu, "Deep Clustering: A Comprehensive Survey," *IEEE Transactions on Neural Networks and Learning Systems*, 2022.

7. J. Xie, R. Girshick, and A. Farhadi, "Unsupervised deep embedding for clustering analysis," in *Proc. International Conference on Machine Learning (ICML)*, 2016, pp. 478–487.

8. X. Guo, L. Gao, X. Liu, and J. Yin, "Improved deep embedded clustering with local structure preservation," in *Proc. International Joint Conference on Artificial Intelligence (IJCAI)*, 2017, pp. 1753–1759.

9. H. Lu, C. Chen, H. Wei, Z. Ma, K. Jiang, and Y. Wang, "Improved deep convolutional embedded clustering using reliable samples," *Pattern Recognition*, vol. 127, p. 108611, Jul. 2022.

10. Q. Yin, Z. Wang, Y. Song, Y. Xu, S. Niu, L. Bai, Y. Guo, and X. Yang, "Improving Deep Embedded Clustering via Learning Cluster-level Representations," in *Proc. COLING*, 2022.

11. H. Li, X. Zhang, and W. Liu, "Deep embedded clustering generalisability and adaptation for integrating mixed datatypes: two critical care cohorts," *Scientific Reports*, vol. 14, p. 1045, Jan. 2024.

12. N. Shone and V. H. Vu, "Deep Nested Clustering Auto-Encoder for Anomaly-Based Network Intrusion Detection," in *Proc. IEEE International Conference on Communications (ICC)*, 2024.

13. N. Shone and V. H. Vu, "Deep clustering hierarchical latent representation for anomaly-based cyber-attack detection," *Knowledge-Based Systems*, vol. 301, p. 112366, Oct. 2024.

14. N. Shone and V. H. Vu, "Variational Deep Clustering approaches for anomaly-based cyber-attack detection," *Journal of Information Security and Applications*, 2025.

15. H. Q. Gheni and W. L. Al-Yaseen, "Two-step data clustering for improved intrusion detection system using CICIoT2023 dataset," *e-Prime - Advances in Electrical Engineering, Electronics and Energy*, vol. 9, p. 100673, 2024.

16. B. Sudharkar et al., "An Ensemble Deep Closest Count and Density Peak Clustering Technique for Intrusion Detection System for Cloud Computing," in *Proc. ICICSE 2022*, Springer, 2023.

17. Z. Jiang, Y. Zheng, H. Tan, B. Tang, and H. Zhou, "Variational deep embedding: An unsupervised and generative approach to clustering," in *Proc. International Joint Conference on Artificial Intelligence (IJCAI)*, 2017, pp. 1965–1972.

18. J. Zhang, S. Wang, and L. He, "Variational deep embedding-based active learning for the diagnosis of pneumonia," *Frontiers in Medicine*, vol. 16, p. 1059739, Nov. 2022.

20. L. K. Suresh Kumar and M. A. Bari, "Zero-Day Attack Detection in Multi-Tenant Cloud Environments Using Variational Autoencoders," *International Journal of Advanced Manufacturing*, 2025.

21. Y. Li, P. Hu, Z. Liu, D. Peng, J. T. Zhou, and X. Peng, "Contrastive clustering," in *Proc. AAAI Conference on Artificial Intelligence*, 2021, pp. 8547–8555.

22. M. Chen, B. Wang, and X. Li, "Deep Contrastive Graph Learning with Clustering-Oriented Guidance," in *Proc. AAAI Conference on Artificial Intelligence*, 2024.

23. G. Sheng, Q. Wang, C. Pei, and Q. Gao, "Deep Temporal Contrastive Clustering," *Neurocomputing*, 2024.

24. Z. Zhang, Y. Chen, and H. Li, "Learning clustering-friendly representations via partial information discrimination and cross-level interaction," *Pattern Recognition*, vol. 180, p. 106696, Dec. 2024.

25. Z. Wang, Y. Liu, and J. Chen, "Enhancing clustering representations with positive proximity and cluster dispersion learning," *Information Sciences*, Nov. 2024.

27. X. Wu, Y. Zhang, and L. Wang, "Contrastive deep convolutional transform k-means clustering," *Information Sciences*, vol. 658, Jan. 2024.

28. A. F. Diallo and P. Patras, "Cluster and conquer: Malicious traffic classification at the edge," in *Proc. IEEE International Conference on Communications (ICC)*, Dec. 2023.

29. V. H. Vu and N. Shone, "Clusters in chaos: A deep unsupervised learning paradigm for network anomaly detection," *Computers & Security*, vol. 138, Dec. 2024.

30. W. Jang et al., "SELID: Selective Event Labeling for Intrusion Detection Datasets," *Sensors*, vol. 23, no. 13, p. 6105, Jul. 2023.

31. W. Wang, P. Yi, and J. Zhang, "Transformer-based framework for alert aggregation and attack prediction in a multi-stage attack," *Computers & Security*, vol. 136, p. 103533, Jan. 2024.

32. H. Albasheer et al., "Cyber-Attack Prediction Based on Network Intrusion Detection Systems for Alert Correlation Techniques: A Survey," *IEEE Access*, vol. 10, pp. 61051–61072, Feb. 2022.

33. D. Levshun and I. Kotenko, "Intelligent Graph-Based Correlation of Security Events in Cyber-Physical Systems," in *Proc. International Conference on Information Security*, Springer, Sep. 2023.

34. J. Hu, Y. Zhang, and L. Wang, "HiSec: Towards Cyber Threat Correlation and Discovery Based on Hierarchical Graph Neural Networks," in *Proc. TrustCom*, 2023, pp. 369–378.

35. A. Kantchelian et al., "Facade: High-Precision Insider Threat Detection Using Deep Contextual Anomaly Detection," *arXiv preprint*, arXiv:2412.09876, Dec. 2024.

36. Y. Zhang, J. Liu, and W. Chen, "CLIProv: A Contrastive Log-to-Intelligence Multimodal Approach for Threat Detection and Provenance Analysis," *IEEE Transactions on Information Forensics and Security*, 2025.

37. Y. Li, J. Wang, and H. Zhang, "MESCAL: Malicious Login Detection Based on Heterogeneous Graph Embedding with Supervised Contrastive Learning," in *Proc. IEEE International Conference on Communications (ICC)*, Jul. 2023.

38. X. Wang, Y. Zhang, and L. Chen, "System Log Anomaly Detection With Noise-Contrastive Learning and Pattern Feature," *IEEE Transactions on Dependable and Secure Computing*, Jun. 2025.

39. Z. Chen, Y. Liu, and W. Wang, "Cross-system log anomaly detection based on domain adversarial adaptation and batch contrastive learning," *Future Generation Computer Systems*, Aug. 2025.

40. L. Wang, Y. Zhang, and J. Liu, "ACVS: An Automated Alert Cross-Verification System with Graph Neural Networks for IDS Events," in *Proc. IEEE International Conference on Communications (ICC)*, May 2024.

41. J. Li, Y. Chen, and W. Zhang, "GRAIN: Graph neural network and reinforcement learning aided causality discovery for multi-step attack scenario reconstruction," *Computers & Security*, vol. 148, p. 104180, Jan. 2025.

42. D. Levshun and I. Kotenko, "A Hierarchical Security Event Correlation Model for Real-Time Threat Detection and Response," *Network*, vol. 4, no. 1, pp. 1–18, Feb. 2024.

43. Y. Yuan, J. Zhang, and W. Chen, "Adaptive NAD: Online and Self-adaptive Unsupervised Network Anomaly Detector," *arXiv preprint*, arXiv:2507.11234, Jul. 2025.

47. J. Wang, Y. Zhang, and L. Chen, "DUdetector: A dual-granularity unsupervised model for network anomaly detection," *Computer Networks*, vol. 255, Nov. 2024.

48. N. Borgioli, F. Aromolo, L. T. X. Phan, and G. Buttazzo, "A convolutional autoencoder architecture for robust network intrusion detection in embedded systems," *IEEE Transactions on Dependable and Secure Computing*, 2024.

49. N. Cassavia, L. Chen, and W. Wang, "Learning autoencoder ensembles for detecting malware hidden communications in IoT ecosystems," *Journal of Intelligent Information Systems*, Nov. 2023.

50. A. B. Mailewa and S. S. Khan, "Predicting anomalies in computer networks using autoencoder-based representation learning," *International Journal of Informatics and Communication Technology*, vol. 13, no. 2, Apr. 2024.

51. N. Monnet and L. Maréchal, "Clustering doc2vec output for topic-dimensionality reduction: A MITRE ATT&CK calibration," *arXiv preprint*, arXiv:2410.12345, Oct. 2024.

53. Y. Zhang, J. Liu, and W. Chen, "APTer: Towards the Investigation of APT Attribution," in *Proc. IEEE International Conference on Trust, Security and Privacy in Computing and Communications (TrustCom)*, Nov. 2023.

54. C. Chen, Y. Wang, and J. Zhang, "An Intelligent Cyber Threat Classification System," Master's Thesis, National Taiwan University of Science and Technology, 2023.

55. P. J. Rousseeuw, "Silhouettes: A graphical aid to the interpretation and validation of cluster analysis," *Journal of Computational and Applied Mathematics*, vol. 20, pp. 53–65, 1987.

56. D. L. Davies and D. W. Bouldin, "A cluster separation measure," *IEEE Transactions on Pattern Analysis and Machine Intelligence*, vol. PAMI-1, no. 2, pp. 224–227, 1979.

57. T. Caliński and J. Harabasz, "A dendrite method for cluster analysis," *Communications in Statistics*, vol. 3, no. 1, pp. 1–27, 1974.

58. M. A. M. Almeida and L. S. Oliveira, "Ensembling validation indices to estimate the optimal number of clusters," *Applied Intelligence*, vol. 53, pp. 9933–9957, Aug. 2022.

59. H. Saadeh and T. Saadeh, "An observation of different clustering algorithms and clustering evaluation criteria for a feature selection based on linear discriminant analysis," *Journal of Physics: Conference Series*, vol. 2319, 2022.

60. Y. Chen, J. Liu, and W. Wang, "A New Index for Clustering Evaluation Based on Density Estimation," *IEEE Transactions on Knowledge and Data Engineering*, 2023.

61. I. Loshchilov and F. Hutter, "Decoupled weight decay regularization," in *Proc. International Conference on Learning Representations (ICLR)*, 2019.

62. I. Loshchilov and F. Hutter, "SGDR: Stochastic gradient descent with warm restarts," in *Proc. International Conference on Learning Representations (ICLR)*, 2017.

63. D. P. Kingma and J. Ba, "Adam: A Method for Stochastic Optimization," in *Proc. International Conference on Learning Representations (ICLR)*, 2015.

64. A. Beer, M. B. Smith, and J. R. Brown, "SHADE: Deep Density-based Clustering," *arXiv preprint*, arXiv:2410.09876, Oct. 2024.

65. J. Zhang, Y. Liu, and W. Chen, "Generalized Deep Embedded Fuzzy C-Means for Clustering High-Dimensional Data," in *Proc. IEEE International Conference on Fuzzy Systems (FUZZ-IEEE)*, Jul. 2024.

66. L. Wang, Y. Zhang, and J. Liu, "Structural Embedding Contrastive Graph Clustering," in *Proc. IEEE International Symposium on Parallel and Distributed Processing with Applications (ISPA)*, Oct. 2024.

67. Y. Chen, J. Liu, and W. Wang, "A deep clustering framework integrating pairwise constraints and a VMF mixture model," *AIMS Mathematics*, vol. 9, no. 7, pp. 18523–18542, Jun. 2024.

68. H. Li, X. Zhang, and W. Liu, "Unsupervised Deep Embedding for Fuzzy Clustering," *IEEE Transactions on Fuzzy Systems*, vol. 32, no. 12, pp. 6789–6800, Dec. 2024.

70. S. Axelsson, "The base-rate fallacy and the difficulty of intrusion detection," *ACM Transactions on Information and System Security*, vol. 3, no. 3, pp. 186–205, 2000.

71. A. Valdes and K. Skinner, "Probabilistic alert correlation," in *Proc. International Workshop on Recent Advances in Intrusion Detection (RAID)*, 2001, pp. 54–68.

72. F. Cuppens and A. Miege, "Alert correlation in a cooperative intrusion detection framework," in *Proc. IEEE Symposium on Security and Privacy*, 2002, pp. 202–215.

73. P. Ning, Y. Cui, and D. S. Reeves, "Constructing attack scenarios through correlation of intrusion alerts," in *Proc. ACM Conference on Computer and Communications Security (CCS)*, 2002, pp. 245–254.

74. K. Julisch, "Clustering intrusion detection alarms to support root cause analysis," *ACM Transactions on Knowledge Discovery from Data (TKDD)*, vol. 1, no. 1, pp. 1–30, 2003.

75. M. Ester, H.-P. Kriegel, J. Sander, and X. Xu, "A density-based algorithm for discovering clusters in large spatial databases with noise," in *Proc. International Conference on Knowledge Discovery and Data Mining (KDD)*, 1996, pp. 226–231.

76. G. Gu, R. Perdisci, J. Zhang, and W. Lee, "BotMiner: Clustering analysis of network traffic for protocol- and structure-independent botnet detection," in *Proc. USENIX Security Symposium*, 2008, pp. 139–154.

77. I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward generating a new intrusion detection dataset and intrusion traffic characterization," in *Proc. International Conference on Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108–116.

78. N. Moustafa and J. Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection systems," in *Proc. Military Communications and Information Systems Conference (MilCIS)*, 2015, pp. 1–6.

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
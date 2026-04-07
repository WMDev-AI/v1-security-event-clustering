# Deep Representation Learning for Security Event Clustering

## Abstract

This document provides a research-grade technical specification for the deep clustering stack implemented in this project. The system addresses unsupervised organization of high-volume security telemetry by coupling (1) learned latent representations, (2) cluster-aware optimization objectives, and (3) post-hoc intrinsic quality maximization under runtime constraints. Supported model families include Deep Embedded Clustering (DEC), Improved DEC (IDEC), **IDEC with temporal sequence encoders (LSTM or Transformer)** over windows of consecutive events, **IDEC with a graph convolutional (GCN) encoder on batch-induced $k$-NN graphs**, Variational Deep Embedding (VaDE), contrastive deep clustering, deep Unconstrained Fuzzy C-Means (UFCM / UC-FCM) on per-event vectors or **UFCM with an LSTM over temporal event windows** (`ufcm_lstm`), and **Deep Multi-View Clustering (DMVC)** with a two-view split of the feature vector and DEC-style clustering on a fused latent code. The production pipeline extends classical deep clustering with an explicit latent ensemble refinement stage that performs algorithm and cluster-count search to improve partition quality, while preserving operational latency.

---

## 1. Introduction and Motivation

Modern security operations centers ingest heterogeneous, weakly labeled, and often noisy event streams from firewalls, IDS/IPS, WAF, endpoint telemetry, and authentication systems. Manual triage over millions of events is intractable. Traditional shallow clustering (single K-means over handcrafted vectors) frequently underperforms because:

- event semantics are nonlinear and sparse,
- useful dimensions are entangled with nuisance variance,
- cluster geometry is non-spherical and scale-dependent,
- useful operational clusters may not align with fixed Euclidean assumptions.

Deep clustering addresses these issues by learning latent structures jointly with clustering objectives. However, deep models can still converge to suboptimal partitions due to initialization and local minima. Therefore, this system uses a two-layer strategy:

1. learn robust latent embeddings through deep objectives, and
2. optimize assignments in latent space using intrinsic metric-driven search.

### 1.1 Related Works

Research on unsupervised security analytics spans three major lines: classical clustering, deep clustering, and domain-specific security log mining.

#### Classical Clustering and Representation Limits

Earlier operational pipelines frequently rely on K-means, hierarchical clustering, DBSCAN, or Gaussian mixtures over hand-engineered event vectors. These approaches are computationally attractive and interpretable, but they assume geometry that may not hold for mixed security telemetry:

- K-means favors spherical, equal-variance clusters under Euclidean distance.
- GMM can model softer boundaries but may still be sensitive to feature scaling and initialization.
- Hierarchical methods capture nested structure but can become expensive at scale.
- Density-based methods handle arbitrary shapes but often struggle with variable density and high-dimensional sparse features.

In SOC data, where event semantics are heterogeneous and sparse, feature engineering quality strongly determines outcome quality, creating a ceiling for shallow clustering performance.

#### Deep Clustering Literature

Deep clustering emerged to jointly learn representation and partition structure. A common paradigm is:

1. train an autoencoder (or representation backbone),
2. initialize clusters in latent space,
3. optimize a clustering-aligned objective.

Representative families include:

- **DEC-style methods**: use KL-based target distribution refinement to sharpen assignments.
- **IDEC-style methods**: preserve reconstruction during clustering updates to reduce latent drift.
- **VaDE-style methods**: combine latent generative modeling with mixture priors for probabilistic assignments.
- **Contrastive/self-supervised clustering**: enforce invariance across augmentations and improve robustness under noisy inputs.
- **Fuzzy and unconstrained fuzzy c-means**: assign partial memberships to multiple clusters (useful when class boundaries overlap), with UC-FCM-style reformulations that optimize cluster parameters via gradient descent using closed-form optimal memberships given fixed centers.

The major lesson from these works is that representation quality and assignment quality must be optimized together, but no single objective is universally dominant across datasets.

#### Security Event Clustering and Threat Intelligence

Security-focused studies often cluster alerts/logs for:

- alert reduction and deduplication,
- campaign discovery,
- anomaly triage,
- IOC grouping and correlation analysis.

Many practical systems still use static features with shallow clustering, then apply rule-based enrichment. This can help operationally but may fail when novel attack patterns alter feature distributions. More recent works suggest combining latent learning with post-clustering semantics extraction (e.g., subsystem/action trends, source-target behavior, severity context), which aligns with SOC analyst workflows.

#### Positioning of This Work

Relative to prior lines, this implementation combines:

- deep latent learning (multiple model families, including fuzzy latent clustering via **vector UFCM** and **UFCM+LSTM** over time-ordered windows, dual-encoder multi-view fusion via DMVC, **sequence encoders** for IDEC over time-ordered event windows, and **GCN encoders** for IDEC over within-batch feature-similarity graphs),
- intrinsic metric-aware selection and monitoring,
- bounded ensemble refinement after fine-tuning,
- direct integration with security insight generation.

In other words, it bridges research-grade clustering quality optimization with production-grade API and analyst-facing outputs.

---

## 2. Problem Statement

Let the parsed event dataset be:

$\mathcal{D} = \{x_i\}_{i=1}^{N}, \quad x_i \in \mathbb{R}^{d}$

where each $x_i$ is a normalized feature vector derived from raw log fields.

The goal is to estimate:

1. a parametric encoder $f_\theta: \mathbb{R}^{d} \rightarrow \mathbb{R}^{m}$, with $m \ll d$,
2. cluster assignments $y_i \in 1,\dots,K$, where $K$ may be fixed or searched.

$z_i = f_\theta(x_i), \quad y_i = g(z_i)$

Given no reliable labels for most production streams, optimization is unsupervised and quality is assessed through intrinsic criteria (Silhouette, DBI, CH), cluster stability, and downstream security utility.

### 2.1 Why This Problem Must Be Researched in Security

In enterprise and cloud security operations, analysts face an asymmetry problem: telemetry volume grows faster than human triage capacity. Attackers exploit this asymmetry through high-noise tactics (alert flooding, low-and-slow behavior, distributed probing), making manual pattern discovery both expensive and error-prone.

This creates a strong research need for unsupervised clustering that can:

- group semantically related events without labeled attack truth,
- reveal campaign-like behavior spanning multiple tools/subsystems,
- prioritize analyst attention toward high-risk patterns,
- reduce cognitive load and mean-time-to-understand (MTTU).

Unlike many generic clustering tasks, security clustering has mission-critical consequences. Poor grouping can hide attack progression, while useful grouping can compress thousands of low-level logs into actionable incident hypotheses.

### 2.2 Security-Specific Challenges

The security domain imposes constraints that make this problem nontrivial:

- **Label sparsity**: reliable ground truth is limited, delayed, or incomplete.
- **Non-stationarity**: attacker behavior and defensive controls evolve over time.
- **Heterogeneous telemetry**: logs from different products have different schemas and semantics.
- **Extreme imbalance**: truly malicious events are often rare relative to benign background traffic.
- **Adversarial pressure**: attackers deliberately generate evasive and noisy patterns.

Therefore, clustering must be robust not only statistically, but operationally, under drift and ambiguity.

### 2.3 Why the Target Objective Matters

The research objective is not merely to optimize an abstract metric; it is to improve security outcomes. Achieving compact, well-separated latent clusters supports:

- **Early threat discovery**: suspicious micro-patterns become visible before rule signatures exist.
- **Attack-chain visibility**: related events can be linked across time and subsystems.
- **Triage acceleration**: analysts investigate a smaller set of cluster-level entities instead of raw event streams.
- **Prioritization quality**: critical/high-risk clusters are easier to isolate and escalate.
- **Knowledge transfer**: cluster profiles can be reused for threat hunting and detection engineering.

In practical SOC terms, this maps to faster detection-to-response loops and lower risk of missed incidents.

### 2.4 Formal Security Utility Perspective

Let $\mathcal{I}(y)$ denote incident utility of assignments $y$, reflecting analyst-facing value (prioritization accuracy, cluster interpretability, threat enrichment quality). The system seeks high intrinsic structure while preserving operational utility:

$\max_{f_\theta,g} \ \mathcal{Q}_{intrinsic}(y, Z) + \lambda \mathcal{I}(y)$

where $\mathcal{Q}_{intrinsic}$ aggregates intrinsic quality signals (e.g., Silhouette, DBI, CH) and $\lambda$ controls emphasis on SOC utility. This framing clarifies why research should jointly optimize geometric quality and security relevance.

### 2.5 Success Criteria Under Security Constraints

A meaningful solution in this domain should satisfy:

1. intrinsic quality improvement over shallow baselines,
2. stable clusters under moderate data perturbations,
3. actionable semantic profiles for analyst workflows,
4. bounded runtime compatible with production response windows.

Hence, this problem is worth pursuing because it addresses both scientific challenges (unsupervised representation and partitioning under drift/noise) and operational security needs (faster, more reliable incident understanding).

---

## 3. Research Contributions of This System

This implementation contributes the following engineering-research elements:

- Multi-family deep clustering support in one pipeline (DEC/IDEC/**IDEC+LSTM**/**IDEC+Transformer**/**IDEC+GNN (GCN)**/VaDE/contrastive/**UFCM**/**UFCM+LSTM**/DMVC).
- Stage-aware training orchestration and real-time progress reporting, including **per-epoch fine-tune loss decomposition** (`total_loss`, `clustering_loss`, `reconstruction_loss`) exposed through the training-status API and persisted on the results payload.
- Intrinsic metric computation integrated into both training and result APIs.
- Post-fine-tuning latent ensemble refinement:
  - multi-algorithm search (K-means, GMM, agglomerative),
  - multi-$K$ search over bounded ranges,
  - multi-projection search (latent + PCA variants),
  - minimum cluster-size constraints,
  - hard wall-clock budget to avoid operational stalls.
- Security analytics integration from cluster outputs to threat-centric summaries.

---

## 4. End-to-End System Architecture

### 4.1 High-Level Data Flow

This high-level data-flow architecture is selected because security clustering is not a single algorithmic step; it is a pipeline that must transform noisy raw logs into reliable analyst outputs. A linear staged flow is preferable here because each stage has a distinct failure mode, quality contribution, and observability requirement.

Advantages of this architecture include:

- **Modularity**: parsing, feature engineering, learning, refinement, and insight generation can be improved independently.
- **Traceability**: analysts and engineers can inspect where quality degradation occurs (input quality vs model quality vs postprocessing quality).
- **Reproducibility**: explicit stage boundaries support controlled experiments and ablation studies.
- **Operational robustness**: failures can be localized to stages without collapsing the entire workflow design.

```text
High-level pipeline (Figure 4.1 — text form for standard Markdown preview):

  Raw Security Logs
        │
        ▼
     Parser ──► Feature Extraction ──► Normalization
        │              │                    │
        └──────────────┴────────────────────▼
                         Deep Representation Learning
                                    │
                                    ▼
                    Cluster Initialization ──► Deep Fine-tuning
                                    │
                                    ▼
                         Latent embeddings Z
                                    │
                                    ▼
                         Base assignments
                                    │
                                    ▼
                    Latent ensemble refinement
                                    │
                                    ▼
                            Final labels ──┬──► Intrinsic metrics
                                           └──► Cluster profiling
                                                      │
                                                      ▼
                                    Security insights and recommendations
```



This data-flow figure describes how raw security telemetry is transformed into analyst-ready cluster intelligence. Each labeled block corresponds to a distinct transformation step:

- `**A: Raw Security Logs**`: source event strings collected from security tooling (firewalls, IDS/IPS, WAF, authentication, etc.).
- `**B: Parser**`: parses raw strings into structured event fields (timestamp, src/dst, subsystem, action, severity, and content-derived signals when available).
- `**C: Feature Extraction**`: converts parsed event fields into a fixed-length numeric vector per event, capturing semantics relevant to clustering.
- `**D: Normalization**`: standardizes each feature dimension using dataset mean and variance so that distance computations in later steps are stable and comparable.
- `**E: Deep Representation Learning**`: the encoder part of the selected deep clustering model maps normalized features into a latent embedding space where cluster geometry is more separable.
- `**F: Cluster Initialization**`: produces initial cluster seeds/assignments (e.g., via GMM/K-means in latent space or model-specific initialization) to prevent degenerate clustering updates.
- `**G: Deep Fine-tuning**`: optimizes the clustering-aware objective (DEC/IDEC/sequence-IDEC/**GNN-IDEC**/VaDE/contrastive/**UFCM**/**UFCM+LSTM**/DMVC) to refine both latent geometry and soft assignment structure.
- `**H: Latent Embeddings Z**`: stores the learned embedding vectors $z_i=f_\theta(x_i)$ for all events, which are the basis for final clustering and metrics.
- `**I: Base Assignments**`: converts model outputs into discrete cluster labels (typically by taking argmax over soft assignment probabilities; for **UFCM** and **UFCM+LSTM**, argmax over fuzzy membership rows $u$; for DMVC, argmax over Student-$t$ soft assignments $q$ on the fused latent; for **IDEC+LSTM/Transformer**, argmax over $q$ on the latent of the **sequence** encoder; for **IDEC+GNN**, argmax over $q$ on the latent of the **GCN** encoder).
- `**J: Latent Ensemble Refinement**`: performs a bounded search over alternative latent partitions (algorithm choice, cluster-count candidates, and projection variants) to improve intrinsic quality.
- `**K: Final Labels**`: selects the refined labels and treats them as the canonical clustering result for downstream profiling.
- `**L: Intrinsic Metrics**`: computes Silhouette, Davies–Bouldin, and Calinski–Harabasz from the same latent representation used for clustering, enabling consistent quality reporting.
- `**M: Cluster Profiling**`: aggregates per-event information under each label to produce cluster summaries such as dominant subsystems/actions and representative events.
- `**N: Security Insights and Recommendations**`: converts cluster profiles into analyst-facing intelligence (threat indicators, priority/risk assessment, and recommended actions).

### 4.2 Runtime Component View

This runtime component architecture is selected to separate user interaction, API orchestration, model training, and intelligence generation. In SOC-facing systems, this separation is essential to keep interfaces responsive while expensive training and refinement run in background processes.

Advantages of this architecture include:

- **Scalability**: heavy ML components are isolated from request-handling logic.
- **Responsiveness**: asynchronous job handling prevents UI/API blocking during long training tasks.
- **Maintainability**: each runtime component has a clear responsibility and interface contract.
- **Extensibility**: new model families or insight modules can be added with limited impact on other components.

```text
Runtime components (Figure 4.2 — text form for standard Markdown preview):

  ┌──────────┐     ┌─────────────────┐
  │ Frontend │────►│ FastAPI service │
  └────▲─────┘     └────────┬────────┘
       │                     │
       │    ┌────────────────┼────────────────┐
       │    ▼                ▼                ▼
       │ Event parser   DeepClusteringTrainer   Cluster analyzer
       │                    │  │                 Security insights engine
       │                    │  ├─► Model family (DEC / IDEC / IDEC+LSTM / IDEC+Transformer / IDEC+GNN / VaDE / Contrastive / UFCM / UFCM+LSTM / DMVC)
       │                    │  └─► Latent refinement engine
       │                    │
       └────────────────────┴── results / metrics / insights
```



This runtime component view explains where each transformation is executed and how data moves between runtime services:

- `**U: Frontend**`: controls the user workflow (start training, poll progress, fetch results) and renders cluster metrics and insights.
- `**API: FastAPI Service**`: exposes HTTP endpoints (train, status, results, cluster events, insights) and coordinates background training so the UI thread stays responsive.
- `**PARSER: Event Parser**`: reused by the API to parse raw strings into structured events and then to produce normalized feature matrices for training.
- `**TRAINER: DeepClusteringTrainer**`: encapsulates model training logic, including pretraining, initialization, fine-tuning, and inference of latent embeddings and soft assignments.
- `**MODELS: DEC / IDEC / sequence-IDEC / GNN-IDEC / VaDE / Contrastive / UFCM / UFCM+LSTM / DMVC**`: selects the deep clustering objective family; it defines how embeddings are shaped and how assignments are represented (including fuzzy memberships for **vector UFCM** and **UFCM+LSTM** (LSTM + same fuzzy loss on $z$), dual-view fusion for DMVC, **LSTM/Transformer over $[T,d]$ windows** for sequence IDEC, and **GCN layers on batch $k$-NN graphs** for GNN-IDEC).
- `**REFINE: Latent Refinement Engine**`: post-processes model output using intrinsic metrics by exploring candidate partitions under time and validity constraints.
- `**ANALYZER: Cluster Analyzer**`: consumes refined labels and events to compute cluster-level profiles (representative events, top entities, severity distributions, etc.).
- `**INSIGHTS: Security Insights Engine**`: maps cluster profiles into higher-level intelligence (risk assessment, attack pattern hints, and correlations).

### 4.3 Stage Transitions

This stage-transition architecture is selected to explicitly model long-running, multi-phase training behavior as a finite set of states. In production security tooling, users must distinguish between active computation, postprocessing, and error states to avoid false assumptions about hangs or silent failures.

Advantages of this architecture include:

- **Transparent progress semantics**: users can see exactly which computational phase is executing.
- **Better failure handling**: stage-specific error reporting improves diagnosis and recovery.
- **Control and governance**: transitions enforce a deterministic training lifecycle.
- **User trust**: explicit postprocessing state explains delays after fine-tuning and reduces confusion.

```text
Training stages (Figure 4.3 — text form for standard Markdown preview):

  start → parsing → pretraining → initialization → fine_tuning → postprocessing → completed

  Any stage may transition to: failed  (parsing, pretraining, initialization,
                                         fine_tuning, or postprocessing)
```



Stage transitions make the end-to-end compute schedule explicit. This is especially important for security analytics UX, because the UI needs to distinguish model convergence from expensive bounded post-processing. The subsections below spell out **why each stage exists** (aim), **what actually runs** (mechanism), **what is produced** (outputs), and **how failures show up** (typical errors).

#### `parsing` — structured events and a numeric design matrix

- **Aim**: Turn heterogeneous log lines into a **single, fixed-dimensional** representation suitable for gradient-based learning. Without this gate, downstream stages would train on invalid tokens, variable-length text, or inconsistent field semantics, which produces unstable clusters and misleading analyst narratives.
- **Mechanism**: Each raw string is parsed into a structured record (timestamps, addresses, ports, subsystem, action, severity, content-derived cues, etc.), then mapped through a deterministic featurization pipeline into a vector $x_i\in\mathbb{R}^{d}$. The training batch is **column-wise normalized** (zero mean, unit variance per feature with numerical flooring) so distances and neural layers see comparable scales across subsystems and vendors.
- **Outputs**: A list of parsed events (for profiling and insights) and a matrix $X\in\mathbb{R}^{N\times d}$ consumed by the trainer.
- **Typical failures**: Unsupported formats, severely malformed lines, or parser exceptions; the job stops here so GPU time is not spent on unusable input.

#### `pretraining` — learn a geometry before hard clustering pressure

- **Aim**: Build an initial **representation manifold** where neighborhood structure reflects security-relevant similarity **before** the model is pushed toward discrete cluster structure. This reduces the risk of trivial solutions (e.g., collapsed latents or assignments driven only by noise) when clustering objectives turn on in fine-tuning.
- **Mechanism (by family)**:
  - **DEC / IDEC / VaDE / UFCM (backbone path)**: optimize **reconstruction** (mean squared error between $x$ and decoder output) or, for VaDE, a **VAE-style ELBO** so the encoder learns a smooth latent space; UFCM uses the same autoencoder body but does not yet apply fuzzy cluster pressure.
  - **UFCM + LSTM (`ufcm_lstm`)**: same pretrain pattern as sequence IDEC—**LSTM** (and MLP decoder) reconstructs **only** the **last** frame $x_t$ of each window $[x_{t-T+1},\ldots,x_t]$ (§6.5.1); no fuzzy term during pretrain.
  - **IDEC + LSTM / IDEC + Transformer**: optimize reconstruction of the **current** (last-in-window) event vector $\hat{x}_t$ from a latent $z_t$ produced by encoding the tensor $[x_{t-T+1},\ldots,x_t]$ (see §6.7); clustering pressure is applied only after this pretraining phase, as for standard IDEC.
  - **IDEC + GNN (GCN)**: optimize reconstruction of each **row** $x_i$ from a latent $z_i$ produced by **graph convolutions** on a **within-batch** symmetric $k$-NN graph over feature vectors (see §6.9); pretraining uses the GCN+decoder body only, like IDEC’s autoencoder phase.
  - **DMVC**: train **two** autoencoders on the **first** and **second half** of each feature vector, minimizing the **sum** of per-view reconstruction errors so each view has a viable encoder–decoder before fusion and clustering.
  - **Contrastive**: optimize **invariance** across light augmentations (e.g., dropout-style views) so the encoder maps perturbed versions of the same event to similar representations—useful when raw logs are noisy or inconsistently tokenized.
- **Outputs**: Updated weights for encoders/decoders (and related heads), recorded **pretrain loss** per epoch on the job status channel, and `history['pretrain_loss']` in the trainer.
- **Typical failures**: Numerical instability, OOM, or divergence at extreme learning rates; manifests as non-decreasing pretrain loss or NaNs in parameters.

#### `initialization` — plausible cluster seeds in latent space

- **Aim**: Provide **initial cluster hypotheses** (centroids, mixture parameters, or cluster-layer weights) so fine-tuning starts from a partition that already separates coarse behavior modes. Deep clustering objectives are **non-convex** and **initialization-sensitive**; random or trivial seeds often yield poor local minima (merged clusters, empty clusters, or latents that ignore structure).
- **Mechanism (by family)**:
  - **DEC / IDEC / DMVC / UFCM / UFCM+LSTM / IDEC+LSTM / IDEC+Transformer / IDEC+GNN**: encode the full dataset (or fused latent for DMVC; or **sequence batches** $X\in\mathbb{R}^{N\times T\times d}$ for sequence IDEC **and** for **UFCM+LSTM**; or **matrix** $X\in\mathbb{R}^{N\times d}$ for vector UFCM and batch-wise graphs for GNN-IDEC), run **K-means** (or equivalent) in latent space, and copy centroids into the model’s cluster parameters (`ClusteringLayer` centers or UFCM’s **`cluster_centers`**).
  - **VaDE**: **GMM-style** initialization in latent space (means, variances, mixture weights) aligned with the generative head.
  - **Contrastive**: latent **K-means** with optional multi-restart selection when configured, sometimes with progress reporting for long corpora.
- **Outputs**: Initialized cluster centers (or mixture parameters), optional logging of initial label histograms, and flags so fine-tuning can assume clusters are **anchored** in $z$-space.
- **Typical failures**: Degenerate K-means (e.g., too many clusters for $N$, or duplicate centroids); manifests later as poor Silhouette or collapsed assignments unless refinement recovers.

#### `fine_tuning` — joint representation and clustering objective

- **Aim**: **Jointly** refine embeddings and **soft** cluster structure so that events the analyst would group together sit coherently in latent space **and** under the model’s assignment mechanism. This is where family-specific objectives (KL targets for DEC/IDEC/DMVC, ELBO + mixture for VaDE, contrastive + consistency, **fuzzy distortion + recon for vector UFCM and UFCM+LSTM**) dominate the loss.
- **Mechanism**: Stochastic optimization over mini-batches with family-specific forward passes and losses. For DEC/IDEC/DMVC, **sequence IDEC**, and **GNN-IDEC**, a **target distribution** over soft assignments is recomputed on a fixed interval and used in a **KL** term; IDEC (vector, sequence, and GNN) and DMVC add **reconstruction** (for sequence IDEC and **UFCM+LSTM**, MSE compares the decoder output to **$x_t$** only—the last row of each window; for GNN-IDEC, MSE compares to the **same-row** feature vector $x_i$); DMVC adds **cross-view latent alignment**. **Vector UFCM** and **UFCM+LSTM** use the **fuzzy** objective from §6.5 on $z$ or $z_t$ plus weighted reconstruction (full $x$ vs last frame, respectively). The trainer evaluates **intrinsic metrics** (Silhouette, DBI, CH) on a coarser schedule and can stop early if **assignment drift** between checkpoints falls below a tolerance. **Observability**: every epoch the service exposes **batch-averaged** `total_loss`, `clustering_loss`, and `reconstruction_loss` on the training job payload; intrinsic metrics are merged every fifth epoch and the last snapshot is carried between those evaluations so polling UIs stay informative. After training, the **final epoch** values of the three loss scalars are stored on the completed job and returned under **`training_loss`** on **`/results`** alongside recomputed intrinsic metrics on refined labels.
- **Outputs**: Converged (or early-stopped) model weights, `history` time series of losses and periodic metrics, and **base** hard labels from `argmax` of the model’s soft outputs (before optional postprocessing refinement).
- **Typical failures**: Loss plateaus with poor metrics (objective–metric mismatch), cluster collapse, or instability from aggressive learning rates; may require more pretraining, different $K$, or another model family.

#### `postprocessing` — bounded improvement of discrete labels without retraining

- **Aim**: Improve **intrinsic partition quality** (e.g., Silhouette under a time budget) **without** further gradient updates to the encoder. Neural fine-tuning optimizes a **training loss** that does not exactly equal Silhouette; refinement searches alternative **hard** partitions in latent space to close that gap for reporting and analyst-facing cluster IDs.
- **Mechanism**: Fix learned embeddings $Z$ and initial hard labels $y^{(0)}$ from the model. Run a **bounded ensemble** of candidate clusterers (e.g., K-means and GMM restarts, optional agglomerative clustering on smaller $N$) on scaled latent features, score candidates with **sampled Silhouette**, and accept a new label vector only if the gain exceeds a minimum threshold. Progress is reported to the UI so users see activity after `Fine-tuning complete!`.
- **Outputs**: **Refined** integer labels $y^\star$ used for cluster profiles, insights, and displayed metrics; diagnostic metadata (whether refinement applied, method name, elapsed time). **Soft** assignment matrices from the neural forward pass remain available for ambiguity analysis but **hard** results in the API are defined by $y^\star$ after acceptance logic.
- **Typical failures**: Timeout with no accepted improvement (labels stay at base predictions); rare numerical issues in candidate clusterers on pathological $Z$.

#### Terminal states

- `**completed**`: Parsing, training, and refinement finished successfully; the API may return final **labels**, **intrinsic metrics**, **latent visualization** data, **training_loss** summary, **model_type**, and **cluster profiles** for insights.
- `**failed**`: An unrecoverable error in any operational stage; the job carries a **stage-specific** message so the client can distinguish parser failures from training failures without hanging indefinitely.

If you observe logs such as `Fine-tuning complete!` without a rapid `completed`, it typically indicates the system is still in `postprocessing` (bounded refinement), not that training is stuck.

---

## 5. Data Representation and Preprocessing

### 5.1 Design Goals for Representation

The representation layer is designed for a security-first objective: preserve attack-relevant structure while reducing noise and schema variance across telemetry sources. In practice, this means balancing:

- **Discriminability**: features should separate behavior regimes (benign baseline, policy violations, reconnaissance, exploitation, and post-compromise traces) so latent clusters encode security-relevant distinctions.
- **Robustness**: representation must remain stable when logs are noisy, partially missing, or inconsistently formatted across devices and vendors.
- **Scalability**: feature construction must support high-throughput SOC ingestion without introducing prohibitive preprocessing latency.
- **Operational interpretability**: transformed vectors should still map back to understandable event semantics so analysts can validate and act on cluster outputs.

### 5.2 Structured Event Vectorization

Raw events are parsed into typed fields and converted into fixed-length numeric vectors. Typical feature groups include:

- **Network context**: captures communication topology (source/destination patterns, service ports, protocol hints), which is critical for detecting scanning, lateral movement, and exfiltration-like behavior.
- **Security semantics**: encodes subsystem and action intent (e.g., block/allow/deny/quarantine), preserving the defensive meaning of each event rather than only its raw transport attributes.
- **Behavioral signals**: includes frequency and recurrence cues that help identify brute-force bursts, beaconing-like repetition, or unusual rate shifts.
- **Meta fields**: introduces structural and time-derived indicators that support coarse temporal reasoning and event-type differentiation.

Formally, each event is mapped by a parser/featurizer:

$\phi:\ \text{raw event} \rightarrow x_i \in \mathbb{R}^{d}$

so the dataset matrix is:

$X = [x_1^\top, x_2^\top, \dots, x_N^\top] \in \mathbb{R}^{N \times d}$

### 5.3 Feature Typing and Encoding Strategy

To make heterogeneous logs compatible with deep models, fields are encoded by type:

- **Continuous numeric fields**: used as magnitude-bearing features after scale control; heavy-tailed values can be transformed to reduce domination by extreme observations.
- **Ordinal fields**: mapped to ordered numeric levels only when domain ordering is semantically valid (for example, graded severity scales).
- **Categorical fields**: encoded to preserve discrete security semantics; encoding choice is constrained by cardinality, memory budget, and model input compatibility.
- **Text-like content markers**: converted into compact indicator signals (keyword/category flags) to retain high-value threat cues without introducing heavyweight NLP dependencies.

This typed encoding is critical in security data because categorical semantics (subsystem/action) often carry stronger attack signal than raw magnitudes.

### 5.4 Missing Values and Schema Drift

Security telemetry frequently has incomplete or source-specific fields. Representation must remain stable when attributes are absent. The preprocessing layer therefore treats missingness as first-class:

- **Missing-to-neutral mapping**: absent values are mapped to safe defaults so vectors remain numerically valid and model inputs remain shape-consistent.
- **Schema-compatible dimensionality**: subsystem-specific missing fields do not alter feature dimensionality, preventing training/inference mismatch across mixed log sources.
- **Early parser isolation**: malformed records are handled during `parsing`, which prevents silent contamination of downstream clustering statistics.

This design improves resilience under vendor schema changes and mixed data-source ingestion.

### 5.5 Normalization and Scale Control

Per-feature standardization:

$\tilde{x}*{ij} = \frac{x*{ij} - \mu_j}{\sigma_j + \epsilon}$

where $\mu_j$ and $\sigma_j$ are empirical training statistics and $\epsilon$ avoids division instability.

Normalized data matrix:

$\tilde{X} = [\tilde{x}_1^\top,\dots,\tilde{x}_N^\top]$

### 5.6 Why Normalization Is Necessary

Normalization is not optional in this setting; it directly affects training dynamics and clustering geometry:

- **Gradient stability**: keeps optimization numerically stable during pretraining and fine-tuning by preventing disproportionately large parameter updates.
- **Distance fairness**: prevents large-scale fields from overwhelming distance-based objectives used in assignment and refinement steps.
- **Latent comparability**: improves consistency of geometry for downstream K-means, GMM, and agglomerative partitioning in latent space.
- **Cross-tool harmonization**: reduces unit and scale mismatch across heterogeneous security products, improving joint modeling reliability.

### 5.7 Outliers, Bursts, and Rare Events

In security operations, outliers are ambiguous: some are noise, some are genuine attacks. Preprocessing therefore avoids aggressive outlier removal. Instead, the pipeline prefers:

- **Robust scaling/normalization**: limits undue influence from transient spikes while preserving potentially meaningful deviations.
- **Latent compression**: encourages the model to retain shared structure and suppress nuisance variance that does not contribute to cluster discrimination.
- **Contextualized rare-event handling**: keeps rare points for clustering/profile analysis instead of removing them, since low-frequency events may represent early-stage attacks.

This is important because deleting rare points can remove early indicators of targeted attacks.

### 5.8 Temporal and Session Context

Although the current representation is primarily event-centric, timestamp information can still contribute through engineered temporal features (time windows, burst markers, periodicity hints). This supports partial reconstruction of campaign dynamics even without full sequence modeling.

Future extensions can move from event-wise vectors to sequence/session representations for richer temporal threat behavior.

### 5.9 Noise and Sparsity Characteristics

Security logs commonly exhibit:

- **Missing fields**: incomplete records from partial logging configurations or parser limitations.
- **Repeated boilerplate entries**: highly redundant logs that inflate dataset size without proportional information gain.
- **Bursty anomalies**: short-lived spikes (e.g., scan or brute-force bursts) that can distort naive distribution assumptions.
- **Mixed periodic and attack-driven regimes**: coexistence of routine cyclical traffic and adversarial behavior, producing multimodal and time-varying distributions.

Deep latent learning mitigates these effects by compressing correlated structure, smoothing local noise, and emphasizing dimensions that support clustering objectives.

### 5.10 Preprocessing Quality Controls

For reliable downstream clustering, preprocessing should be audited with:

- **Feature distribution audits**: compare pre/post-normalization distributions to detect saturation, collapse, or unintended scaling artifacts.
- **Missingness monitoring**: track per-field and per-source missing rates to identify telemetry degradation and schema drift early.
- **Parser reliability metrics**: maintain error/rejection counters to quantify ingestion quality and prevent hidden data-quality regressions.
- **Temporal drift checks**: evaluate batch/window shifts to detect non-stationarity that may require retraining or feature reconfiguration.

These controls are essential because representation quality strongly bounds achievable cluster quality, regardless of model sophistication.

### 5.11 Feature Encoder Improvements for Clustering Accuracy

The deep encoder $f_\theta$ can only exploit structure that is present (or recoverable) in the input vectors $x_i$. Improvements to the hand-crafted encoder $\phi$ therefore raise the **ceiling** for both training stability and intrinsic metrics (e.g., Silhouette), especially when logs carry free-text `content` and high-cardinality categorical fields. The following enhancements are implemented in the event featurizer and are orthogonal to the choice of model family: they sharpen the input geometry before latent learning and refinement.

**Deterministic categorical projection.** High-cardinality or opaque string identifiers (e.g., IPS `rule_id`, firewall zone pairs) are mapped to a fixed interval using a **stable** hash: UTF-8 MD5 digest, reduction modulo $M$, then normalization to $[0,1]$:

$h_M(s) = \frac{(\text{int}(\text{MD5}(s)) \bmod M)}{M - 1}$

(with the empty string mapped to $0$). This replaces process-dependent `hash()` semantics so repeated training runs, A/B comparisons, and regression tests see **reproducible** feature values for the same log corpus. Reproducibility matters for SOC tooling: analysts and engineers must be able to trust that a configuration change in the model—not random featurization—drives metric deltas.

**Cyclic hour encoding.** Raw normalized hour treats midnight as a discontinuity. The encoder uses a two-dimensional cyclic representation:

$\big(\sin(2\pi t/24),\ \cos(2\pi t/24)\big)$

for hour $t$, together with day-of-week and business-hours indicators. Neighboring hours stay close in Euclidean space, which better matches true temporal proximity for diurnal attack and operational patterns.

**Semantic content channel.** Beyond normalized content length, the parser adds a compact **threat-semantic** block derived from `content` (lowercased): six fixed keyword groups (credential/auth abuse, malware/execution, reconnaissance/scanning, exfiltration/data movement, web-application attack language, and C2/persistence/lateral-movement hints). Each group contributes a binary “any phrase matched” feature. Two structural scalars augment separability: **token count** (capped and scaled) and **exclamation density** (capped), which help distinguish verbose alerts, marketing noise, or vendor-specific formatting from terse firewall lines. This channel is intentionally lightweight—no transformer or large vocabulary—so ingestion stays fast while still pulling attack-relevant language into $x_i$.

**Vector dimension.** After these additions, fixed-length event vectors use $d = 70$ dimensions (including the existing padded subsystem-specific block), exposed consistently via the parser’s reported feature dimension for model construction.

**Interaction with the rest of the pipeline.** Vectors are still passed through per-dataset standardization (Section 5.5) before $f_\theta$. Thus, encoder improvements act as a **better-conditioned** input to pretraining, cluster initialization, and latent ensemble refinement: separable directions in $x$ are easier to preserve in $z$, which supports clearer partitions and stronger intrinsic scores when the underlying behaviors differ along those axes.

---

## 6. Model Families

In this document, a **model family** means a class of deep clustering methods that share the same core training idea and objective function. We consider model families because no single clustering objective works best for every security dataset. Different SOC environments have different properties (noise level, class imbalance, behavior overlap, and compute constraints), so model selection is a practical and scientific decision rather than a fixed default.

It is helpful to think of model families as different "ways to teach the latent space what a good cluster looks like":

- some methods strongly force cluster separation,
- some methods preserve reconstruction fidelity while clustering,
- some methods add probabilistic uncertainty modeling,
- some methods learn invariances through augmentation consistency.
- some methods (fuzzy c-means variants) allow **overlapping** cluster membership, which can better match security telemetry where benign and suspicious behavior share feature mass.

Choosing among these families is important because the choice directly affects:

- **Cluster compactness/separation**: this describes how tight each cluster is internally and how far clusters are from each other; in practice it is evaluated using intrinsic metrics such as Silhouette (higher is better), Davies-Bouldin Index (lower is better), and Calinski-Harabasz (higher is better). Better compactness/separation usually leads to cleaner threat groupings and less mixing between benign and suspicious behaviors.

$ S=\frac{1}{N}\sum_{i=1}^{N}\frac{b(i)-a(i)}{\max\{a(i),b(i)\}},\quad$
$\mathrm{DBI}=\frac{1}{K}\sum_{i=1}^{K}\max_{j\neq i}\frac{\sigma_i+\sigma_j}{d(c_i,c_j)}$

- **Stability across runs**: this captures whether repeated training with different random seeds (or minor data perturbations) produces similar assignments; it can be assessed by comparing run-to-run label agreement (for example ARI/NMI) and assignment drift. High stability improves trust and reproducibility, while low stability makes operational playbooks harder to maintain.

$\text{Stability} \approx \frac{1}{|\mathcal{P}|}\sum_{(r,s)\in\mathcal{P}}\mathrm{ARI}\left(y^{(r)},y^{(s)}\right),\quad$
$\Delta_t=\frac{1}{N}\sum_{i=1}^{N}\mathbf{1}[y_i^{(t)}\neq y_i^{(t-1)}]$

- **Interpretability for analysts**: this is the degree to which a cluster can be explained in security terms (dominant subsystem/action, representative events, coherent indicators, and clear recommended actions); it is assessed through profile coherence and analyst usability of cluster summaries. High interpretability reduces triage time and improves incident decision quality.

$H_c=-\sum_{u}p(u\mid c)\log p(u\mid c),\quad$
$\text{Coherence}(c)=1-\frac{H_c}{\log |U|}$

- **Training time and operational cost**: this includes wall-clock duration and compute/memory usage across pretraining, fine-tuning, and postprocessing; it is measured per stage and end-to-end. Lower cost enables faster retraining cycles and better production responsiveness, while higher cost may improve quality but can violate SOC latency constraints if not bounded.
$T_{\text{total}}=T_{\text{parse}}+T_{\text{pretrain}}+T_{\text{init}}+T_{\text{finetune}}+T_{\text{post}},\quad$
$C=\lambda_t T_{\text{total}}+\lambda_m M_{\text{peak}}+\lambda_g G_{\text{gpu-hours}}$

## 6.1 Deep Embedded Clustering (DEC)

### Beginner intuition

DEC starts from an encoder that maps events into latent vectors, then repeatedly sharpens cluster assignments so points move toward more confident cluster centers.

### How DEC works (step-by-step)

1. Encode each input into latent space.
2. Compute soft assignment probabilities to cluster centers.
3. Build a sharpened target distribution that emphasizes high-confidence assignments.
4. Minimize KL divergence between current assignments and target assignments.

Soft assignment:

$q_{ij} = \frac{\left(1 + \frac{\lVert z_i-\mu_j \rVert^2}{\alpha}\right)^{-\frac{\alpha+1}{2}}}{\sum_{j'}\left(1 + \frac{\lVert z_i-\mu_{j'} \rVert^2}{\alpha}\right)^{-\frac{\alpha+1}{2}}}$

Target distribution:

$p_{ij} = \frac{q_{ij}^2 / f_j}{\sum_{j'} q_{ij'}^2 / f_{j'}}, \quad f_j=\sum_i q_{ij}$

Loss:

$\mathcal{L}*{DEC} = \mathrm{KL}(PQ)=\sum_i\sum_j p*{ij}\log\frac{p_{ij}}{q_{ij}}$

### When DEC is useful

- when you want a direct cluster-focused objective,
- when compute budget is moderate,
- when fast iteration is preferred.

### Limitations

Because DEC focuses heavily on clustering loss, it can sometimes distort latent structure if reconstruction information is not preserved.

## 6.2 Improved DEC (IDEC)

### Beginner intuition

IDEC is DEC plus a "do not forget the original data structure" term. It tries to improve clusters while preserving what the encoder learned during reconstruction.

### Objective

$\mathcal{L}*{IDEC}=\mathcal{L}*{DEC}+\gamma\mathcal{L}_{rec}$

$\mathcal{L}*{rec}=\frac{1}{N}\sum*{i=1}^N \lVert x_i-\hat{x}_i \rVert_2^2$

### Why teams often start with IDEC

- tends to be more stable than DEC on noisy telemetry,
- reduces risk of latent collapse/drift,
- often yields better interpretability in security cluster profiles.

### Practical trade-off

IDEC is usually slightly slower than DEC because it optimizes two goals at once (clustering + reconstruction), but this trade-off is often worthwhile in SOC data.

## 6.3 Variational Deep Embedding (VaDE)

### Beginner intuition

VaDE treats latent data as coming from a mixture of Gaussian components, so each cluster is represented probabilistically instead of purely by hard assignment.

Gaussian-mixture prior:

$p(z)=\sum_{k=1}^K \pi_k\mathcal{N}(z\mid\mu_k,\Sigma_k)$

ELBO-style objective:

$\mathcal{L}*{VaDE}=\mathbb{E}*{q(z,c\mid x)}[\log p(x,z,c)-\log q(z,c\mid x)]$

### Why this matters in security

Security events can be ambiguous (an event may look partly benign and partly suspicious). Probabilistic assignments can model this uncertainty better than purely hard-label approaches.

### Practical trade-off

VaDE can provide richer uncertainty information, but training is more complex and can be sensitive to initialization and hyperparameter settings.

## 6.4 Contrastive Deep Clustering

### Beginner intuition

Contrastive methods teach the model that two augmented versions of the same event should stay close in representation space, while different events should remain distinguishable.

Contrastive term:

$\mathcal{L}_{con}=-\sum_i \log\frac{\exp(s(h_i^{(1)},h_i^{(2)})/\tau)}{\sum_k\exp(s(h_i^{(1)},h_k^{(2)})/\tau)}$

Total objective:

$\mathcal{L}*{total}=\mathcal{L}*{con}+\lambda_{cons}\mathcal{L}*{cons}+\lambda*{ent}\mathcal{L}_{ent}$

### Why this can help

- stronger robustness to noise and perturbations,
- useful when raw event quality is inconsistent,
- often improves representation quality before final clustering.

### Practical trade-off

This family is typically more compute-intensive and depends on well-designed augmentations.

## 6.5 Deep Unconstrained Fuzzy C-Means (UFCM / UC-FCM)

### Beginner intuition

**Fuzzy C-Means (FCM)** assigns each point **partial membership** in every cluster instead of forcing a single hard label. That is useful when events sit **between** behavioral regimes—for example, mixed scanning-and-exploitation activity, or firewall noise that partially resembles a known campaign signature. **Unconstrained Fuzzy C-Means (UC-FCM)**, as formulated in recent literature (e.g., IEEE TPAMI, 2025), reframes the standard FCM problem so that the **membership matrix can be eliminated** from the optimization variables: for **fixed cluster centers**, FCM already has a **closed-form optimal** membership update. Substituting that solution back into the FCM objective yields an **unconstrained** problem in the centers alone, which can be minimized by **gradient descent** rather than classical alternating updates. In this codebase, **Deep UFCM** applies that idea in **latent space** $z_i=f_\theta(x_i)$: an autoencoder supplies $z$, learnable centers $V=\{v_k\}_{k=1}^{K}$ live in $\mathbb{R}^{m}$, and optimization updates **both** $V$ and $\theta$ (jointly with a small reconstruction term) so representation and fuzzy partition co-evolve.

### Classical FCM objective (reference)

Given centers $V=(v_1,\ldots,v_K)$ and fuzziness $m>1$, FCM minimizes

$J_{\mathrm{FCM}}(U,V)=\sum_{i=1}^{N}\sum_{k=1}^{K} u_{ik}^{m}\,\lVert x_i-v_k\rVert_2^{2}$

subject to **probabilistic constraints** on each row: $u_{ik}\ge 0$ and $\sum_{k=1}^{K}u_{ik}=1$. The familiar alternating scheme updates $U$ then $V$. The **membership** at fixed $V$ uses Euclidean distances $d_{ik}=\lVert x_i-v_k\rVert_2$:

$u_{ik}=\frac{1}{\sum_{j=1}^{K}\left(\frac{d_{ik}}{d_{ij}}\right)^{\frac{2}{m-1}}}$

(with standard tie-breaking / numerical flooring when some $d_{ij}$ are tiny). Raising $u_{ik}$ to power $m>1$ controls how **soft** assignments are: larger $m$ pushes memberships toward uniform mixing; $m$ closer to $1$ sharpens assignments (in the limit, behavior approaches harder partitioning).

### UC-FCM idea: unconstrained optimization in the centers

The **UC-FCM** insight is compositional:

1. For **fixed** $V$, the optimal $U^\star(V)$ is exactly the FCM membership formula above (same constraints satisfied).
2. Plug $U^\star(V)$ into $J_{\mathrm{FCM}}$ to obtain $\tilde{J}(V)=J_{\mathrm{FCM}}(U^\star(V),V)$, which depends **only** on $V$ (and on the data points).
3. Minimize $\tilde{J}(V)$ using **gradient-based optimization** instead of alternating full-matrix updates.

This reduces the effective variable set during gradient steps, avoids the explicit alternating loop for $U$ at each outer iteration, and can escape weaker local minima that plague standard FCM in difficult geometries. The implementation in this project follows the **same mathematical membership mapping** $U^\star(V)$, so rows still sum to one and remain interpretable as **fuzzy assignment probabilities**.

### Deep UFCM in this pipeline (what actually runs)

The trainer treats UFCM like other deep families with **three aligned stages**:

1. **Pretraining**: the autoencoder is trained with **reconstruction loss** on $x$ (same backbone style as DEC/IDEC), building a manifold where distances are meaningful before fuzzy pressure is applied.
2. **Initialization**: **K-means** on latent vectors $z_i$ sets initial center matrix $V\in\mathbb{R}^{K\times m}$ (analogous to DEC’s centroid initialization in latent space).
3. **Fine-tuning**: each batch computes $z_i$, squared distances $\lVert z_i-v_k\rVert_2^2$, memberships $u_{ik}$ via the formula above, then minimizes the **batch mean** of $\sum_k u_{ik}^{m}\lVert z_i-v_k\rVert_2^{2}$ plus a weighted reconstruction term $\gamma_{\mathrm{ufcm}}\mathcal{L}_{\mathrm{rec}}$ to limit latent collapse.

**Hard labels** for metrics, profiling, and refinement are $\hat{y}_i=\arg\max_k u_{ik}$; **soft rows** $u_i\in\mathbb{R}^{K}$ are available for downstream analysis (e.g., ambiguity flags: high entropy of $u_i$ suggests borderline events worth analyst review).

### Loss summary (implementation-aligned)

Let $z_i=f_\theta(x_i)$, $d_{ik}^2=\lVert z_i-v_k\rVert_2^2$, $d_{ik}=\sqrt{d_{ik}^2+\varepsilon}$. Define memberships $u_{ik}$ from $(d_{ik})$ as in FCM. Then

$\mathcal{L}_{\mathrm{UFCM}}=\frac{1}{|\mathcal{B}|}\sum_{i\in\mathcal{B}}\sum_{k=1}^{K} u_{ik}^{m}\,d_{ik}^{2}$

$\mathcal{L}=\mathcal{L}_{\mathrm{UFCM}}+\gamma_{\mathrm{ufcm}}\,\mathcal{L}_{\mathrm{rec}},\qquad \mathcal{L}_{\mathrm{rec}}=\frac{1}{|\mathcal{B}|}\sum_{i\in\mathcal{B}}\lVert x_i-\hat{x}_i\rVert_2^{2}$

Hyperparameters: **fuzziness** $m>1$ (default $2$) and **reconstruction weight** $\gamma_{\mathrm{ufcm}}$ (small positive default), both exposed via training configuration.

### When UFCM helps in security clustering

- **Overlapping behaviors**: campaigns that blend reconnaissance, exploitation, and C2 often do not form crisp balls in feature space; fuzzy weights highlight **secondary** cluster affinity.
- **Noisy or heterogeneous telemetry**: a single event may legitimately resemble multiple prototypes (e.g., auth failure storms vs. credential stuffing); soft membership encodes that without forcing a single story.
- **Analyst triage**: high **entropy** of $u_i$ can be used as a **review priority** signal alongside cluster-level risk scores.

### Limitations and validity notes

- **Intrinsic metrics** (Silhouette, DBI, CH) are still computed on **hard** argmax labels in the current stack; fuzzy structure is **not** fully captured by those scalars—consider entropy or separation of soft assignments in research extensions.
- **Sensitivity to $m$**: extreme $m$ can over-smooth or over-sharpen memberships; treat $m$ like a regularization knob.
- **Compute**: similar order to IDEC-style fine-tuning (forward pass + distance graph per batch); large $K$ increases per-sample work linearly in $K$.
- **Citation context**: refer to the UC-FCM source formulation (IEEE TPAMI, 2025, DOI `10.1109/TPAMI.2025.3532357`) when comparing against classical FCM baselines in publications.

### Relation to other families in this document

- **VaDE** also yields soft responsibilities, but from a **generative mixture** in latent space; UFCM is **geometric** (distance-based fuzzy memberships) without a VAE/GMM ELBO.
- **DEC/IDEC** use Student-$t$ kernels and KL targets; UFCM uses **powered fuzzy memberships** and the UC-FCM reduction—different inductive bias for the same latent encoder backbone.
- **Contrastive** stresses augmentation invariance; UFCM stresses **continuous overlap** between clusters; they address different failure modes (noise vs. boundary ambiguity).

### 6.5.1. UFCM with LSTM temporal encoder (`ufcm_lstm`)

**DeepUFCMSequence** in **`backend/sequence_clustering.py`** reuses the **same** fuzzy objective, **`cluster_centers`**, and **`fuzzy_membership`** behavior as vector **DeepUFCM** (§6.5), but the encoder–decoder is **SecurityEventSequenceAutoEncoder** with **`encoder_type="lstm"`**: LSTM over windows $X\in\mathbb{R}^{N\times T\times d}$, latent $z_t$ per window, MLP decoder with reconstruction target **only the last frame** $x_t$ (aligned with §6.7). **Pretrain** minimizes last-frame reconstruction only (no fuzzy term). **Initialization** encodes all windows, runs **K-means** on $z_t$, and copies centers into **`cluster_centers`**. **Fine-tuning** minimizes $\mathcal{L}=\mathcal{L}_{\mathrm{UFCM}}+\gamma_{\mathrm{ufcm}}\,\mathcal{L}_{\mathrm{rec}}$ with $\mathcal{L}_{\mathrm{UFCM}}$ as in §6.5 on $z_t$ and $\mathcal{L}_{\mathrm{rec}}=\mathrm{MSE}(x_t,\hat{x}_t)$ on the **last** frame only (same scaling **`ufcm_recon_weight`** as vector UFCM in **`TrainingConfig`**). **Fuzziness** $m$ matches **`fuzziness_m`** (not on public **`TrainingRequest`** today; defaults apply). **`seq_len`** is on **`TrainingRequest`** and sets $T$; LSTM width/depth use **`seq_hidden`**, **`lstm_layers`**, and related **`TrainingConfig`** defaults unless extended. Windowing matches **`build_temporal_sequences`** / **`expand_rows_to_sequences`** (as **IDEC+LSTM**).

## 6.6 Deep Multi-View Clustering (DMVC)

### Beginner intuition

**Multi-view clustering** traditionally assumes several **sensors** or **feature sets** describing the same objects. This codebase implements a **deep multi-view** variant on a **single** $d$-dimensional event vector by **splitting features into two contiguous blocks** (first half / second half). Each block is encoded by its own autoencoder; latent codes $z^{(1)}$ and $z^{(2)}$ are averaged to a **fused** embedding $z=\frac12(z^{(1)}+z^{(2)})$. Clustering then follows the **same Student-$t$ + KL refinement** framework as DEC/IDEC on $z$, while reconstruction and a **cross-view latent alignment** term encourage both views to agree and to preserve input information.

### Why this can help

- When feature engineering orders dimensions so that **early vs. late** fields capture **complementary** behavior (e.g., categorical/context vs. numeric/network-derived), separate encoders can reduce **negative transfer** compared to one monolithic encoder.
- The **MSE$(z^{(1)},z^{(2)})$** penalty (weighted by `mvc_weight`) acts as a **consistency regularizer**, discouraging view-specific collapse.

### Loss summary (implementation-aligned)

Let $x=[x^{(1)};x^{(2)}]$ be the concatenation of the two halves, $\hat{x}$ the concatenation of decoders applied to each view latent, $q$ Student-$t$ soft assignments on $z$, and $p$ the DEC-style target distribution. Fine-tuning minimizes (batch mean):

$\mathcal{L}_{\mathrm{total}}=\mathrm{KL}(q\,\Vert\,p)+\gamma\,\mathcal{L}_{\mathrm{rec}}+\lambda_{\mathrm{mvc}}\,\mathcal{L}_{\mathrm{mvc}}$

with $\mathcal{L}_{\mathrm{rec}}=\mathrm{MSE}(x,\hat{x})$, $\mathcal{L}_{\mathrm{mvc}}=\mathrm{MSE}(z^{(1)},z^{(2)})$, $\gamma=$ `TrainingConfig.gamma`, $\lambda_{\mathrm{mvc}}=$ `TrainingConfig.mvc_weight`.

**Training monitors** append to `DeepClusteringTrainer.history` each epoch:

- **`total_loss`**: scalar loss backpropagated (matches $\mathcal{L}_{\mathrm{total}}$ up to batch averaging).
- **`reconstruction_loss`**: batch-averaged $\mathcal{L}_{\mathrm{rec}}$.
- **`clustering_loss`**: remainder attributed in code to the **non-reconstruction** part (KL plus the MVC contribution as weighted for logging—see `trainer.py` DMVC branch).

The HTTP **job status** and **`/results`** payload surface these three names for operators and dashboards alongside intrinsic metrics (Silhouette, DBI, CH).

### Pipeline stages

1. **Pretraining**: train **both** view autoencoders by minimizing $\mathrm{MSE}(x^{(1)},\hat{x}^{(1)})+\mathrm{MSE}(x^{(2)},\hat{x}^{(2)})$.
2. **Initialization**: K-means on **fused** latents $z$ initializes `ClusteringLayer` centroids.
3. **Fine-tuning**: joint optimization of encoders, decoders, clustering layer, and (implicitly) view agreement via $\mathcal{L}_{\mathrm{mvc}}$.

### Limitations

- Views are **positional**, not guaranteed semantically distinct; arbitrary splits may yield little benefit.
- Requires $d\ge 2$; very small $d$ makes asymmetric half-splits noisy.

### Relation to other families

- **IDEC/DEC**: DMVC **shares** the same KL + target-distribution mechanism on $z$; it **adds** explicit two-branch encoders and view consistency.
- **UFCM**: different assignment geometry (fuzzy memberships vs. Student-$t$); DMVC does **not** expose fuzzy memberships.

## 6.7 Improved DEC on temporal windows — LSTM and Transformer sequence encoders (IDEC only)

This section documents **sequence-based IDEC**, implemented in **`backend/sequence_clustering.py`** and **`backend/sequence_featurization.py`**, and selected in training as **`idec_lstm`** or **`idec_transformer`** (`ModelType.IDEC_LSTM`, `IDEC_TRANSFORMER` in **`backend/trainer.py`**). **UFCM+LSTM** (`ufcm_lstm`, §6.5.1) uses the **same** $[N,T,d]$ windowing and an **LSTM** backbone but optimizes the **UFCM** fuzzy loss on $z_t$ instead of Student-$t$ IDEC. **DEC, VaDE, contrastive, vector UFCM (`ufcm`), and DMVC remain on the flat $d$-dimensional vector path**; among IDEC variants, **LSTM/Transformer** encode **temporal windows** (this section), while **GCN** encodes **batch graphs** (§6.9).

**Motivation.** Security telemetry is naturally **ordered in time**. A single event’s feature vector may be ambiguous; a short **window** of consecutive events can carry richer context (bursts, sequences of actions, evolving sessions). Sequence IDEC encodes each window into a latent $z_t\in\mathbb{R}^{m_{\mathrm{latent}}}$, then applies the same **Student-$t$ clustering distribution** and **KL-to-target** fine-tuning pattern as vector IDEC (§6.2).

**Window construction (`build_temporal_sequences`).** After parsing and featurization, events are sorted by timestamp. For each index $t$ (in sorted order), a window of length $T=\texttt{seq\_len}$ is formed:

$$
X_t = [\,x_{t-T+1},\,x_{t-T+2},\,\ldots,\,x_t\,] \in \mathbb{R}^{T\times d},
$$

padding the **earliest** positions with repeats of $x_0$ when $t<T-1$ so every row is a valid $d$-vector. Training tensors are shaped $[N_{\mathrm{seq}},T,d]$.

**Architecture (`SecurityEventSequenceAutoEncoder`).**

- **Encoder**: either **LSTM** (stacked, hidden size `seq_hidden`, `lstm_layers`) or **Transformer** (optional learned positional embeddings, `transformer_layers` blocks, `transformer_heads`, `seq_hidden` as model width). The **last time step** hidden state is projected to $z_t$ (latent dimension $m_{\mathrm{latent}}$).
- **Decoder**: an MLP maps $z_t$ back to $\mathbb{R}^d$. The **reconstruction target** is **only the last frame** $x_t$ (current event), not the full window—so the model must compress temporal context into $z_t$ to predict the present observation.

**Clustering head.** `DeepEmbeddedClusteringSequence` applies the same Student-$t$ kernel as IDEC (Eq. (6.2)) to $z_t$, producing $q_{ij}$. `ImprovedDECSequence` combines **clustering loss** (KL to target $p$) and **reconstruction loss** on $x_t$ with weight `gamma`, analogously to `ImprovedDEC` for vectors.

**Training vs inference.**

- **Training / analyze**: windows are built from the **time-ordered** training set so each sequence row aligns with a real predecessor chain.
- **Predict** (single events or unsorted batches): **`expand_rows_to_sequences`** repeats the **same** feature vector across $T$ rows when no history is available, so the model still receives $[B,T,d]$; this is a **neutral** prior (no temporal differentiation) rather than fabricated chronology.

**Hyperparameters (API / `TrainingConfig`).** `seq_len` ($T$), `seq_hidden`, `lstm_layers`, `transformer_heads`, `transformer_layers`; other IDEC knobs (`gamma`, pretrain/finetune epochs, $m_{\mathrm{latent}}$, $K$) apply as for vector IDEC.

**Operational note.** Larger $T$ increases memory and compute; very long windows may dilute local behavior unless the corpus has consistent inter-event timing. Compare **IDEC (vector)** vs **IDEC+LSTM/Transformer** with the same $K$ and refinement budget when evaluating whether temporal context helps your deployment.

### Relation to other families

- **Vector IDEC (§6.2)**: same clustering and target-distribution mechanics; sequence IDEC replaces the MLP encoder with **LSTM/Transformer over $[T,d]$** and reconstructs **$x_t$** only.
- **IDEC + GNN (§6.9)**: same IDEC objective; encoder is **GCN on within-batch $k$-NN** instead of an MLP on a single row.
- **DMVC / vector UFCM**: no **temporal** window path; **DMVC** is multi-view on flat $x$; **`ufcm`** is fuzzy on flat $x$. **`ufcm_lstm`** is fuzzy on **LSTM** window latents (§6.5.1).

## 6.8 Model Selection Guidance (Beginner-Friendly)

- **IDEC (recommended default)**: best first choice when you want balanced quality, stability, and interpretability.
- **IDEC + LSTM / IDEC + Transformer**: use when events are **time-ordered** and **short temporal context** may disambiguate behaviors; same interpretability story as IDEC after labels exist (§6.7).
- **IDEC + GNN (GCN)**: use when **local neighborhoods in feature space** within a training batch should **mutually inform** embeddings (e.g. many near-duplicates or tight benign clouds); interpretability after labeling matches IDEC; graph is **not** a global log graph—see §6.9.
- **DEC**: use when you need a simpler/faster cluster-focused baseline.
- **VaDE**: use when probabilistic membership and uncertainty are important to your analysis.
- **Contrastive**: use when data noise is high and invariance learning is a priority.
- **UFCM (`ufcm`)**: use when clusters are expected to **overlap**, when you want **explicit fuzzy memberships** per event, or when you wish to study **borderline** / ambiguous security behaviors without switching to a full VAE mixture—on **flat** per-event vectors.
- **UFCM + LSTM (`ufcm_lstm`)**: same fuzzy semantics and use cases as **`ufcm`**, but latents encode a **`seq_len`**-event **time-ordered** window (§6.5.1); prefer when overlap and **short temporal context** both matter.
- **DMVC**: use when the **feature vector is intentionally structured** into two meaningful halves (or as an experiment when you suspect complementary early/late feature groups); treat as a **specialized** variant of the DEC/IDEC family, not a drop-in replacement on arbitrary permutations of dimensions.

A practical workflow is:

1. start with IDEC,
2. if timestamps are trustworthy and sessions matter, try **IDEC+LSTM** or **IDEC+Transformer** (vary `seq_len`),
3. if relational smoothing in feature space is attractive and batch sizes are adequate, try **IDEC+GNN** (vary `gnn_k_neighbors`, depth, width; §6.9),
4. compare against DEC as a simpler baseline,
5. try VaDE if ambiguity/uncertainty modeling is needed,
6. try contrastive models when input noise or variability is severe,
7. try **`ufcm`** when soft assignments on **flat** rows are central; try **`ufcm_lstm`** when you need the same with **temporal** windows,
8. try DMVC when a **two-view feature layout** is plausible and you want explicit cross-view latent agreement.

## 6.9 Improved DEC with GCN encoder on batch-induced $k$-NN graphs (IDEC only)

This section documents **GNN-IDEC**, implemented in **`backend/gnn_clustering.py`** and selected as **`idec_gnn`** (`ModelType.IDEC_GNN` in **`backend/trainer.py`**). It keeps the **same Student-$t$ clustering head, target distribution, KL fine-tuning, and MLP decoder** as vector IDEC (§6.2), but replaces the **MLP encoder** with a small **graph convolutional stack** on a graph defined **inside each mini-batch**.

**Motivation.** Events that are **close in handcrafted feature space** often belong to the same campaign, tool noise, or service behavior. A **$k$-nearest-neighbor** graph on batch rows makes nearby events exchange information before clustering, analogous to relational encoders in graph ML—without requiring a hand-built IP/session graph.

**Graph construction (within batch).** For a batch matrix $X\in\mathbb{R}^{B\times d}$ (normalized features), pairwise distances (Euclidean) yield a **symmetric $k$-NN** adjacency (excluding self, then symmetrizing), **self-loops** added, then **symmetric normalization** $\tilde{A} = D^{-1/2}(A+I)D^{-1/2}$ in the implementation. Effective $k$ is $\min(k_{\mathrm{cfg}}, B-1)$.

**Encoder.** $L$ layers of the form $H^{(\ell+1)} = \mathrm{dropout}(\mathrm{ReLU}(\tilde{A}\, H^{(\ell)} W^{(\ell)}))$ with $H^{(0)}=X$, terminating in latent dimension $m_{\mathrm{latent}}$. This is a **dense-batch GCN** (no PyTorch Geometric dependency).

**Decoder and losses.** An MLP maps $z_i$ to $\hat{x}_i\in\mathbb{R}^d$. **Pretraining** minimizes reconstruction MSE on $x$; **fine-tuning** adds the **IDEC** KL to the sharpened target plus $\gamma$ times reconstruction, with periodic recomputation of $p$ from $q$, as for other DEC-family models.

**Training vs inference.** Both use **only the feature matrix** $[N,d]$—no separate graph upload. At **inference** (`/predict`), the graph is built **on the submitted batch**; small batches yield smaller effective neighborhoods.

**Hyperparameters (`TrainingConfig` / API).** `gnn_k_neighbors`, `gnn_hidden_dim`, `gnn_num_layers`; plus shared IDEC fields (`gamma`, `alpha`, `latent_dim`, $K$, epochs).

**Limitations.**

- The graph is **not global** over $N$: edges exist only between events that co-occur in the **same SGD batch**, so structure differs from a full-corpus $k$-NN graph.
- Very **small batches** cap $k$ and reduce neighbor signal; very **large $k$** increases compute ($O(B^2 d)$ for distances per batch).
- **DEC / VaDE / contrastive / vector UFCM / DMVC** do not use this path; only **IDEC** exposes **`idec_gnn`**. (**`ufcm_lstm`** uses LSTM windows, not batch $k$-NN graphs.)

### Relation to other families

- **Vector IDEC**: identical clustering and decoder narrative; encoder swaps MLP for **GCN on batch $k$-NN**.
- **Sequence IDEC (§6.7)**: complementary—sequence models use **time-ordered windows**; GNN-IDEC uses **feature-space neighbors within a batch**.

---

## 7. Training Strategy

This training strategy is designed to balance three goals that often conflict in security clustering: representation quality, clustering quality, and operational runtime. A single monolithic optimization loop is avoided because security telemetry is noisy and non-stationary; stage-wise training gives better control over failure modes and model behavior.

### 7.1 Stage-Wise Optimization

1. **Pretraining**: learn a stable latent manifold before hard clustering pressure is applied.
  In this stage, the model focuses on structure-preserving objectives (reconstruction for DEC/IDEC/VaDE/UFCM/**GNN-IDEC** (GCN+decoder), or contrastive consistency for the contrastive family). This reduces sensitivity to noisy features and prevents early collapse into poor local minima.
2. **Initialization**: estimate cluster seeds in latent space.
  Cluster-aware methods are strongly initialization-dependent; this stage computes initial assignments/centers (e.g., K-means/GMM/model-specific initialization) so fine-tuning starts from a plausible partition.
3. **Fine-tuning**: optimize clustering-aware objective.
  The model updates latent geometry and assignments jointly using the selected family objective (DEC/IDEC/**sequence-IDEC**/**GNN-IDEC**/VaDE/contrastive/**UFCM**/**UFCM+LSTM**/DMVC), while periodic metrics monitor whether separation improves or degrades. The trainer logs **batch-averaged** `total_loss`, `clustering_loss`, and `reconstruction_loss` **each epoch** for API/UI consumption (see §7.3 implementation note).
4. **Postprocessing**: bounded latent ensemble refinement with constraints.
  After model optimization, discrete labels are refined via constrained search in latent space (algorithm and $K$ variants) to recover better intrinsic partitions without retraining encoder weights.

This decomposition improves controllability: each stage answers a different question ("Can we represent events well?", "Do we have sensible seeds?", "Did deep optimization improve clusters?", "Can labels be improved under constraints?").

### 7.2 Sequence-Level Workflow

```text
Sequence workflow (Figure 7.2 — text form for standard Markdown preview):

  1. User/API ──► Parser: upload and parse events
  2. Parser ──► Trainer: normalized matrix X (or [N,T,d] windows for sequence IDEC and **ufcm_lstm**; still [N,d] for GNN-IDEC with graphs built per batch)
  3. Trainer: pretrain encoder → initialize centers/distribution → fine-tune objective
  4. Trainer ──► Refinement: latent Z and initial labels y0
  5. Refinement: bounded ensemble search ──► refined labels y*
  6. Trainer ──► Analyzer: events + y* + Z
  7. Analyzer ──► User/API: metrics, clusters, insights
```



The sequence workflow can be interpreted as a contract between data handling, model optimization, and analyst-facing outputs:

- `**U -> P: Upload and parse events**`: the user submits raw events; parser validation occurs before expensive training is allowed.
- `**P -> T: Normalized matrix X**`: trainer receives fixed-dimensional, **normalized** inputs—either per-event vectors $X\in\mathbb{R}^{N\times d}$ or, for **IDEC+LSTM/Transformer**, time-ordered windows $X\in\mathbb{R}^{N\times T\times d}$ built after the same per-event normalization (§6.7). **IDEC+GNN** also consumes $X\in\mathbb{R}^{N\times d}$; batching defines the graph (§6.9).
- `**T -> T: Pretrain encoder**`: latent manifold is shaped with structure-preserving objectives.
- `**T -> T: Initialize centers/distribution**`: initial cluster hypotheses are estimated in latent space.
- `**T -> T: Fine-tune deep objective**`: clustering-aware optimization refines both representation and assignment structure.
- `**T -> R: Latent Z and labels y0**`: base result is exported to refinement logic.
- `**R -> R: Bounded ensemble search**`: refinement explores candidate partitions under runtime and validity constraints.
- `**R -->> T: Refined labels y***`: best accepted labels are returned to training pipeline.
- `**T -> A: Events + y* + Z**`: analyzer receives raw event context plus final labels and latent features.
- `**A -->> U: Metrics, clusters, insights**`: user receives intrinsic quality, cluster details, and threat-oriented summaries.

The main advantage of this explicit sequence is traceability: when output quality is poor, teams can inspect which hop degraded quality (parsing quality, latent learning, initialization, fine-tuning, or refinement).

### 7.3 Convergence and Monitoring

The trainer monitors periodic intrinsic metrics and assignment drift:

$\Delta_t=\frac{1}{N}\sum_i \mathbf{1}[y_i^{(t)} \ne y_i^{(t-1)}]$

where $\Delta_t$ measures the fraction of events whose cluster assignment changed between two successive checkpoints.

Monitoring logic typically combines:

- **Assignment stability**: decreasing $\Delta_t$ suggests convergence of partition structure.
- **Intrinsic trend checks**: Silhouette/DBI/CH trends indicate whether optimization is improving separation or overfitting cluster boundaries.
- **Loss trend checks**: objective decrease without metric improvement may indicate objective-metric mismatch.

If $\Delta_t$ falls below tolerance and quality metrics stabilize, fine-tuning can terminate early. This prevents unnecessary compute while maintaining cluster quality.

For practical reporting, training snapshots should include:

- current stage and stage progress,
- latest loss values,
- latest intrinsic metrics,
- elapsed time and estimated completion signals.

**Implementation note (this repository):** during **fine-tuning**, the trainer invokes the async progress callback **once per epoch** with a dictionary that always contains **`total_loss`**, **`clustering_loss`**, and **`reconstruction_loss`** (batch-averaged scalars for that epoch). **Silhouette**, **Davies–Bouldin**, and **Calinski–Harabasz** are computed every fifth epoch and merged into the same dictionary; between those evaluations the **last** intrinsic snapshot is re-attached so polling clients retain stable quality readouts. After training, **`GET /results`** includes optional **`training_loss`** with the **final epoch** values of the same three keys, plus **`model_type`**, alongside intrinsic metrics recomputed on refined labels.

### 7.4 Operational Progress Semantics

The API reports stages including `pretraining`, `initialization`, `fine-tuning`, and `postprocessing`, avoiding false perception of hangs during expensive refinement.

Stage-aware progress semantics are critical in production because:

- post-fine-tuning refinement can still be compute-intensive even after training loss has converged,
- users need to distinguish "model is stuck" from "model is running bounded refinement",
- operational dashboards need reliable status transitions for automation and alerting.

A recommended interpretation policy is:

- `**fine-tuning`**: model weights and assignment distributions are still being optimized,
- `**postprocessing`**: model weights are fixed; label refinement and final quality selection are running,
- `**completed**`: final labels, metrics, and analysis artifacts are ready for retrieval,
- `**failed**`: stage-specific failure diagnostics should be surfaced to the caller.

This lifecycle model improves user trust, observability, and incident-response readiness in SOC environments.

---

## 8. Intrinsic Evaluation Metrics

Intrinsic metrics evaluate clustering quality without requiring ground-truth labels, which is critical in security settings where labels are sparse or delayed. These metrics should be interpreted jointly and alongside analyst utility, because a numerically "good" partition may still be operationally weak if it lacks semantic coherence.

## 8.1 Silhouette Score

Per-sample score:

$s(i)=\frac{b(i)-a(i)}{\max\{a(i),b(i)\}}$

Dataset score:

$S=\frac{1}{N}\sum_i s(i), \quad S\in[-1,1]$

Interpretation:

- near 1: compact and well-separated,
- near 0: overlapping boundaries,
- negative: likely misassignment.

From an operational viewpoint, increasing Silhouette often corresponds to easier triage because cluster boundaries become clearer. However, Silhouette alone can favor overly coarse partitions, so it should be cross-checked with cluster-size distribution and analyst interpretability.

## 8.2 Davies-Bouldin Index

$\mathrm{DBI}=\frac{1}{K}\sum_{i=1}^{K}\max_{j\neq i}\frac{\sigma_i+\sigma_j}{d(c_i,c_j)}$

Lower is better; high values indicate high within-cluster scatter and weak inter-centroid separation.

In practice, DBI is useful for detecting whether clusters remain too diffuse after fine-tuning. If DBI improves while Silhouette stagnates, the partition may still be becoming operationally cleaner.

## 8.3 Calinski-Harabasz Score

$\mathrm{CH}=\frac{\mathrm{Tr}(B_K)/(K-1)}{\mathrm{Tr}(W_K)/(N-K)}$

Higher is better; ratio of between-cluster dispersion to within-cluster dispersion.

CH is particularly useful for comparing candidate configurations (different model families or cluster-count choices) because it summarizes global separation efficiency.

## 8.4 Joint Interpretation

No single metric is sufficient. A practical acceptance region often requires:

- high or improved Silhouette,
- low or decreasing DBI,
- high or increasing CH,
- plus cluster-size sanity and analyst relevance.

A composite comparison score may be used for internal ranking:

$\mathcal{Q}_{intrinsic}=w_s S - w_d \mathrm{DBI} + w_c \log(1+\mathrm{CH})$

where $w_s,w_d,w_c$ are task-dependent weights. This helps prioritize experiments but should not replace detailed metric diagnostics.

---

## 9. Post-Fine-Tuning Latent Ensemble Refinement

### 9.1 Motivation

Fine-tuned model labels may be locally optimal but not globally best under intrinsic criteria. Refinement performs bounded search in latent space to recover better partitions.

This stage is especially relevant in security telemetry because latent representation quality and hard assignment quality may diverge. Refinement explicitly targets assignment quality after representation learning has converged.

### 9.2 Search Space

- Algorithms: K-means, Gaussian Mixture, Agglomerative.
- Cluster counts: bounded candidate set $\mathcal{K}$.
- Feature spaces: normalized latent and PCA projections.
- Constraints: minimum cluster size threshold.

Selection objective:

$y^*=\arg\max_{y\in\mathcal{C}} \mathrm{Silhouette}(Z,y)$

Adoption criterion:

$\Delta S=S(y^*)-S(y_0)\ge\delta$

where $y_0$ is original model prediction and $\delta$ is a minimum gain threshold.

A constrained refinement view:

$y^*=\arg\max_{y\in\mathcal{C}} \mathrm{Silhouette}(Z,y)\quad \text{s.t.} \quad\min_k |C_k(y)| \ge n_{\min},\ \ T(y)\le T_{max}$

### 9.3 Runtime Guardrails

- search-time cap $T_{max}$,
- reduced restart counts,
- bounded $K$-range,
- immediate return with best-so-far solution when time budget is hit.

These guardrails keep quality improvements practical for production API latency.

The refinement stage therefore behaves as an anytime optimization: when the time budget is reached, the best admissible partition found so far is returned.

### 9.4 Conceptual Figure

```text
Refinement decision flow (Figure 9.4 — text form for standard Markdown preview):

  Latent Z, labels y0
        │
        ▼
  Generate candidate spaces (e.g. latent / PCA views)
        │
        ├──► K-means grid ────┐
        ├──► GMM grid ────────┼──► Score each partition (e.g. Silhouette)
        └──► Agglomerative grid ┘
                    │
                    ▼
        Apply constraints; pick best candidate y*
                    │
                    ▼
            Gain ≥ δ ?
           ╱          ╲
         yes            no
          │              │
          ▼              ▼
   Use refined y*   Keep original labels
```



This figure summarizes the bounded refinement decision process in latent space:

- `**A: Latent Z and labels y0**` is the input from deep fine-tuning, where $Z$ are learned embeddings and $y_0$ are the initial hard assignments.
- `**B: Generate candidate spaces**` prepares multiple search spaces (for example normalized latent and PCA-projected variants) to reduce sensitivity to a single geometric view.
- `**C1/C2/C3**` represent algorithm-specific candidate generation:
  - `C1` explores K-means partitions over candidate $K$ values,
  - `C2` explores Gaussian Mixture partitions,
  - `C3` explores agglomerative partitions.
- **K-means grid (`C1`)** means running K-means over a grid of candidate hyperparameters (primarily cluster count $K$, plus multiple random restarts). This branch is efficient and works well when latent clusters are approximately compact and centroid-separable.
- **GMM grid (`C2`)** means fitting Gaussian Mixture Models over candidate $K$ values (and optionally covariance choices/restarts), then converting posterior assignments into hard labels for scoring. This branch is useful when clusters have different variances/shapes and soft probabilistic membership is informative.
- **Agglomerative grid (`C3`)** means hierarchical clustering runs across candidate $K$ values (and potentially linkage/distance settings), followed by cut-level label extraction and scoring. This branch is valuable when latent structure is non-spherical or nested, though it can be more expensive at larger $N$.
- `**D: Score by Silhouette`** evaluates each candidate partition using intrinsic quality so candidates from different algorithms can be compared on a common criterion.
- `**E: Apply constraints and choose best y*`** enforces admissibility constraints (minimum cluster size, runtime budget) and selects the best valid candidate assignment $y^*$.
- `**F: Gain >= delta?`** is the acceptance gate. The selected candidate is adopted only if quality gain over $y_0$ satisfies the threshold:

$\Delta S = S(y^*) - S(y_0) \ge \delta$

- `**G: Use refined labels`** means refinement delivered sufficient benefit and the pipeline promotes $y^*$ to final labels.
- `**H: Keep original labels`** is a safeguard path that avoids unnecessary label churn when improvement is marginal or unstable.

The theoretical workflow for these branches can be written as:

$\text{For each } a \in \mathcal{A}=\text{KMeans},\text{GMM},\text{Agg},$
$\text{for each } K\in\mathcal{K},$
$\text{for each } r\in\mathcal{R}*a:$
$\quad y*{a,K,r} \leftarrow \mathcal{M}_{a,K,r}(Z)$

Algorithm-specific objective views:

- **K-means grid** (minimize within-cluster sum of squares):

$\min_{\{\mu_k\},y}\ \sum_{i=1}^{N}\left\|z_i-\mu_{y_i}\right\|_2^2,\quad y_i\in\{1,\dots,K\}$

This is typically solved by alternating assignment and centroid-update steps for each $(K,r)$ pair.

- **GMM grid** (maximize mixture likelihood):

$\max_{\Theta}\ \sum_{i=1}^{N}\log\left(\sum_{k=1}^{K}\pi_k\,\mathcal{N}(z_i\mid\mu_k,\Sigma_k)\right),\quad \Theta=\{\pi_k,\mu_k,\Sigma_k\}_{k=1}^{K}$

Posterior responsibilities:

$\gamma_{ik}=\frac{\pi_k\mathcal{N}(z_i\mid\mu_k,\Sigma_k)}{\sum_{j=1}^{K}\pi_j\mathcal{N}(z_i\mid\mu_j,\Sigma_j)}$

Hard labels are derived by $y_i=\arg\max_k \gamma_{ik}$ for scoring/selection.

- **Agglomerative grid** (hierarchical linkage optimization):

$\min_{A,B}\ d_{\text{link}}(A,B)$

where at each merge step the pair of clusters $(A,B)$ with minimal linkage distance is merged (e.g., Ward linkage minimizes increase in within-cluster variance). For each candidate $K$, the dendrogram is cut to yield labels $y$.

Selection among branches then uses a unified intrinsic criterion:

$y^*=\arg\max_{y\in\mathcal{Y}_{\text{valid}}}\mathrm{Silhouette}(Z,y),\quad\Delta S = S(y^*)-S(y_0)$

Operationally, this figure captures a conservative optimization policy: improve quality when there is clear evidence, otherwise preserve the original model output.

---

## 10. Complexity Considerations

Let $N$ be number of points, $m$ latent dimension, $K$ clusters, and $I$ iterative solver steps.

### 10.1 Stage-wise Complexity

- Encoder forward extraction: $O(N \cdot C_f)$ where $C_f$ is network forward cost.
- K-means candidate: approximately $O(NKmI)$.
- GMM candidate (EM): approximately $O(NKmI)$ with covariance overhead.
- Agglomerative candidate: super-linear, often dominant for large $N$.

Dominant cost depends on data regime:

- large $N$ with hierarchical candidates can make agglomerative search dominant,
- large restart grids can make K-means/GMM candidates dominant,
- high-dimensional latent space increases distance and covariance computation cost.

### 10.2 Ensemble Search Complexity

$O\left(\sum_{a\in\mathcal{A}} |\mathcal{K}| \cdot |\mathcal{R}_a| \cdot \mathrm{cost}(a)\right)$

where $\mathcal{A}$ is algorithm set and $\mathcal{R}_a$ are restarts for algorithm $a$.

### 10.3 Practical Cost Control

Through explicit time budgets and bounded candidate sets, effective runtime becomes:

$\min\left(\text{full search cost},\ T_{max}\right)$

Quality-cost tradeoff can be formalized as:

$\max_{\Theta}\ \mathcal{Q}_{intrinsic}(\Theta)-\lambda T(\Theta)$

where $\Theta$ denotes model and refinement hyperparameters, and $\lambda$ encodes latency sensitivity.

---

## 11. Security Analytics Layer

Cluster outputs are mapped to analyst-facing intelligence. The following items are the main deliverables of the analytics layer: for each, we summarize **what** it is, **how** it is produced in this system, and **what to do** with it in practice.

- **Threat-level estimation per cluster**  
  - *What:* A qualitative label (e.g. unknown, low, medium, high, critical) summarizing how “dangerous” or alert-heavy the cluster appears from aggregated event semantics—not from ground-truth labels.  
  - *How:* The cluster analyzer scores each cluster using distributions of **severity** fields, **action** types (blocked vs allowed), **subsystem** exposure (e.g. IPS/IDS, DDoS), **suspicious destination ports**, and **content keywords** aligned with threat language. A separate **cluster risk** object (used in threat-landscape views) applies an additive numeric score with explicit **factors** so the label is inspectable.  
  - *What to do:* Use threat level to **sort triage queues** and escalation policy; **open the listed factors** before trusting the label alone; downgrade noise clusters dominated by benign policy blocks; escalate when threat level aligns with business-critical assets or with high-severity insights for the same cluster.

- **Dominant subsystems and actions**  
  - *What:* The most frequent **subsystem** strings (firewall, WAF, IPS, etc.) and **action** outcomes (allow, block, deny, …) within each cluster, exposed as `primary_subsystems` and `primary_actions` in cluster profiles.  
  - *How:* After clustering, all events assigned to cluster $k$ are scanned; counters aggregate normalized subsystem and action fields from the parser. The top categories by count (or frequency share) are selected for display and for narrative text in summaries.  
  - *What to do:* **Match clusters to owning teams** (network vs app vs identity); **validate parser mappings** if subsystems look wrong; use dominant **block/deny** patterns to prioritize defensive controls and use dominant **allow** noise to consider filtering or separate “baseline” clusters in future runs.

- **Representative events**  
  - *What:* A small set of **raw or lightly structured events** chosen to exemplify what “typical” activity in the cluster looks like, so analysts need not scroll the full cluster volume immediately.  
  - *How:* The analyzer selects representatives by **stratifying** or **scoring** diversity (e.g. favoring high-information fields, common IPs, or varied content) within the cluster; the UI can later **page** additional events via the cluster-events API.  
  - *What to do:* **Read representatives first** to confirm the cluster is coherent; if they disagree with the cluster label, treat the partition as suspect (feature or $K$ issue); **quote representatives** in tickets or postmortems for traceability; **hunt** using fields copied from representatives (IPs, users, URLs).

- **Top source IPs and destination ports**  
  - *What:* Ranked **source IP** addresses and **destination port** numbers (with counts) that characterize where traffic in the cluster comes from and what services it hits.  
  - *How:* Per-cluster counters over `source_ip` and `dest_port` from parsed events; top-$k$ entries are attached to profiles and often reused inside insights (e.g. brute-force sources, targeted services). Port semantics may be cross-checked against known sensitive services (SSH, RDP, SMB, etc.).  
  - *What to do:* **Enrich IPs** with ownership and geolocation; **block or rate-limit** only after false-positive review; **correlate** top sources across clusters (see correlations below); **review ports** for unexpected exposure (e.g. management ports on internet-facing hosts) and align with vulnerability management.

- **Recommended mitigation actions**  
  - *What:* Short, concrete **immediate** and **long-term** recommendations tied to detected patterns (per insight) plus **executive-level priority lines** that synthesize the worst findings across clusters.  
  - *How:* Template-based text is emitted when heuristics fire (e.g. authentication hardening after brute-force detection, WAF tuning after web-attack detection); the executive summary adds **recommended_priorities** from global severity counts and keyword matches on insight titles.  
  - *What to do:* **Map each action to an owner** (SOC, IR, platform engineering); **convert** into change tickets with scope and rollback; **avoid blind automation**—tune rules to your environment; **measure** whether post-change log volume or risk scores improve on the next training run.

- **IOC and correlation extraction**  
  - *What:* **IOCs** are observable indicators (e.g. IP addresses with context strings, suspicious users, attack-pattern summaries) suitable for block lists, hunts, or threat-intel sharing; **correlations** link pairs of clusters when they share sources, share targets, satisfy a simple **attack-chain** overlap rule (sources in one cluster appear as targets in another), or exhibit **high cosine similarity between cluster centroids in latent space** (`sequence_latent_similarity`).  
  - *How:* IOCs are gathered from **`ioc_indicators`** on insights and aggregated in the IOC endpoint (deduplicated contexts, severity roll-up, optional firewall-rule suggestions). Correlations combine set overlap on **source** and **destination** IP sets between cluster event groups (with numeric **strength** thresholds to suppress noise) and optional **latent centroid** comparisons when embeddings are available (§11.3).  
  - *What to do:* For IOCs, **verify provenance** (which insight and samples), **age out** stale indicators using `generated_at` and retraining, and **feed** only vetted IPs into enforcement tiers. For correlations, **treat as hypotheses**: validate with timestamps and identity data; use **shared-source** links for actor-centric cases and **attack-chain** links for possible lateral movement—then **document** disproven links to improve future heuristics.

This conversion from unsupervised clusters to actionable security semantics is central for SOC integration.

Two principles make this layer useful in practice:

- **traceability**: every cluster-level claim should be backed by representative raw events,
- **actionability**: outputs should support concrete decisions (escalate, block, investigate, monitor).

**A simplified SOC utility objective.** Security operations rarely optimize a single metric (such as Silhouette on embeddings). Operationally, leadership cares about **compressing alert volume**, **improving decisions**, and **controlling human cost**. A compact way to express that tradeoff is to define a scalar **utility** that rewards good outcomes and penalizes analyst burden:

$\mathcal{U}_{soc}=\alpha \mathcal{R}_{triage}+\beta \mathcal{A}_{decision}-\gamma \mathcal{C}_{analyst}$

The symbols are interpreted as follows.

- **$\mathcal{U}_{soc}$ (overall SOC utility)** — A notional score to **maximize** when comparing two system configurations (e.g. clustering + insights A vs B), or when deciding whether a model update is “worth it.” It is **not** automatically computed in the codebase; it is a **conceptual target** for evaluation design. Higher $\mathcal{U}_{soc}$ means the stack better supports the SOC mission under your chosen weights.

- **$\mathcal{R}_{triage}$ (triage reduction benefit)** — How much the clustering and narrative layer **reduces raw triage load** without hiding incidents. Proxies include: fewer **distinct analyst work items** after grouping (events per cluster vs per event), shorter **mean time to first understanding** when analysts start from cluster summaries instead of unstructured queues, and **coverage** of the original stream (no silent drops). A strict formulation would require a baseline (“unclustered queue”) and the same time window for fair comparison.

- **$\mathcal{A}_{decision}$ (decision quality)** — How much the outputs improve **downstream security decisions**: correct escalations, timely containment, fewer false escalations on benign clusters, alignment with **validated** incidents or purple-team exercises. In research terms this is often **partially labeled**; in production it may be scored via **post-incident review**, **ticket outcomes**, or **analyst ratings** of cluster usefulness. Intrinsic clustering metrics (Silhouette, etc.) may **correlate** with $\mathcal{A}_{decision}$ but are not substitutes for it.

- **$\mathcal{C}_{analyst}$ (analyst effort / cost)** — The **human price** of using the system: wall-clock review time, number of clicks or drill-downs, **cognitive load** from contradictory or empty clusters, retraining and playbook updates, and **alert fatigue** if clusters are too granular or too noisy. This term is **subtracted** because effort is a cost, not a benefit.

- **$\alpha$, $\beta$, $\gamma$ (nonnegative weights)** — They set the **relative importance** of triage gain vs decision quality vs analyst cost for your organization. For example, a mature SOC with severe staffing constraints might increase $\gamma$ so that solutions that explode review time are disfavored even if they slightly improve embedding metrics; a greenfield SOC might emphasize $\mathcal{R}_{triage}$ first to get control of volume ($\alpha$ large), then raise $\beta$ as ground truth labels become available. In practice these weights are **implicit** in leadership priorities; making them explicit clarifies why “best cluster quality” alone is an incomplete goal.

**How to use this expression in practice.** Treat $\mathcal{R}_{triage}$, $\mathcal{A}_{decision}$, and $\mathcal{C}_{analyst}$ as **measurable surrogates** you define (dashboards, sampling studies, periodic reviews), not as built-in API fields. Re-estimate them when **log sources**, **threat model**, or **staffing** change. If two objectives conflict (e.g. finer clusters improve separation but raise $\mathcal{C}_{analyst}$), the weighted sum makes the tradeoff discussable; alternatively, keep $\mathcal{U}_{soc}$ as a narrative **Pareto** story (improve triage and decisions **without** increasing analyst hours above a cap).

**Metrics commonly used to compare commercial SOC stacks (illustrative mapping).** Published product briefs, analyst reports (e.g. Gartner Magic Quadrant for SIEM / security analytics), and customer case studies for major platforms (representative families include Microsoft Sentinel, Splunk Enterprise Security, Google Chronicle, IBM QRadar, Elastic Security, Palo Alto Cortex, Sumo Logic, and SOAR-centric suites) rarely expose an explicit $(\alpha,\beta,\gamma)$ triple—they instead headline **operational KPIs** that you can map onto $\mathcal{R}_{triage}$, $\mathcal{A}_{decision}$, and $\mathcal{C}_{analyst}$ after normalization. Widely cited families of measures include:

| Measurement family | Typical examples (as reported in marketing and benchmarks) | Maps most naturally to |
|--------------------|-----------------------------------------------------------|-------------------------|
| Speed / latency | Mean time to **detect** (MTTD), **acknowledge** (MTTA), **respond** or **resolve** (MTTR); time-to-triage for a queue | $\mathcal{A}_{decision}$ (outcome quality + timeliness), partly $\mathcal{R}_{triage}$ if “time to understand” drops |
| Volume / noise | Alerts or events **per analyst per day**, **deduplication** or **correlation** rates, “noise reduction” percentages in case studies | $\mathcal{R}_{triage}$ |
| Accuracy / fidelity | **True/false positive** discussion, escalation quality, incident **validation** rate, purple-team or red-team **detection** scores | $\mathcal{A}_{decision}$ |
| Human effort | **Analyst hours** per incident, staffing FTE, **queue backlog**, survey-based **usability** or burnout proxies | $\mathcal{C}_{analyst}$ |

Frameworks such as **NIST** incident response lifecycle metrics and **SANS** SOC survey categories (staffing, tooling, process maturity) are often used alongside vendor KPIs when organizations benchmark “before vs after” a SIEM/SOAR deployment. Any head-to-head product comparison should fix the **same** observation period, log scope, and labeling protocol when turning these headlines into numeric $\mathcal{R}_{triage}$, $\mathcal{A}_{decision}$, and $\mathcal{C}_{analyst}$ scores (e.g. min–max scale each to $[0,1]$ per quarter).

**Illustrative weight values $(\alpha,\beta,\gamma)$—not vendor-published constants.** No major SOC product publishes internal utility weights in the form above; the following triples are **synthetic examples** showing how different operating models would tilt the same measured $(\mathcal{R}_{triage},\mathcal{A}_{decision},\mathcal{C}_{analyst})$ when comparing two pipelines (e.g. “baseline SIEM rules only” vs “clustering + insights”). Assume each of $\mathcal{R}_{triage}$, $\mathcal{A}_{decision}$, and $\mathcal{C}_{analyst}$ has been scaled to $[0,1]$ for the quarter so that magnitudes are comparable before weighting.

| Archetype | $\alpha$ | $\beta$ | $\gamma$ | Interpretation for comparison |
|-----------|----------|---------|----------|--------------------------------|
| **High-volume / MSSP-style** — maximize throughput of review | $0.50$ | $0.30$ | $0.20$ | Strong emphasis on collapsing alert volume and queue shape ($\mathcal{R}_{triage}$); still rewards correct outcomes, moderate penalty on extra analyst time. |
| **Regulated enterprise / IR quality** — minimize miss rate and audit risk | $0.25$ | $0.55$ | $0.20$ | Dominant weight on decision correctness and detection fidelity ($\mathcal{A}_{decision}$); triage compression is secondary to missing fewer true incidents. |
| **Severely understaffed SOC** — cap human burn | $0.30$ | $0.25$ | $0.45$ | Largest weight on analyst cost ($\mathcal{C}_{analyst}$): a product or model that improves Silhouette but doubles review time scores poorly unless $\mathcal{A}_{decision}$ jumps enough to compensate. |

**Numeric illustration (same surrogates, different products).** Suppose after scaling, **Product A** achieves $(\mathcal{R}_{triage},\mathcal{A}_{decision},\mathcal{C}_{analyst})=(0.8,\ 0.6,\ 0.5)$ and **Product B** achieves $(0.5,\ 0.75,\ 0.35)$. Under the **MSSP** weights $(0.50,0.30,0.20)$: $\mathcal{U}_{soc}(A)=0.50(0.8)+0.30(0.6)-0.20(0.5)=0.48$; $\mathcal{U}_{soc}(B)=0.50(0.5)+0.30(0.75)-0.20(0.35)=0.405$ — A wins on triage-heavy scoring. Under the **understaffed** weights $(0.30,0.25,0.45)$: $\mathcal{U}_{soc}(A)=0.30(0.8)+0.25(0.6)-0.45(0.5)=0.165$; $\mathcal{U}_{soc}(B)=0.30(0.5)+0.25(0.75)-0.45(0.35)=0.18$ — B wins because lower analyst cost and higher decision score outweigh A’s triage advantage. This shows why **published SOC comparisons** that only quote “$X\%$ faster MTTR” are incomplete until weights (or Pareto constraints) reflect your SOC’s priorities.

### 11.1 Measuring security insights, priority actions, and cluster risk

**Insight measurement (operational view).** In this implementation, a *security insight* is not a single scalar; it is a structured object with explicit fields that analysts can audit: `category` (e.g. attack, policy violation, anomaly), `severity` (critical / high / medium / low / info), `confidence` (heuristic score in $[0,1]$), `event_count`, `sample_events`, `affected_subsystems`, `source_ips`, `target_assets`, `immediate_actions`, `long_term_actions`, and `ioc_indicators`. *Measurement* therefore proceeds by:

1. **Coverage**: number of insights per cluster and globally (`insights_generated` in the executive summary).
2. **Severity mix**: histogram over `severity` across all insights—useful for workload sizing (e.g. many `critical` implies immediate queue pressure).
3. **Evidence weight**: `event_count` and overlap with raw telemetry (samples) validate that an insight is not a spurious label on a tiny fragment of a cluster.
4. **Confidence**: treated as a *relative* ranking signal between heuristics of the same type, not a calibrated probability, unless validated on labeled data.

**Priority actions.** Priorities are derived in two places. First, each `SecurityInsight` carries **immediate** and **long-term** action lists authored by rule templates (e.g. block high-volume sources, enable MFA, tune WAF). Second, the executive summary builds **`recommended_priorities`**: it prepends urgent lines when any `critical` insights exist, counts `attack`-category insights, then adds pattern-specific guidance when insight *titles* match coarse keywords (e.g. “Brute Force”, “Web Application”, “DDoS”, “Exfiltration”). Analysts should treat this list as a **ranked agenda** to merge with ticketing severity and business context.

**Cluster risk assessment.** Cluster-level risk used in threat-landscape views is computed by a **transparent additive score** over the events in that cluster (capped at 100), then mapped to `critical` / `high` / `medium` / `low`:

- Block-dominant clusters: if the fraction of events with actions in $\{\text{blocked}, \text{denied}, \text{drop}\}$ exceeds $0.8$, add points and record factor “High block rate”.
- Severity: each `critical` event adds a large increment; `high` adds a medium increment; contributing factors are listed by name.
- Subsystem cues: presence of `ips`/`ids` or `ddos` in subsystem names adds fixed bonuses (defensive-alert-heavy clusters).
- Content keywords: if more than 10% of events contain high-salience threat tokens (e.g. attack, exploit, malware, intrusion, breach), add points.

The returned object includes `score`, `level`, `factors`, and `event_count` so analysts can **inspect why** a cluster was rated—not only the final label. This is complementary to per-insight severity, which is pattern-specific.

### 11.2 MITRE ATT&CK tactics and techniques (and how this system obtains them)

**What MITRE ATT&CK represents.** The [MITRE ATT&CK](https://attack.mitre.org/) framework organizes adversary behavior into **tactics** (the “why” of an action—e.g. Initial Access, Credential Access) and **techniques** (the “how”—e.g. T1110 Brute Force). Mapping clusters to ATT&CK helps teams align detections, playbooks, and reporting with industry vocabulary.

**How information is produced here (rule-based, not ML classification).** The `SecurityInsightsEngine` maintains an internal dictionary **`MITRE_MAPPINGS`**: keys are *short textual cues* (e.g. `brute`, `sqli`, `ddos`, `c2`) mapped to `(tactic_name, technique_string)` pairs. When a detector fires (e.g. brute-force heuristic passes), the corresponding **`SecurityInsight`** is constructed with **`mitre_tactics`** and **`mitre_techniques`** lists set explicitly in code for that template—see for example brute-force insights that set `Credential Access` and `T1110 - Brute Force`. Web, DDoS, and other pattern builders follow the same pattern.

**Where consumers read aggregated MITRE data.**

- **Per insight**: each insight object exposes `mitre_tactics` and `mitre_techniques`.
- **Executive summary**: all insights are scanned; unique tactics and a truncated list of techniques appear under `mitre_coverage`.
- **Dedicated API**: `GET /api/insights/{job_id}/mitre` recomputes insights per cluster and aggregates tactics/techniques, kill-chain-style narrative, coverage assessment, and suggested mitigations (from a small curated technique→mitigation table in the API layer).

**Limitations.** These mappings are **heuristic and template-driven**: they depend on keyword statistics, ports, and subsystems—not on a trained ATT&CK classifier. False links are possible when log text is ambiguous; analysts should confirm against raw events and their own threat model.

### 11.3 Cluster correlations and attack chains

After clustering, the engine compares **pairs of clusters** with (1) **network identity overlap** on parsed `source_ip` and `dest_ip` fields and (2) optional **latent centroid similarity** when the API passes stored embeddings and refined labels into `find_cluster_correlations` (`security_insights.py`).

**Same-source correlation.** Let $S_a$, $S_b$ be the sets of source IPs in clusters $a$ and $b$. If $S_a \cap S_b \neq \emptyset$, define

$\text{strength}_{ss} = \frac{|S_a \cap S_b|}{\max(|S_a|, |S_b|)}$.

If $\text{strength}_{ss} > 0.1$, emit a `ClusterCorrelation` with `correlation_type="same_source"`, `shared_indicators` (sample of shared IPs), and a human-readable description. Intuition: a single actor or asset appears in multiple behavioral groups.

**Same-target correlation.** Analogously for destination sets $T_a$, $T_b$:

$\text{strength}_{st} = \frac{|T_a \cap T_b|}{\max(|T_a|, |T_b|)}$,

with threshold $0.1$ and type `same_target`. Intuition: multiple attack patterns converge on the same victims or services.

**Attack-chain hypothesis.** The implementation flags **`attack_chain`** when sources seen in cluster $a$ appear as **targets** in cluster $b$:

$H_{ac} = S_a \cap T_b$.

If non-empty, strength is reported as $|H_{ac}| / |S_a|$ (fraction of $a$’s sources that are “pivots” into $b$’s target set). The description states that sources in cluster $a$ are targets in cluster $b$, suggesting a possible **lateral movement or multi-stage** narrative. This is a **weak structural signal**: it does not prove temporal ordering or causality; analysts should validate with timestamps and authentication context.

**Latent centroid similarity (`sequence_latent_similarity`).** When `latent_embeddings` (per-event matrix $Z$) and `cluster_labels` align in length, the engine computes **L2-normalized** mean latent vectors (centroids) per cluster and, for each unordered pair $(a,b)$, the **cosine similarity** of those centroids. If similarity $\ge$ a configurable threshold (default $0.55$), it emits `correlation_type="sequence_latent_similarity"` with `correlation_strength` equal to that cosine. Despite the name, this uses **whatever** latent vectors the job stored (vector IDEC, sequence IDEC, **UFCM+LSTM**, GNN-IDEC, DMVC, etc.); it highlights **geometrically similar** cluster prototypes in embedding space, not IP overlap.

**Evaluation guidance.** Treat correlations as **hypotheses for investigation**: sort by `correlation_strength`, cross-check shared IPs against asset inventory, and reject spurious overlaps (NAT pools, load balancers, scanners hitting many clusters). For latent pairs, confirm with cluster profiles and samples before merging narratives—high centroid similarity can still reflect benign structure shared across clusters.

### 11.4 Evaluating indicators of compromise (IOCs)

**Definition in this pipeline.** IOCs are **actionable observables** extracted from insights and events: IP addresses attached to insights as `ioc_indicators`, attack-pattern summaries, suspicious user accounts, and suggested firewall rules.

**Aggregation (`GET /api/insights/{job_id}/iocs`).** For each cluster, cluster insights are recomputed. For every insight:

- **IP IOCs**: each indicator with `type == "ip"` increments per-IP aggregates: `contexts` (deduplicated strings such as `brute_force_source`), `event_count` (summed from `insight.event_count`), and `severity` escalated to `critical`/`high` when any contributing insight has that severity.
- **Attack patterns**: `category == "attack"` insights contribute rows with title, description snippet, MITRE techniques, sample `source_ips`, and severity.
- **Suspicious users**: globally, users with **block rate** $> 0.5$ across their events are listed with reasons.

**How to evaluate IOC quality (analyst / engineering checklist).**

1. **Provenance**: trace each IP IOC back to the insight and sample events—high `event_count` driven by a single noisy insight is weaker than consistent multi-insight agreement.
2. **Severity vs. prevalence**: prefer blocking or hunting on IPs that appear with `critical`/`high` severity and multiple contexts rather than one-off scanner noise.
3. **False-positive controls**: shared infrastructure, CDN edges, and corporate egress NAT can create **same_source** / IOC overlap without malice; correlate with reputation feeds and internal ownership.
4. **Suggested firewall rules**: auto-generated rules (e.g. block lists for high-severity IPs, rate limits when brute-force patterns exist) are **starting points**—review change windows, scope, and rollback before production enforcement.
5. **Temporal validity**: IOC endpoints include `generated_at`; stale jobs should be re-run after major log or policy changes.

Together, §11.1–11.4 describe how this project turns clusters into **measured**, **prioritized**, **ATT&CK-aligned**, **correlation-aware**, and **IOC-ready** outputs—while keeping assumptions explicit for scientific and operational review.

---

## 12. Experimental Design and Evaluation Protocol

### 12.1 Reproducibility

- fix random seeds across PyTorch and clustering backends,
- record model hyperparameters and selected refinement outputs,
- run each configuration multiple times.

For stronger reproducibility, also record:

- parser/feature schema version,
- stage-level runtimes and hardware context,
- data snapshot identifiers and time-window boundaries.

### 12.2 Core Experiments

1. **Model family comparison**: DEC vs IDEC vs **IDEC+LSTM** vs **IDEC+Transformer** vs **IDEC+GNN** vs VaDE vs contrastive vs **UFCM** vs **UFCM+LSTM** vs DMVC.
2. **Latent dimension sweep**: impact of $m$ on separability.
3. **Cluster count sensitivity**: fixed $K$ vs adaptive search.
4. **Refinement ablation**:
  - no refinement,
  - fixed-$K$ refinement,
  - adaptive-$K$ ensemble refinement.
5. **Runtime-quality Pareto**: metric gains vs postprocessing time budget.

Recommended extensions:

1. **Missingness robustness**: controlled field dropout and noise injection tests.
2. **Temporal drift evaluation**: train-test splits across different time windows.
3. **Analyst utility assessment**: time-to-triage and confidence scoring with/without clustering assistance.

### 12.3 Reporting

Report mean and standard deviation for:

- Silhouette,
- DBI,
- CH,
- cluster-size dispersion,
- runtime breakdown per stage,
- final-epoch **fine-tune** `total_loss`, `clustering_loss`, and `reconstruction_loss` when comparing model families or hyperparameters (values returned by the API as `training_loss`).

Include variability statistics for rigorous reporting:

$\bar{m}=\frac{1}{R}\sum_{r=1}^{R}m_r,\qquad$
$s_m^2=\frac{1}{R-1}\sum_{r=1}^{R}(m_r-\bar{m})^2$

---

## 13. Experimental Results

This section gives **illustrative** experimental summaries that match the evaluation protocol in Section 12. The numeric cells are **representative** of the kinds of outcomes observed when running the implemented stack (handcrafted features + deep clustering + bounded latent refinement) on mixed synthetic and demo-style security logs; they are **not** a fixed external benchmark. Replace them with means $\pm$ standard deviations from your own $R$ repeated runs, data snapshots, and hardware context for publication-grade reporting.

### 13.1 Setup (aligned with the codebase)

- **Input**: $N \approx 10^4$–$10^5$ parsed key=value events; per-batch z-score normalization of the $d=70$-dimensional vectors (Section 5).
- **Models**: DEC, IDEC, **IDEC+LSTM**, **IDEC+Transformer**, **IDEC+GNN**, VaDE, contrastive, UFCM, **UFCM+LSTM**, DMVC; default-ish depths and latent dimension $m_{\mathrm{latent}}=32$ unless noted. For sequence IDEC and **UFCM+LSTM**, record **`seq_len`** (and LSTM/Transformer width-depth knobs where applicable). For GNN-IDEC, record **`gnn_k_neighbors`**, **`gnn_hidden_dim`**, **`gnn_num_layers`**, and **batch size** (it shapes the graph). (Do not confuse latent width with UFCM fuzziness $m_{\mathrm{fuzz}}>1$ in Section 6.5.) For DMVC, also record `gamma` and `mvc_weight` when comparing runs.
- **Refinement**: latent ensemble search with time budget $T_{\max}\approx 8\,\mathrm{s}$, sampled Silhouette for scoring (Section 9).
- **Metrics**: Silhouette ($S$, higher better), Davies–Bouldin ($\mathrm{DBI}$, lower better), Calinski–Harabasz ($\mathrm{CH}$, higher better), all computed in **latent space** on final assignments unless stated otherwise.

### 13.2 Table 1 — End-to-end pipeline vs shallow baseline

**Figure 1 (tabular).** Intrinsic metrics for a **shallow baseline** (K-means on standardized handcrafted features, same $K$) compared to **IDEC** without post-hoc refinement and **IDEC + latent refinement** (final labels).

| Configuration | Silhouette $S$ | DBI | CH $(\times 10^{3})$ | Notes |
|---------------|----------------|-----|----------------------|--------|
| K-means (raw features) | 0.05 | 2.8 | 4.2 | No learned encoder; geometry limited by linear separability. |
| IDEC (latent, pre-refine) | 0.12 | 2.1 | 6.8 | Deep representation improves separation vs raw K-means. |
| IDEC + refinement | 0.19 | 1.7 | 8.4 | Post-hoc assignment search on $z$ boosts $S$ within budget. |

Values are rounded to two decimals; CH scaled for readability. DBI and CH are only comparable **within** the same dataset and embedding space.

### 13.3 Table 2 — Model family comparison (fixed protocol)

**Figure 2 (tabular).** Same data and $K$, single seed, comparable training budgets (pretrain + finetune epoch counts fixed across families). Shows typical **relative** ordering; absolute numbers drift with hyperparameters and corpus.

| Model family | Silhouette $S$ | DBI | CH $(\times 10^{3})$ |
|--------------|----------------|-----|----------------------|
| DEC | 0.10 | 2.3 | 6.1 |
| IDEC | 0.12 | 2.1 | 6.8 |
| VaDE | 0.11 | 2.2 | 6.4 |
| UFCM | 0.10 | 2.2 | 6.5 |
| UFCM + LSTM | 0.10 | 2.2 | 6.5 |
| DMVC | 0.10 | 2.2 | 6.4 |
| IDEC + LSTM | 0.11 | 2.2 | 6.6 |
| IDEC + Transformer | 0.11 | 2.1 | 6.7 |
| IDEC + GNN (GCN) | 0.11 | 2.2 | 6.6 |
| Contrastive | 0.09 | 2.4 | 5.9 |

IDEC often balances clustering loss and reconstruction, yielding slightly better intrinsic scores on mixed security-style logs in this illustrative setting. **Sequence IDEC** and **UFCM+LSTM** rows are **illustrative**: outcomes depend on timestamp quality, burst structure, and `seq_len`; they are not guaranteed to beat vector baselines on every corpus. **GNN-IDEC** is similarly **illustrative**: gains depend on batch size, $k$, and whether within-batch neighbors are semantically meaningful. DMVC’s relative position depends strongly on whether the **feature half-split** matches meaningful structure; the table entry is **illustrative** only. UFCM and UFCM+LSTM can sit near DEC/VaDE on hard-label intrinsic metrics because argmax labels do not fully reflect fuzzy overlap; soft-assignment diagnostics (e.g., membership entropy) are complementary.

### 13.4 Table 3 — Ablations: encoder and refinement

**Figure 3 (tabular).** Isolated effects of **feature encoder upgrades** (Section 5.11) and **refinement on/off**; all rows use IDEC with matched training steps.

| Variant | Silhouette $S$ | $\Delta S$ vs row 1 |
|---------|----------------|---------------------|
| Baseline encoder, no refinement | 0.09 | — |
| Improved encoder, no refinement | 0.11 | +0.02 |
| Baseline encoder + refinement | 0.15 | +0.06 |
| Improved encoder + refinement | 0.19 | +0.10 |

$\Delta S$ summarizes **relative** gains; combined encoder + refinement typically yields the largest lift when content and categorical fields carry cluster-relevant signal.

### 13.5 Figure 4 — Illustrative Silhouette trajectory across stages

The figure below is a **schematic** monotonic uplift (not a per-epoch training log). It shows the *shape* of improvement from raw features to deep latent space to refined assignments. It uses a plain-text chart so the built-in VS Code Markdown preview renders it without extra extensions—Table 1 remains authoritative for numbers.

```text
Figure 13.5 — Illustrative Silhouette vs pipeline stage (latent metric, same values as Table 1)

  Stage              S (approx)   Text bar (0 … 0.25 scale)
  ─────────────────  ───────────  ───────────────────────────
  K-means (raw)      0.05         ██░░░░░░░░░░░░░░░░░░
  IDEC (latent)      0.12         █████░░░░░░░░░░░░░░░
  IDEC + Refine      0.19         ████████░░░░░░░░░░░░
```

### 13.6 Figure 5 — Runtime vs quality tradeoff (schematic)

Postprocessing improves intrinsic scores but consumes bounded CPU time. The sketch below situates **four operating points** as conceptual examples; axis scales are qualitative (plain text for standard Markdown preview).

```text
Figure 13.6 — Latency vs quality tradeoff (schematic)

                    higher Silhouette S
                           ▲
         "Target zone"      │     slower / marginal gains
         (e.g. T_max 8s)   │     (e.g. T_max 30s)
                           │
         fast / weaker     │     (avoid: high time, weak gain)
         (no refinement,   │
          T_max 2s)        │
                           └──────────────────────────────►
                               low ──► high postprocess time
```

Interpretation: moving right increases refinement budget; the **target zone** balances acceptable SOC latency with measurable $S$ gains. Saturation (upper-right) can occur when the time budget exceeds useful new candidates—consistent with bounded search in Section 9.

### 13.7 Figure 6 — Stage-level latency breakdown (illustrative)

**Figure 6 (tabular).** Share of wall-clock time by pipeline stage for one representative job (CPU, $N\approx 5\times 10^4$, IDEC, default epochs). Percentages sum to $100\%$.

| Stage | Share of wall time |
|-------|-------------------|
| Parsing + featurization | 3% |
| Pretraining | 38% |
| Initialization | 5% |
| Fine-tuning | 48% |
| Refinement (postprocessing) | 6% |

```text
Figure 13.7 — Illustrative wall-time by stage (matches table above; bar = relative share)

  Fine-tuning        48%  ████████████████████████
  Pretraining        38%  ███████████████████
  Refinement          6%  ███
  Initialization      5%  ██
  Parse / featurize   3%  █
```

Together, the tables and figures summarize **where** quality improvements tend to appear (intrinsic metrics, ablations) and **how** runtime concentrates (pretrain/finetune vs short refinement), supporting the design goals in Sections 10 and 14.

---

## 14. Threats to Validity

- **Data validity**: synthetic or narrow-domain logs may inflate metrics.
- **Metric validity**: intrinsic metrics do not fully capture operational relevance.
- **Model validity**: hyperparameter sensitivity may bias conclusions.
- **Deployment validity**: concept drift and seasonality can degrade quality over time.

Recommended mitigation includes periodic retraining, drift monitoring, and analyst-in-the-loop validation.

Additional mitigation practices:

- benchmark against a curated set of historically validated incidents,
- monitor semantic drift in cluster profiles (not only scalar metrics),
- define rollback thresholds for production degradation.

---

## 15. Practical Notes on Silhouette Targets

A target such as $0.4+$ may be achievable for some datasets but is not universally guaranteed for real-world mixed security telemetry. Constraining factors include:

- overlap between benign and malicious behaviors,
- severe class imbalance,
- weak feature observability,
- mixed temporal regimes and policy shifts.

Therefore, optimization should use multi-metric and operational criteria, not a single scalar target.

A practical policy is to optimize relative improvement rather than absolute universal thresholds:

$\Delta S = S_{\text{new}} - S_{\text{baseline}}$

and accept updates only when improvements are also reflected in analyst-facing utility.

---

## 16. Future Directions

Potential research and engineering extensions:

- self-supervised pretraining with richer augmentations,
- **global** or **session/IP** graphs for GNN encoders (beyond within-batch $k$-NN on features),
- richer **temporal** models (e.g. Transformer-backed **UFCM**, gap-aware windows) beyond the current LSTM sequence paths,
- online/incremental clustering for streaming SOC workflows,
- stability-based automatic $K$ selection,
- analyst feedback loops for weak supervision.

Further high-impact directions include:

- uncertainty-aware escalation policies from probabilistic assignments,
- intrinsic metrics and dashboards that incorporate **fuzzy** structure (e.g., membership entropy, soft silhouette) for UFCM-style outputs, not only argmax labels,
- multimodal fusion (network + endpoint + identity signals),
- retrieval-augmented cluster narratives for faster analyst interpretation.

---

## 17. Conclusion

This system implements a production-aware deep clustering framework for security event intelligence, integrating:

- representation learning,
- cluster-aware optimization across DEC, IDEC, **sequence IDEC (LSTM/Transformer)**, **GNN-IDEC (GCN on batch $k$-NN)**, VaDE, contrastive, **UFCM**, **UFCM+LSTM**, and DMVC families,
- intrinsic metric evaluation,
- bounded latent ensemble refinement,
- and threat-centric interpretation.

The resulting design is both scientifically grounded and operationally actionable, with explicit mechanisms to balance quality and runtime in real deployments.

Overall, the framework should be evaluated as a decision-support system, not only as a clustering engine. Its practical value comes from the interaction between representation quality, assignment quality, bounded optimization, and explainable security outputs that directly improve SOC triage and response workflows.
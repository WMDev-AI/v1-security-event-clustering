# Project Reporter: Architecture, API, Classes, and Functions

This document describes the **Security Event Deep Clustering** codebase: system layout, HTTP API contracts, major classes, and important functions with parameters, behavior, and call flow. Paths are relative to the repository root.

---

## 1. High-level architecture

### 1.1 Components

| Layer | Location | Role |
|--------|-----------|------|
| API gateway | `backend/main.py` | FastAPI app mounted at `/api`; CORS; job orchestration; insight endpoints |
| Featurization | `backend/event_parser.py` | Parse `key=value` logs → `SecurityEvent` → fixed-length vectors ($d=70$) |
| Models & losses | `backend/deep_clustering.py` | PyTorch DEC / IDEC / VaDE / contrastive / **DeepUFCM** modules and loss helpers |
| Training & metrics | `backend/trainer.py` | `DeepClusteringTrainer`, `TrainingConfig`, `ClusteringMetrics`, latent refinement |
| Cluster narratives | `backend/cluster_analyzer.py` | `ClusterProfile`, per-cluster stats, summaries |
| SOC intelligence | `backend/security_insights.py` | `SecurityInsightsEngine`, MITRE-style insights, correlations |
| Frontend client | `frontend/lib/api.ts` | Typed fetch wrappers to `http://localhost:8000/api` (insights, IOCs, MITRE, MITRE events) |

### 1.2 Process layout

- **`app`** (`FastAPI`): all routes below are prefixed with **`/api`** when using `root_app` (uvicorn entry is typically `root_app` on port 8000).
- **In-memory state**: `training_jobs[job_id]` (dict progress), `trained_models[job_id]` (trained `trainer`, events, labels, latent, profiles, normalization stats).
- **Training** runs as a **background task**: `delayed_training` → `run_training` (async), so `/train` returns immediately with `job_id`.

### 1.3 End-to-end flow (code inspection)

1. Client **POST `/api/train`** with raw event strings → job queued → `run_training` parses via `parse_events_to_features` → `DeepClusteringTrainer.pretrain` → `initialize_clusters` → `finetune` → `predict` + `get_latent_representations` → `refine_cluster_assignments` → `analyze_clusters_from_results` → `trained_models[job_id]` populated.
2. Client **GET `/api/train/{job_id}`** polls `training_jobs[job_id]` until `status == "completed"`.
3. Client **GET `/api/results/{job_id}`** loads profiles and recomputes intrinsic metrics on latent vectors.

---

## 2. HTTP API reference

Base URL (default): `http://localhost:8000/api`

### 2.1 Summary table

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Service and device probe |
| GET | `/models` | List model types |
| POST | `/train` | Start training job |
| GET | `/train/{job_id}` | Training status / progress |
| GET | `/results/{job_id}` | Full analysis + metrics + 2D latent plot data |
| POST | `/predict` | Cluster new events with saved model |
| GET | `/cluster-events/{job_id}/{cluster_id}` | Paginated events in one cluster |
| GET | `/threat-indicator-events/{job_id}` | Paginated events from clusters that list a given threat indicator (query `indicator`) |
| POST | `/analyze` | Ad-hoc batch vs trained profiles |
| GET | `/demo` | Sample event strings |
| POST | `/upload` | Upload log file → event list |
| DELETE | `/job/{job_id}` | Remove job and cached model |
| GET | `/insights/{job_id}` | Full insights + correlations + summaries |
| GET | `/insights/{job_id}/cluster/{cluster_id}` | One cluster’s insights |
| GET | `/insights/{job_id}/iocs` | IOC-style extract |
| GET | `/insights/{job_id}/mitre` | MITRE-oriented mapping |
| GET | `/insights/{job_id}/mitre/events` | Paginated events matching one MITRE tactic, technique, or kill-chain filter |

### 2.2 `GET /health`

- **Request**: none.
- **Response** (JSON):
  - `status` — e.g. `"healthy"`.
  - `timestamp` — ISO8601 string.
  - `cuda_available` — boolean.
  - `device` — `"cuda"` or `"cpu"`.

### 2.3 `GET /models`

- **Request**: none.
- **Response**: `{ "models": [ { "id", "name", "description" }, ... ] }`  
  - `id`: `dec` | `idec` | `vade` | `contrastive` | `ufcm`.

### 2.4 `POST /train`

- **Request body** (`TrainingRequest`):
  - `events` (string[], required) — raw lines; **minimum 100** events.
  - `model_type` — `dec` | `idec` | `vade` | `contrastive` | `ufcm` (default `idec`).
  - `n_clusters` (int, 2–100) — must satisfy `n_clusters <= len(events) // 10`.
  - `latent_dim` (int, 8–256).
  - `hidden_dims` (int[]) — encoder/decoder widths.
  - `pretrain_epochs`, `finetune_epochs`, `batch_size`, `learning_rate`.
- **Response**: `{ "job_id": "<uuid>", "message": "Training started" }`.
- **Errors**: `400` with `detail` if validation fails.

### 2.5 `GET /train/{job_id}`

- **Request**: path `job_id`.
- **Response**: dict (job state). Aligns with `TrainingProgress` plus extra keys:
  - Core: `job_id`, `status` (`queued` | `parsing` | `training` | `completed` | `failed`), `progress` (0–100), `stage` (`pretraining` | `initialization` | `fine-tuning` | `postprocessing`, etc.), `stage_progress`, `current_epoch`, `total_epochs`, `stage_epoch`, `stage_total_epochs`, `current_loss`, `metrics`, `message`, `stages_completed`.
  - Often present: `model_type`, `n_events`, `n_clusters`, `created_at`.
  - After completion: `refinement` may mirror refinement info (`applied`, `method`, `elapsed_seconds`, `time_budget_hit`, etc.).
- **Errors**: `404` if unknown `job_id`.

### 2.6 `GET /results/{job_id}`

- **Request**: path `job_id`.
- **Response** (`AnalysisResponse`):
  - `total_events`, `n_clusters`.
  - `clusters`: array of `ClusterResult` (see §3.2).
  - `summary`: dict from `ClusterAnalyzer.generate_cluster_summary` (threat distribution, critical/high cluster ids, top indicators, sizes, etc.).
  - `intrinsic_metrics`: Silhouette, Davies–Bouldin, Calinski–Harabasz, cluster counts/sizes, etc., or null if not computable.
  - `latent_visualization`: `{ "points": [{ "x", "y", "cluster" }], "explained_variance": number[] }` (PCA-2D).
- **Errors**: `400` if training not completed; `404` if no results.

### 2.7 `POST /predict`

- **Request** (`PredictRequest`): `job_id`, `events` (string[]).
- **Response**: `{ "predictions": [ { "event_index", "cluster_id", "confidence", "probabilities", "event_summary" }, ... ] }`  
  - `probabilities`: per-cluster soft scores (list of float). For **UFCM**, these are **fuzzy membership** weights (non-negative, typically summing to $\approx 1$ per row, same shape as other models’ soft vectors).  
  - `event_summary`: subset of parsed fields.
- **Note**: Features are normalized with **batch** mean/std of the provided events (same helper as training path for new data).
- **Errors**: `404` if job/model missing.

### 2.8 `GET /cluster-events/{job_id}/{cluster_id}`

- **Query**: `page` (default 1), `limit` (default 30, max 100).
- **Response**: `job_id`, `cluster_id`, `total_events`, `page`, `limit`, `total_pages`, `events` (array of lightweight event dicts with `index`, `timestamp`, IPs, `dest_port`, `subsystem`, `action`, `severity`, `content`).
- **Errors**: `400` bad pagination; `404` unknown job or empty cluster.

### 2.8a `GET /threat-indicator-events/{job_id}`

- **Query**: `indicator` (required) — must **exactly match** a string that appears in some cluster profile’s `threat_indicators` (the same strings aggregated into `summary.top_threat_indicators`); `page` (default 1), `limit` (default 50, max 100).
- **Response**: `job_id`, `indicator`, `cluster_ids` (clusters whose profile includes that indicator), `total_events`, `page`, `limit`, `total_pages`, `events` (same row shape as §2.8).
- **Semantics**: Returns the union of all training events assigned to any matching cluster, sorted by global event index, paginated.
- **Errors**: `400` if `indicator` is missing/blank or pagination invalid; `404` if model missing.

### 2.9 `POST /analyze`

- **Request** (`AnalyzeRequest`): `job_id`, `events`.
- **Response**: `total_events`, `clusters_found`, `cluster_insights` (list with `cluster_id`, `event_count`, `threat_level`, indicators, recommendations, `matches_known_pattern`, optional `known_pattern_info`), `summary`, `high_priority_clusters` (threat `critical` or `high`).
- **Errors**: `404` if model missing.

### 2.10 `GET /demo`

- **Response**: `sample_events`, `total_samples`, `note`.

### 2.11 `POST /upload`

- **Request**: `multipart/form-data` with `file` (`.txt`, `.csv`, `.json` / JSONL).
- **Response** (`FileUploadResponse`): `filename`, `total_events`, `events` (full list as strings), `format_detected`, `sample_events`, `errors`.
- **Errors**: `400` for empty/invalid files.

### 2.12 `DELETE /job/{job_id}`

- **Response**: `{ "message": "Job deleted successfully" }`.
- **Errors**: `404` if nothing deleted.

### 2.13 `GET /insights/{job_id}`

- **Response** (`FullInsightsResponse`-shaped JSON): `job_id`, `total_events`, `total_clusters`, `insights` (list of insight objects), `correlations`, `executive_summary`, `threat_landscape`.
- **Semantics**: Built by grouping training events by cluster label, running `SecurityInsightsEngine.analyze_cluster_insights` per cluster, `find_cluster_correlations`, `generate_executive_summary`, and `_generate_threat_landscape`. See **§9** for measurement, risk, correlations, and IOC context.
- **Errors**: `400` / `404` if job incomplete or missing.

### 2.14 `GET /insights/{job_id}/cluster/{cluster_id}`

- **Response**: `cluster_id`, `event_count`, `profile` (nullable cluster profile dict), `insights`, `risk_assessment`, `sample_events`.
- **`risk_assessment`**: Output of `main._calculate_cluster_risk` for that cluster’s events (numeric `score`, categorical `level`, `factors`, `event_count`). See **§9.4**.
- **Errors**: `404` if cluster empty / missing.

### 2.15 `GET /insights/{job_id}/iocs`

- **Response**: IOC aggregation: `malicious_ips`, `attack_patterns`, `suspicious_users`, `firewall_rules`, counts, `generated_at`, etc.
- **Semantics**: Re-runs per-cluster insight extraction and folds `ioc_indicators` plus heuristic user blocking stats into a single export. See **§9.6**.
- **Errors**: `404` if model missing.

### 2.16 `GET /insights/{job_id}/mitre`

- **Response**: `tactics_coverage`, `techniques_detected`, counts, `kill_chain_analysis`, `coverage_assessment`, `mitigation_priorities`.
- **Errors**: `404` if model missing.

### 2.17 `GET /insights/{job_id}/mitre/events`

- **Purpose**: Return paginated **raw training events** whose cluster assignments fall under clusters mapped to a **single** MITRE filter (exactly one query parameter must be set).
- **Query** (provide **one** of):
  - `tactic` — enterprise tactic name string (must match keys used in internal tactic→cluster maps).
  - `technique` — technique label string as used in insight/MITRE rollups.
  - `kill_chain_stage` — normalized stage key (spaces → underscores, lowercased); must be one of the keys accepted by the server (see `main._mitre_kill_chain_stage_tactics`).
- **Pagination**: `page` (≥ 1), `limit` (1–200, default 50).
- **Response**: `filter_type`, `filter_value`, `cluster_ids` (clusters contributing to the filter), `total_events`, `page`, `limit`, `total_pages`, `events` (rows with `index`, `timestamp`, IPs, `dest_port`, `subsystem`, `action`, `severity`, truncated `content`).
- **Errors**: `400` if zero or more than one filter parameter is provided, unknown `kill_chain_stage`, or invalid `page`/`limit`; `404` if model missing.

---

## 3. API schema classes (Pydantic / dataclasses used in API)

These are defined in `backend/main.py` unless noted.

### 3.1 `ModelTypeEnum`

- **Values**: `DEC`, `IDEC`, `VADE`, `CONTRASTIVE`, `UFCM` → serialized as lowercase strings for JSON.

### 3.2 `TrainingRequest`

- Fields listed in §2.4. Used only as request body validation.

### 3.3 `PredictRequest` / `AnalyzeRequest`

- `job_id: str`, `events: list[str]`.

### 3.4 `TrainingProgress`

- Documented fields in §2.5. Actual runtime dict may include additional keys written in `run_training`.

### 3.5 `ClusterResult`

- `cluster_id`, `size`, `threat_level`, `primary_subsystems`, `primary_actions`, `threat_indicators`, `recommended_actions`, `top_source_ips`, `top_dest_ports`, `representative_events`.

### 3.6 `AnalysisResponse`

- Top-level analysis payload for `/results/{job_id}` (§2.6).

### 3.7 `FileUploadResponse`

- File upload outcome (§2.11).

### 3.8 Insight-related response models

- `InsightResponse`, `CorrelationResponse`, `FullInsightsResponse` — mirror structures returned by `get_security_insights` and related helpers.

---

## 4. Core orchestration functions (`backend/main.py`)

### 4.1 `parse_events_to_features(raw_events: list[str]) -> tuple[list[SecurityEvent], np.ndarray]`

- **Purpose**: Single entry for “strings → model input matrix”.
- **Parameters**: `raw_events` — list of raw log lines.
- **Behavior**: `parser.parse_events` → `event_to_features` per event → `np.float32` array → **per-column z-score** using this batch’s mean/std ($\epsilon=10^{-8}$).
- **Returns**: Parsed events and normalized feature matrix `X`.
- **Flow**: Called from `run_training`, `predict_clusters`, `analyze_events`, and any path that scores new data.

### 4.2 `run_training(job_id, raw_events, config, model_type)`

- **Purpose**: Full training pipeline for one job; updates `training_jobs[job_id]` throughout.
- **Parameters**:
  - `job_id` — UUID string.
  - `raw_events` — training corpus.
  - `config` — `TrainingConfig` dataclass.
  - `model_type` — `trainer.ModelType` enum.
- **Flow**:
  1. `parsing` → `parse_events_to_features` (on failure: `failed` + message, return).
  2. Build `DeepClusteringTrainer(input_dim, model_type, config)`.
  3. `pretraining` — async `pretrain_callback` updates epoch loss and progress (~0–50% overall).
  4. `initialization` — `initialize_clusters`; `init_callback` maps 0–100% stage to ~50–75% overall.
  5. `fine-tuning` — `finetune` with metric callback; overall progress uses same band as callback implementation.
  6. `postprocessing` — `predict` → `get_latent_representations` → `await refine_cluster_assignments(..., progress_callback=refine_progress_callback)` → `get_cluster_probabilities` (for **UFCM**, each row is **fuzzy membership** over clusters; **refined** hard `labels` may differ from `argmax(probs)` when refinement accepts a better partition).
  7. `analyze_clusters_from_results` → store `trained_models[job_id]` dict with `trainer`, `events`, `features`, `labels`, `latent`, `probs`, `refinement_info`, `profiles`, `summary`, `feature_mean`, `feature_std`.
  8. Mark `completed`, final `ClusteringMetrics.compute_all` on refined labels + latent.
- **Callbacks**: `refine_progress_callback` updates `stage_progress` and overall `progress` (95–100%), logs to stdout, `await asyncio.sleep(0.05)` for event-loop yield.

### 4.3 `delayed_training(job_id, events, config, model_type)`

- **Purpose**: `asyncio.sleep(2)` then `await run_training(...)`. Decouples HTTP response from immediate CPU spike.

### 4.4 Private helpers (insights / MITRE)

- `_generate_threat_landscape`, `_calculate_cluster_risk`, `_generate_firewall_rules`, `_analyze_kill_chain`, `_assess_mitre_coverage`, `_generate_mitre_mitigations` — build nested dicts for insight endpoints; parameters are insight lists, event groupings, or tactic/technique maps.

---

## 5. Training configuration and metrics (`backend/trainer.py`)

### 5.1 `ModelType` (Enum)

- Members: `DEC`, `IDEC`, `VADE`, `CONTRASTIVE`, `UFCM` (string values match API).

### 5.2 `TrainingConfig` (dataclass)

- **Key fields**: `hidden_dims`, `latent_dim`, `n_clusters`, `dropout`, pretrain/finetune epochs and batch sizes and learning rates, DEC/IDEC `alpha`, `gamma`, `update_interval`, `tol`, VaDE `beta`, contrastive `temperature`, **UFCM** `fuzziness_m` ($>1$, FCM fuzzifier, default `2.0`), `ufcm_recon_weight` (MSE reconstruction scale on $x$, default `0.1`), `weight_decay`, `device`.
- **`__post_init__`**: default `hidden_dims` to `[256, 128, 64]` if `None`.

### 5.3 `ClusteringMetrics`

- **Method**: `compute_all(labels_pred, labels_true=None, features=None) -> dict`
  - **Parameters**: `labels_pred` — required; `labels_true` — optional for NMI/ARI; `features` — typically latent matrix for Silhouette/DBI/CH.
  - **Returns**: floats for metrics where defined; `n_clusters_found`, `cluster_sizes`, `size_std`, `size_min`, `size_max`.

### 5.4 `DeepClusteringTrainer`

#### Instance variables

- `input_dim`, `model_type`, `config`, `device`, `model` (nn.Module), `history` (loss/metric lists), `is_pretrained`, `is_clusters_initialized`.

#### Methods (public / important)

| Method | Parameters | Role / flow |
|--------|------------|-------------|
| `__init__` | `input_dim`, `model_type`, `config` | `_create_model()`, move to device |
| `pretrain` | `data`, optional async `progress_callback(epoch, loss)` | AE or VAE or **UFCM** (autoencoder only) or contrastive pretrain; updates `history` |
| `initialize_clusters` | `data`, optional async `progress_callback(pct)` | Latent encoding + K-means or VaDE `initialize_gmm`; **UFCM** uses `DeepUFCM.initialize_clusters` (K-means on $z$ → `cluster_centers`); contrastive path has multi-init K-means with progress |
| `finetune` | `data`, optional `labels_true`, async `progress_callback(epoch, metrics)` | Main clustering loop; DEC/IDEC target distribution; **UFCM** batch loss $(u^m \odot d^2)$ mean + `ufcm_recon_weight` * MSE recon; periodic `_evaluate` |
| `refine_cluster_assignments` | `latent`, `initial_labels`, optional hyperparams, async `progress_callback` | Scaled latent; K-means/GMM/agglomerative trials; sampled Silhouette; time budget; returns best labels + info dict |
| `predict` | `data` | Hard labels from model soft assignments |
| `get_cluster_probabilities` | `data` | Soft assignment matrix |
| `get_latent_representations` | `data` | Encoder outputs $z$ |
| `get_cluster_centers` | — | DEC/IDEC/VaDE/**UFCM** centers if defined (`DeepUFCM.cluster_centers`) |
| `save_model` / `load_model` | path | Torch checkpoint |

#### Private helpers

- `_create_model`, `_pretrain_contrastive`, `_compute_target_distribution`, `_vade_loss`, `_evaluate`.

---

## 6. Deep clustering modules (`backend/deep_clustering.py`)

### 6.1 Module-level loss functions

| Function | Parameters | Meaning |
|----------|------------|---------|
| `reconstruction_loss` | `x`, `x_recon` | MSE reconstruction |
| `kl_divergence_loss` | `q`, `p` | KL for DEC target distribution |
| `vae_loss` | `x`, `x_recon`, `mu`, `logvar`, `beta` | ELBO-style loss |
| `cluster_assignment_entropy` | `q` | Entropy regularizer for soft assignments |

### 6.2 `BaseAutoEncoder` (ABC)

- **Abstract**: `encode`, `decode`; **`forward`**: returns `(z, x_recon)`.

### 6.3 `SecurityEventAutoEncoder`

- **Members**: `input_dim`, `hidden_dims`, `latent_dim`, `activation`, `encoder` (`Sequential`), `decoder` (`Sequential`).
- **Methods**: `encode`, `decode`, `forward`.

### 6.4 `VariationalAutoEncoder`

- **Members**: `encoder_base`, `fc_mu`, `fc_logvar`, `decoder`, `training_mode`.
- **Methods**: `reparameterize`, `encode` (sampling), `encode_with_params`, `decode`, `forward` (returns z, recon, mu, logvar).

### 6.5 `ClusteringLayer`

- **Members**: `n_clusters`, `alpha`, `cluster_centers` (`nn.Parameter`).
- **Methods**: `forward` (Student-t soft assignments `q`), `get_target_distribution` (sharpened `p`).

### 6.6 `DeepEmbeddedClustering`

- **Members**: `autoencoder`, `clustering_layer`, `n_clusters`, `latent_dim`.
- **Methods**: `encode`, `forward` → `(q, z, x_recon)`, `initialize_clusters` (K-means on latent to set centers).

### 6.7 `ImprovedDEC`

- **Members**: `dec` (nested `DeepEmbeddedClustering`), `gamma`.
- **Methods**: delegate `forward`, `encode`, `initialize_clusters`; `clustering_layer` / `autoencoder` properties.

### 6.8 `VaDE`

- **Members**: `vae`, `pi`, `mu_c`, `logvar_c`, `n_clusters`, `latent_dim`.
- **Methods**: `forward` → z, recon, mu, logvar, `gamma`; `get_gamma`; `encode`; `initialize_gmm` (K-means + variance/mixture init).

### 6.9 `ContrastiveDeepClustering`

- **Members**: `encoder` (subset of autoencoder), `projection_head`, `cluster_head`, `n_clusters`, `temperature`.
- **Methods**: `encode`, `forward` → `(z, proj, cluster_prob)`, `contrastive_loss(proj1, proj2)` (NT-Xent-style).

### 6.10 `DeepUFCM`

- **Purpose**: **Deep Unconstrained Fuzzy C-Means** — fuzzy clustering in **latent space** with the UC-FCM-style reduction (optimal fuzzy memberships as a function of centers, objective minimized by gradient descent over centers and encoder). See **§6A** for narrative and formulas.
- **Members**: `autoencoder` (`SecurityEventAutoEncoder`), `cluster_centers` (`nn.Parameter`, shape `[n_clusters, latent_dim]`), `n_clusters`, `latent_dim`, `fuzziness_m` (Python float, must be $>1$).
- **Methods**:
  - `encode(x)` → $z$.
  - `squared_distances(z)` → $\lVert z_i - v_k\rVert_2^2$ per batch element.
  - `fuzzy_membership(z)` → `(u, sq)` where $u_{ik}$ are standard **FCM** memberships from Euclidean distances (rows sum to $1$).
  - `ufcm_objective(z)` → batch mean of $\sum_k u_{ik}^{m} d_{ik}^2$ (used where a single scalar is needed; `trainer.finetune` inlines one membership pass per batch for efficiency).
  - `forward(x)` → `(u, z, x_recon)` with `u` from `fuzzy_membership(z)`.
  - `initialize_clusters(data_loader, device)` — full pass for $z$, **sklearn KMeans** on $z$, copy centroids into `cluster_centers`; returns hard K-means labels (for logging only; fine-tuning then optimizes fuzzy objective).

---

## 6A. UFCM — extended reference (algorithm, stack integration, and semantics)

This subsection is the **reporter-facing** companion to `docs/research.md` §6.5: same ideas, but tied to **files, API fields, and runtime behavior** in this repository.

### 6A.1 What problem UFCM addresses here

Security events often sit **between** behavioral prototypes (mixed tactics, noisy firewalls, auth storms that resemble credential attacks). **Hard** clustering forces one label per event; **fuzzy** clustering keeps a **distribution over clusters** per event. The implementation exposes that distribution through the same **`probs`** / **`probabilities`** channels as other models (`trainer.get_cluster_probabilities`, `trained_models[job_id]["probs"]`, `/predict` payloads). **Discrete** `labels` stored after training are produced by **latent ensemble refinement** starting from the model’s hard predictions (for UFCM, **argmax** of $u$ on the training forward pass); refinement may **change** some labels to improve intrinsic scores, so **`labels` need not equal `argmax(probs)`** row-wise. Profiles, insights, and displayed metrics use these **refined** `labels`; `probs` remain the **last forward-pass** soft matrix from the neural module (§6A.5, §4.2 step 6).

### 6A.2 Classical FCM membership (what the code implements)

For batch latent vectors $z_i$ and centers $v_k$, let $d_{ik}=\lVert z_i-v_k\rVert_2$ (with numerical flooring). Fuzziness $m>1$. Then:

$u_{ik}=\dfrac{1}{\sum_{j=1}^{K}\left(\dfrac{d_{ik}}{d_{ij}}\right)^{\frac{2}{m-1}}}$

Objective contribution per sample: $\sum_{k=1}^{K} u_{ik}^{m}\, d_{ik}^{2}$ (with $d_{ik}^2$ the squared distance). This matches the **standard FCM** membership at fixed centers; **UC-FCM** in the literature substitutes this $U^\star(V)$ into the full objective and optimizes **$V$** (here also $\theta$ for the encoder) by **gradient descent** instead of alternating full matrix updates. This codebase follows that **substitution + autograd** pattern in `DeepClusteringTrainer.finetune` for `ModelType.UFCM`.

### 6A.3 Loss actually optimized in `trainer.py` (fine-tuning)

Per batch:

- $\mathcal{L}_{\mathrm{UFCM}} = \frac{1}{|\mathcal{B}|}\sum_{i\in\mathcal{B}}\sum_{k} u_{ik}^{m}\, d_{ik}^{2}$ with $u$ computed from current $z$ and `cluster_centers`.
- $\mathcal{L}_{\mathrm{rec}} = \mathrm{MSE}(x,\hat{x})$ from the autoencoder decode path.
- $\mathcal{L} = \mathcal{L}_{\mathrm{UFCM}} + \gamma_{\mathrm{ufcm}}\,\mathcal{L}_{\mathrm{rec}}$ with $\gamma_{\mathrm{ufcm}} =$ `TrainingConfig.ufcm_recon_weight`.

**Pretraining** uses **only** reconstruction on the UFCM autoencoder (same pattern as DEC/IDEC backbone). There is **no** DEC-style target distribution or KL term for UFCM.

### 6A.4 Configuration surface (today)

| Knob | Type | Default | Where |
|------|------|---------|--------|
| `fuzziness_m` | float | `2.0` | `TrainingConfig`; must be $>1$ (`DeepUFCM` raises if not). |
| `ufcm_recon_weight` | float | `0.1` | `TrainingConfig`; scales reconstruction vs fuzzy objective. |

These are **not** yet exposed on the public `TrainingRequest` Pydantic model in `main.py`; jobs started via API use defaults unless the server code is extended. The **React** training UI exposes `model_type: "ufcm"` in the model `Select` and `TrainingRequest` TypeScript union (`frontend/lib/api.ts`, `training-config.tsx`).

### 6A.5 API and persistence behavior

- **`GET /api/models`**: includes an entry with `id: "ufcm"` and a short description (see `list_models` in `main.py`).
- **`POST /api/train`**: `model_type: "ufcm"` selects `ModelType.UFCM` → `DeepUFCM` inside `_create_model`.
- **`trained_models[job_id]["probs"]`**: rows are fuzzy memberships for the **training** feature matrix (shape `[N, K]`). After refinement, **`labels`** reflect the **refined** hard partition; **`probs`** remain those from **`get_cluster_probabilities`** on the **base** model before replacement by refinement labels — operators should treat **`labels`** as canonical for cluster IDs in profiles while using **`probs`** as **model-native softness** (this matches other models’ interaction with refinement; see `run_training` ordering in §4.2).

### 6A.6 How UFCM differs from other families (quick matrix)

| Aspect | DEC / IDEC | VaDE | Contrastive | **UFCM** |
|--------|------------|------|-------------|----------|
| Soft output | Student-$t$ $q$, KL to $p$ | GMM posterior $\gamma$ | `cluster_head` softmax | **FCM** $u_{ik}$ from distances |
| Latent geometry pressure | KL (+ recon IDEC) | ELBO + mixture | Contrastive + consistency | **Weighted fuzzy distortion** + recon |
| Centers | `ClusteringLayer` params | `mu_c` | implicit in head | **`cluster_centers`** in $\mathbb{R}^{m}$ |

### 6A.7 Analyst and metrics caveats

- **Silhouette / DBI / CH** in `/results` and job completion metrics are computed on **hard** labels and **latent** features; they **do not** encode full fuzzy overlap. High **entropy** of a row of `probs` can still flag “borderline” events in custom tooling.
- **Security insights** (`§9`) consume **cluster_id** from hard labels only; they do not currently consume fuzzy weights.

### 6A.8 Reference publication

For citations and equivalence claims to **UC-FCM**, use the TPAMI 2025 paper (DOI `10.1109/TPAMI.2025.3532357`). Full theoretical discussion: `docs/research.md` §6.5–6.6.

---

## 7. Event parsing (`backend/event_parser.py`)

### 7.1 `SecurityEvent` (dataclass)

- **Core**: `timestamp`, `source_ip`, `dest_ip`, `dest_port`, `source_port`, `subsystem`, `user`, `action`, `severity`, `content`, `protocol`, `raw_data`.
- **Subsystem-specific**: WAF/webfilter (`url`, `response_code`, `reason`, …), IPS (`rule_id`, `rule_name`, `attack_type`), VPN, mail/DLP, proxy, DNS, AV/sandbox, DDoS, firewall zones/policy, etc. (see class body).

### 7.2 `EventParser`

#### Class-level data

- `FIELD_MAPPINGS`, `SUBSYSTEM_FIELD_MAPPINGS`, `KNOWN_SUBSYSTEMS`, `KNOWN_ACTIONS`, `SEVERITY_LEVELS`, `CONTENT_KEYWORD_GROUPS`, compiled regex patterns.

#### Methods

| Method | Parameters | Purpose / flow |
|--------|------------|----------------|
| `parse_event` | `raw_event: str` | Regex key=value scan; subsystem detection; fills `SecurityEvent` |
| `parse_events` | `raw_events: list[str]` | List comprehension over `parse_event` |
| `_set_subsystem_field` | `event`, `field_name`, `value`, `subsystem` | Typed assignment for extended fields |
| `_is_float` | `value: str` | Parse guard |
| `_stable_hash_to_unit` | `value: str`, `modulo: int` | MD5 bucket → $[0,1]$ for stable categoricals |
| `ip_to_features` | `ip: str` | Octets + private flag (5 dims) |
| `port_to_features` | `port: int` | Normalized port + category flags (4 dims) |
| `subsystem_to_features` | `subsystem: str` | Multi-label-style over known list (15 dims) |
| `action_to_features` | `action: str` | Block/allow/alert/other (4 dims) |
| `severity_to_feature` | `severity: str` | Single scalar |
| `timestamp_to_features` | `timestamp: str` | Cyclic hour sin/cos, DOW, business hours (4 dims) |
| `content_to_features` | `content: str` | Keyword groups + token + punctuation density |
| `event_to_features` | `event: SecurityEvent` | Concatenates all blocks + `_extract_subsystem_features` |
| `_extract_subsystem_features` | `event` | Up to 12 dims, padded |
| `get_feature_dim` | — | Returns `70` |

---

## 8. Cluster analysis (`backend/cluster_analyzer.py`)

### 8.1 `ClusterProfile` (dataclass)

- **Fields**: `cluster_id`, `size`, `primary_subsystems`, `primary_actions`, `severity_distribution`, `top_source_ips`, `top_dest_ips`, `top_dest_ports`, `peak_hours`, `weekend_ratio`, `business_hours_ratio`, `top_users`, `has_user_ratio`, `content_keywords`, `threat_level`, `threat_indicators`, `recommended_actions`, `representative_events`.

### 8.2 `ClusterAnalyzer`

- **Class constants**: `SUSPICIOUS_PORTS`, `THREAT_KEYWORDS`.
- **Instance**: `parser: EventParser`.
- **Methods**:
  - `analyze_cluster(events, cluster_id, latent_centroid=None)` — aggregates counters, content tokens, threat assessment, representatives → `ClusterProfile`.
  - `generate_cluster_summary(profiles)` — dataset-level summary dict.
- **Private**: `_assess_threat`, `_assess_subsystem_threats`, `_generate_recommendations`, `_select_representatives`.

### 8.3 `analyze_clusters_from_results(events, labels, latent_features=None)`

- **Purpose**: Stateless convenience wrapper: groups by label, optional latent centroid per cluster, `analyze_cluster` per id, then `generate_cluster_summary`.
- **Returns**: `(list[ClusterProfile], summary_dict)`.

---

## 9. Security analytics: insights, risk, correlations, attack-chain hints, and IOCs

This section documents **`backend/security_insights.py`** and the **API-layer** helpers in **`backend/main.py`** that turn clustered events into SOC-oriented narratives. Everything here is **heuristic and rule-based** unless noted; it does not use the neural clustering loss.

### 9.1 Dataclasses (`security_insights.py`)

| Type | Main fields | Role in API |
|------|-------------|-------------|
| **`SecurityInsight`** | `insight_id`, `category` (`attack`, `policy_violation`, `anomaly`, `reconnaissance`, …), `title`, `description`, `severity` (`critical`…`info`), `confidence` (float, template-assigned), `event_count`, `sample_events`, `affected_subsystems`, `source_ips`, `target_assets`, `mitre_tactics`, `mitre_techniques`, `immediate_actions`, `long_term_actions`, `related_clusters`, `ioc_indicators` | One **actionable narrative** attached to evidence; serialized in `/insights/*` responses. |
| **`ClusterCorrelation`** | `cluster_a`, `cluster_b`, `correlation_type`, `correlation_strength`, `shared_indicators`, `description` | Pairwise **hypothesis** between clusters (see §9.5). |
| **`AttackPattern`**, **`ThreatActor`**, **`AnomalyScore`** | Various | Defined for richer modeling; primary HTTP payloads today center on **`SecurityInsight`** and summaries built from them. |

### 9.2 `SecurityInsightsEngine` — processing pipeline

**Class data**

- **`MITRE_MAPPINGS`**: lowercase keyword → `(tactic_name, technique_label)`; used when building `mitre_tactics` / `mitre_techniques` on specific insight templates (not a learned classifier).
- **`SUSPICIOUS_PORTS`**: port → `(service_name, severity_hint)` for narrative and severity flavor.
- **`PRIVATE_RANGES`**: RFC1918-style networks for `_is_external_ip`.

**`analyze_cluster_insights(cluster_id, events, latent_features=None)`**

1. **`_collect_cluster_stats`**: single pass over `events` → counters for subsystems, actions, severities, source/dest IPs, dest ports, users, hours, `content_words` (regex tokens), protocols, block/allow counts, internal vs external sources, timestamps list.
2. **Detectors** (each may append zero or more `SecurityInsight`):
   - `_detect_attack_patterns` → brute force, web attack, DDoS, malware/C2 heuristics (`_is_*` + `_create_*_insight`).
   - `_detect_policy_violations` → unauthorized access, data-policy style patterns.
   - `_detect_anomalies` → temporal and volume anomalies.
   - `_detect_reconnaissance` → scan/probe style signals.
   - `_detect_data_exfiltration` → exfiltration-style content/volume cues.
3. **`latent_features`**: reserved for future use; current templates rely on **parsed fields + content stats**, not on $Z$.

**`generate_executive_summary(all_insights, cluster_count, total_events)`**

- Aggregates severity and category histograms; lists top critical/high findings with snippets; collects unique MITRE tactics/techniques from insights; counts IP-type IOCs; calls **`_generate_priorities`** (severity-driven + title-keyword rules such as Brute Force / Web Application / DDoS / Exfiltration).

### 9.3 Security insights — measurement and interpretation

An insight is **measured** for SOC purposes along several auditable axes (no single scalar in the API):

| Axis | Source fields | How to use |
|------|----------------|------------|
| **Coverage** | Count of insights per cluster; `executive_summary.overview.insights_generated` | Low count may mean quiet cluster or weak keyword match; cross-check raw event volume. |
| **Severity** | `severity` | Drives triage ordering; should be cross-checked against `sample_events`. |
| **Evidence mass** | `event_count` vs cluster size | Large `event_count` relative to cluster supports stronger claims. |
| **Confidence** | `confidence` | Template constant or heuristic; treat as **relative** ranking, not calibrated probability. |
| **Traceability** | `sample_events`, `source_ips`, `target_assets` | Trace back to raw logs before enforcement. |
| **Actionability** | `immediate_actions`, `long_term_actions`; `recommended_priorities` in executive summary | Map to tickets/owners; executive list is **global** synthesis. |

**MITRE fields**: Populated from **`MITRE_MAPPINGS`** and hard-coded strings in `_create_*_insight` methods (e.g. brute force → Credential Access / T1110). Validate against source events when auditing.

### 9.4 Cluster risk assessment (API layer)

Distinct from per-insight severity: **`main._calculate_cluster_risk(events)`** scores **all events in one cluster** with a **transparent additive model** (cap 100), then maps to `level` ∈ {`critical`, `high`, `medium`, `low`}.

**Contributions (conceptual)**

- **High block rate**: if fraction of events with action in {blocked, denied, drop} **> 0.8** → add points; factor string recorded.
- **Severity histogram**: increments for `critical` and `high` event severities; factors name counts.
- **Subsystem cues**: `ips`/`ids` or `ddos` in subsystem string → fixed bonuses.
- **Content keywords**: if share of events whose `content` contains any of {attack, exploit, malware, intrusion, breach} **> 0.1** → bonus; factor recorded.

**Return shape**: `{ "score", "level", "factors", "event_count" }`.

**Where it appears**

- **`GET /insights/{job_id}/cluster/{cluster_id}`** → `risk_assessment`.
- **`threat_landscape.cluster_risk_scores`** in **`GET /insights/{job_id}`** — dict keyed by `cluster_id` string with the same structure per cluster.

This risk score is **independent** of Silhouette or deep model loss; it summarizes **log semantics** inside the cluster.

### 9.5 Cluster correlations and attack-chain hints

**`find_cluster_correlations(cluster_profiles, events_by_cluster)`** compares **unordered pairs** of clusters $(a,b)$ using sets of **source** and **destination** IPs from parsed events (not from insights).

Let $S_k$ = set of `source_ip` values in cluster $k$, $T_k$ = set of `dest_ip` values.

| `correlation_type` | Condition | `correlation_strength` | Meaning |
|--------------------|-----------|-------------------------|---------|
| **`same_source`** | $S_a \cap S_b \neq \emptyset$ | $\|S_a \cap S_b\| / \max(\|S_a\|, \|S_b\|)$, emitted only if **> 0.1** | Shared origin IPs across behavioral groups. |
| **`same_target`** | $T_a \cap T_b \neq \emptyset$ | $\|T_a \cap T_b\| / \max(\|T_a\|, \|T_b\|)$, only if **> 0.1** | Same victims/services touched from different clusters. |
| **`attack_chain`** | $S_a \cap T_b \neq \emptyset$ | $\|S_a \cap T_b\| / \|S_a\|$ | **Hypothesis**: actors (sources) in cluster $a$ appear as **targets** in $b$ (e.g. pivot); not proof of temporal ordering. |

**`shared_indicators`**: up to 5 sample IPs from the intersection. **`description`**: human-readable summary.

**Operational note**: NAT, scanners, and load balancers create false overlaps; correlate with timestamps and asset inventory before incident declaration.

### 9.6 IOC extraction and evaluation (`GET /insights/{job_id}/iocs`)

**Flow (`get_indicators_of_compromise`)**

1. Group all training `events` by final cluster label.
2. For each cluster, call `analyze_cluster_insights` (same as full-insights path).
3. **IP IOCs**: for each insight, for each element of `ioc_indicators` with `type == "ip"`, aggregate by IP:
   - append `context` strings (deduped later),
   - add `insight.event_count` into a running **event_count** (approximate weighting),
   - promote stored `severity` to `critical`/`high` if any contributing insight has that severity.
4. **Attack patterns**: insights with `category == "attack"` → list entries with title, description excerpt, MITRE techniques, sample `source_ips`, severity.
5. **Suspicious users**: across **all** events (not per cluster), users where **> 50%** of their events have action blocked/denied → `suspicious_users` with reasons.
6. **`firewall_rules`**: `main._generate_firewall_rules` suggests block lists / rate limits / WAF toggles from aggregated IOC structure (advisory only).

**Response highlights**: `generated_at`, `malicious_ips` (sorted by event_count, capped), `attack_patterns`, `suspicious_users`, `firewall_rules`, `total_unique_threat_ips`, `total_attack_patterns`.

**How to evaluate IOC quality in operations**

- **Provenance**: jump from IP row to originating insights and samples before blocking.
- **Stale data**: IOCs reflect the **trained job snapshot**; retrain or refresh after major log or policy changes.
- **False positives**: shared egress IPs and CDNs inflate “malicious” lists; enrich with ownership and reputation feeds.
- **Automation**: treat `firewall_rules` as **draft** change requests, not auto-applied production policy.

### 9.7 Related API entry points (summary)

| Endpoint | Primary content |
|----------|-----------------|
| `GET /insights/{job_id}` | Flattened `insights`, `correlations`, `executive_summary`, `threat_landscape` (includes `cluster_risk_scores`). |
| `GET /insights/{job_id}/cluster/{cluster_id}` | One cluster’s `insights`, `risk_assessment`, `profile`, `sample_events`. |
| `GET /insights/{job_id}/iocs` | Aggregated IOCs and suggested rules (§9.6). |
| `GET /insights/{job_id}/mitre` | Recomputes insights and builds tactic/technique rollups, kill-chain narrative, mitigation suggestions (`main` helpers). |
| `GET /insights/{job_id}/mitre/events` | Events whose clusters match one tactic, technique, or kill-chain stage filter (§2.17). |

---

## 10. Frontend API layer (`frontend/lib/api.ts`)

- **Constants**: `API_BASE = 'http://localhost:8000/api'`.
- **Interfaces**: `TrainingRequest`, `TrainingProgress`, `SecurityEvent`, `ClusterResult`, `FileUploadResponse`, `AnalysisResponse`, plus extended types for insights, IOCs, MITRE (`InsightsResponse`, `IOCsResponse`, `MITREResponse`, etc.).
- **Functions**: `startTraining`, `getTrainingStatus`, `getResults`, `getClusterEvents`, `getThreatIndicatorEvents`, `getDemoEvents`, `uploadEventLog`, `getModels`, `checkHealth`, `getSecurityInsights`, `getClusterInsights`, `getIOCs`, `getMITREMapping`, `getMITREEvents` — each maps to the corresponding REST path documented in §2 (including §2.8a and §2.17).

---

## 11. Quick reference: `trained_models[job_id]` payload

| Key | Type / meaning |
|-----|----------------|
| `trainer` | `DeepClusteringTrainer` instance |
| `events` | List of `SecurityEvent` used for training |
| `features` | Normalized numpy training matrix |
| `labels` | Final integer labels (after refinement) |
| `latent` | Latent matrix $Z$ |
| `probs` | Soft assignment matrix |
| `refinement_info` | Dict from `refine_cluster_assignments` (silhouette before/after, applied flag, method, timing, etc.) |
| `profiles` | `list[ClusterProfile]` |
| `summary` | Summary dict |
| `feature_mean`, `feature_std` | Vectors used conceptually for consistent normalization (training batch stats) |

---

## 12. Frontend UI components, workflow, interactions, and event handling

This section documents the **React** (Webpack-bundled SPA) frontend under `frontend/`: HTML shell, the main page state machine, child components, user-driven events, and how they call `frontend/lib/api.ts`.

### 12.1 Technology stack and entry points

| Item | Location | Notes |
|------|-----------|--------|
| HTML shell | `frontend/public/index.html` | `#root`, `class="dark"` on `<html>`, Google Fonts (`Inter`, `JetBrains Mono`). |
| Bootstrap | `frontend/src/index.tsx` | `createRoot` → `<App />`, imports `src/globals.css`. |
| Main UI | `frontend/src/App.tsx` | Interactive logic and API polling. |
| API client | `frontend/lib/api.ts` | `fetch` wrappers; base URL `http://localhost:8000/api`. |
| Visualization shell | `frontend/components/visualization-tab.tsx` | `React.lazy` + `Suspense` around `ClusterVisualization`; Progress fallback (§12.9a). |
| IOC downloads | `frontend/lib/ioc-export.ts` | JSON/CSV/firewall-text exports for IOCs tab (§12.9b). |
| Threat Analysis tab | `frontend/components/threat-analysis.tsx` | Event popups for top indicators (§2.8a) and priority clusters (§2.8). |
| Shared UI | `frontend/components/ui/*` | shadcn-style primitives (`Button`, `Card`, `Tabs`, `Badge`, `Progress`, `ScrollArea`, `Slider`, `Select`, `Tooltip`, etc.). |

### 12.2 Application state machine (`AppState`)

The root component `App` uses:

`type AppState = 'idle' | 'configuring' | 'training' | 'completed' | 'error'`

| State | When set | Primary UI |
|--------|-----------|------------|
| `idle` | Initial; after reset | Hero, feature cards, subsystem badges; **Get Started** (disabled if backend offline). |
| `configuring` | User clicks Get Started | **Back** clears upload metadata; **EventLogUpload**; after upload, **TrainingConfig**. |
| `training` | After `startTraining` succeeds | **TrainingProgress** (requires `progress` object from first poll). |
| `completed` | Poll sees `status === 'completed'` and `getResults` succeeds | Summary metrics, intrinsic metric cards, tabbed results. |
| `error` | `startTraining` throws, or poll sees `failed`, or other hard failures | Error card + **Try Again** (`handleReset`). |

### 12.3 Root component state variables (`App.tsx`)

| State | Type | Purpose |
|-------|------|---------|
| `state` | `AppState` | Drives which main block renders. |
| `backendStatus` | `'checking' \| 'online' \| 'offline'` | Header badge; from `checkHealth()` on mount. |
| `deviceInfo` | `string` | e.g. `cpu` / `cuda` from health response. |
| `sampleEvents` | `string[]` | Loaded from `getDemoEvents()` (available for future use; primary path is file upload). |
| `loadedEvents` | `string[]` | Events passed from upload into `TrainingConfig`. |
| `uploadedFilename` | `string` | Shown as “uploaded”; gating Step 2. |
| `jobId` | `string \| null` | Returned by `POST /train`; triggers polling. |
| `progress` | `TrainingProgress \| null` | Latest job status from `getTrainingStatus`. |
| `results` | `AnalysisResponse \| null` | From `getResults(jobId)` when training completes. |
| `insights` | `InsightsResponse \| null` | From `getSecurityInsights(jobId)` after results. |
| `insightsLoading` | `boolean` | While insights request in flight. |
| `resultsTab` | `string` | Active results tab (`insights` \| `visualization` \| `clusters` \| `threats`); **controlled** `Tabs` value so heavy UI mounts only when needed (§12.9a). Reset to `insights` when `jobId` changes. |
| `error` | `string \| null` | User-visible error message. |

### 12.4 Effects and async workflow

**Mount (`useEffect`, empty deps)**

1. `checkHealth()` → on success: `backendStatus = 'online'`, `deviceInfo = health.device`.
2. `getDemoEvents()` → `setSampleEvents(demo.sample_events)`.
3. On failure: `backendStatus = 'offline'` (demo load skipped if health throws).

**Training poll (`useEffect` deps: `[jobId, state]`)**

Runs only when `jobId` is set **and** `state === 'training'`.

1. **Concurrency guard**: `isPolling` flag avoids overlapping polls.
2. **Abort**: creates `AbortController` per tick; passes `signal` to `getTrainingStatus(jobId, signal)` so an in-flight request is aborted when the effect cleans up or a new tick starts.
3. **Interval**: `setInterval(poll, 1500)` plus **immediate** `poll()` on subscribe.
4. **On `status === 'completed'`**: `getResults(jobId)` → `setResults`, `setState('completed')`; then `getSecurityInsights(jobId)` with `insightsLoading` true/false (errors logged, non-fatal).
5. **On `status === 'failed'`**: `setError(status.message)`, `setState('error')`.
6. **Fetch errors**: `AbortError` ignored; others `console.error`.
7. **Cleanup**: `clearInterval`, `abortController.abort()`.

### 12.5 Root-level event handlers

| Handler | Trigger | Behavior |
|---------|---------|----------|
| `handleStartTraining(config)` | `TrainingConfig` submit | Clears error/results; `setState('training')`; `startTraining(config)` → `setJobId(job_id)`; on catch sets error + `error` state. |
| `handleReset` | **New Analysis** / **Try Again** | Resets to `idle`, clears `jobId`, `progress`, `results`, `insights`, loading, `error`. |
| `formatMetric(value)` | Render intrinsic metrics | Returns `'N/A'` if undefined, negative, or NaN; else fixed decimals. |
| Inline **Get Started** | Button click | `setState('configuring')` (disabled when backend not online). |
| Inline **Back** (configuring) | Button click | `setState('idle')`, clear `loadedEvents`, `uploadedFilename`. |

### 12.6 `EventLogUpload` (`frontend/components/event-log-upload.tsx`)

**Props**

- `onEventsLoaded?: (events: string[], filename: string) => void` — parent stores corpus + filename.

**Local state**

- `uploading`, `uploadResult`, `error`; `fileInputRef` for resetting input.

**Interactions**

| Event | Handler | Flow |
|-------|-----------|------|
| File chosen | `handleFileSelect` (`ChangeEvent<HTMLInputElement>`) | `uploadEventLog(file)` → `setUploadResult`; call `onEventsLoaded(result.events, result.filename)`; clear input value in `finally`. |
| Drag over | `handleDragOver` | `preventDefault` / `stopPropagation` so drop works. |
| Drop | `handleDrop` (`DragEvent`) | Same API path as file select for `files[0]`. |
| Tabs | Radix `Tabs` | **Upload File** vs **Supported Formats** (static help). |

### 12.7 `TrainingConfig` (`frontend/components/training-config.tsx`)

**Props**

- `onSubmit(config: TrainingRequest)`, `isLoading`, optional `sampleEvents`, `preloadedEvents`, `preloadedFilename`.

**Local state**

- `events` (textarea content synced from `preloadedEvents` via `useEffect`), `modelType` (`'dec' \| 'idec' \| 'vade' \| 'contrastive' \| 'ufcm'`), `nClusters`, `latentDim`, `pretrainEpochs`, `finetuneEpochs`, `showAdvanced`.

**Validation**

- `eventLines = events.trim().split('\n').filter(...)`; `eventCount >= 100` **and** `preloadedFilename` required for `isValid` (matches backend minimum event rule).

**Submit (`handleSubmit`)**

Builds `TrainingRequest`: fixed `hidden_dims: [256,128,64]`, `batch_size = clamp(floor(eventCount/10), 32, 256)`, `learning_rate: 0.001`, plus UI-controlled fields → `onSubmit(config)`.

**UI**

- Model `Select` (options driven from `MODEL_INFO`, including **UFCM** with tooltip copy), sliders for hyperparameters, tooltips (`TooltipProvider`), optional advanced section, **Start Training** disabled when `!isValid`.

### 12.8 `TrainingProgress` (`frontend/components/training-progress.tsx`)

**Props**

- `progress: TrainingProgress` (from API).

**Behavior**

- Animated progress bar synced to `progress.progress` via short timeout.
- Stage checklist: pretraining, initialization, fine-tuning, **Refining cluster assignments** (`stage === 'postprocessing'` shows dedicated bar and percent).
- Shows epoch, loss, stage; optional `metrics` preview (e.g. silhouette); spinner when status is training-like.

### 12.9 `ClusterVisualization` (`frontend/components/cluster-visualization.tsx`)

**Props**

- `data: AnalysisResponse`.

**Behavior**

- `useMemo` transforms: PCA scatter from `latent_visualization.points`, threat pie/bar data from `summary.threat_distribution`, cluster sizes, subsystem aggregation.
- **Scatter performance**: if `points.length` exceeds a fixed cap (4,000), the component **evenly subsamples** points for rendering so Recharts does not block the main thread on very large jobs; the card description notes how many points are shown vs total.
- Renders **Recharts** (`ScatterChart`, `PieChart`, `BarChart`, etc.) inside `Card` components — read-only; tooltips via Recharts only.
- Loaded **only** through the lazy shell in §12.9a (not in the main bundle’s eager graph).

### 12.9a Lazy-loaded visualization shell (`App.tsx`, `visualization-tab.tsx`)

- **`react.lazy`** + **`Suspense`** wrap `ClusterVisualization` in `frontend/components/visualization-tab.tsx`. The Recharts-heavy module is emitted as a **separate Webpack chunk**, so initial load stays smaller.
- **Fallback UI**: card with short copy and a **Progress** bar whose value animates while the chunk loads and charts initialize.
- **`App.tsx`** uses **controlled** `Tabs` (`value={resultsTab}`, `onValueChange={setResultsTab}`). The visualization panel renders `<VisualizationTab data={results} />` **only when** `resultsTab === 'visualization'` **and** results exist, so inactive tabs do not mount the chart tree (Radix would otherwise keep hidden content mounted).
- **`useEffect` on `jobId`**: resets `resultsTab` to `insights` when the training job changes so users do not stay on a stale Visualization tab.

### 12.9b IOC export helpers (`frontend/lib/ioc-export.ts`)

- **Purpose**: Client-side downloads for the **IOCs** tab (see §12.11), using data already returned by `GET /insights/{job_id}/iocs`.
- **`exportIOCsJson`**: pretty-printed JSON file (`iocs-{job_id}.json`).
- **`exportIOCsCsvFile`**: multi-section CSV with comment/header rows for malicious IPs, attack patterns, suspicious users, and firewall rule rows.
- **`exportFirewallRulesFile`**: text file (`firewall-suggestions-{job_id}.txt`) with human-readable rule summaries plus an embedded JSON block of `firewall_rules` (or an explicit empty-rules payload when none were generated).
- **`downloadBlob`**: shared helper to trigger browser downloads.

### 12.10 `ClusterDetails` (`frontend/components/cluster-details.tsx`)

**Props**

- `clusters: ClusterResult[]`, optional `jobId` (required for paginated API fetch).

**Structure**

- `ClusterCard` per cluster: expand/collapse (`isExpanded`), threat badge, summary fields.

**Lazy loading and scroll**

- On first expand with `jobId`: `getClusterEvents(jobId, cluster_id, page=1, PAGE_SIZE=30)`.
- Further pages appended on scroll: `useEffect` attaches listener to Radix ScrollArea viewport; near-bottom triggers `loadPage(currentPage + 1)` until `totalPages`.
- On fetch error page 1: fallback to `cluster.representative_events`.

**Other interactions**

- Buttons for expand chevron; optional external links if present in UI for artifacts.

### 12.11 `SecurityInsights` (`frontend/components/security-insights.tsx`)

**Props**

- `data: InsightsData | null` (local interface mirroring API), `loading: boolean`.
- **`jobId?: string`** — when set (passed from `App` as the current training job id), enables enriched MITRE data, IOC fetch, and MITRE-related event drill-down.

**State**

- `selectedInsight`, `activeTab` (e.g. `overview`, MITRE, IOCs, correlations).
- **MITRE**: `mitreDetail` / `mitreLoading` / `mitreError` from `getMITREMapping(jobId)` when `jobId` and `data` are present.
- **MITRE event popup**: `mitrePopup` (dialog open state + title/description + filter), `mitrePopupEvents` / loading / error from `getMITREEvents(jobId, { …filter, page, limit })`.
- **IOCs**: `iocsData` / `iocsLoading` / `iocsError`; `getIOCs(jobId)` runs when the **IOCs** tab becomes active.

**Behavior**

- Loading skeleton when `loading && !data`.
- Tabbed sections: executive summary, insight list, **MITRE ATT&CK** (tactics/techniques coverage, kill chain, mitigation priorities when `mitreDetail` loads), correlations, threat landscape, **IOCs**.
- **Enriched MITRE UI**: dashboard cards and charts driven by `MITREResponse`; interactive elements can **open a dialog** and load **`/insights/{job_id}/mitre/events`** with exactly one of `tactic`, `technique`, or `kill_chain_stage` to show a **paginated table** of backing events (with page navigation).
- **IOCs tab**: lists threat IPs from the IOC payload (with tooltips) when available, else falls back to `executive_summary.top_threat_actors`; **Export as JSON**, **Export as CSV**, and **Generate Firewall Rules** call §12.9b helpers (buttons disabled until `getIOCs` succeeds).
- Clicking an insight sets `selectedInsight` where applicable for detail panes.

### 12.12 Results view composition (`state === 'completed'`)

- **Summary row**: total events, clusters, critical/high counts from `results.summary`.
- **Intrinsic row**: Silhouette, DBI, CH via `formatMetric(results.intrinsic_metrics)` (computed on **refined hard** labels + latent; for **UFCM** they do not summarize fuzzy overlap—see §6A.7).
- **Tabs** (**controlled**: `value={resultsTab}`, `onValueChange={setResultsTab}`; see §12.3 / §12.9a):
  - **Security Insights** → `SecurityInsights` with `insights`, `insightsLoading`, and **`jobId={jobId ?? undefined}`** so MITRE/IOCs/API drill-downs work.
  - **Visualization** → `VisualizationTab` (lazy `ClusterVisualization`) only while the Visualization tab is selected.
  - **Cluster Details** → scrollable `ClusterDetails` with `jobId`.
  - **Threat Analysis** → `ThreatAnalysis` (`frontend/components/threat-analysis.tsx`): top threat indicators and priority clusters each expose **Events** / **View events** opening a dialog with the same paginated event table as MITRE/cluster popups; indicators call `GET /threat-indicator-events/{job_id}` (§2.8a), clusters call `GET /cluster-events/...` (§2.8). Rendered only when the Threat Analysis tab is active (`resultsTab === 'threats'`).

### 12.13 End-to-end user journey (sequence)

1. User opens app → health check + demo samples loaded.
2. **Get Started** → configuring.
3. User uploads file → `onEventsLoaded` → parent stores events + filename → Step 2 appears.
4. User adjusts model/hyperparameters → **Start Training** → `handleStartTraining` → API returns `job_id`.
5. Poll loop updates progress until complete → results + insights fetched.
6. User explores tabs (including lazy-loaded Visualization, MITRE drill-down with event popup, IOC exports) / expands clusters / scrolls event pages.
7. **New Analysis** → reset to idle.

### 12.14 Error handling and edge cases

- **Backend offline**: training entry disabled; badge shows offline.
- **Training start failure**: message from thrown `Error` (API `detail` surfaced by `api.ts`).
- **Polling `AbortError`**: ignored (expected on cleanup or superseded request).
- **Insights failure after success**: logged; UI may show empty insights with loading false.
- **Cluster events API failure**: falls back to representative events for first page.
- **MITRE events popup failure**: error string in dialog; user can dismiss or retry depending on UI state.
- **IOCs fetch failure**: error banner with **Retry** on the IOCs tab; exports stay disabled until load succeeds.

---

*Generated to reflect the repository layout at documentation time; after code changes, re-verify signatures and response shapes against `backend/main.py` and Pydantic models.*

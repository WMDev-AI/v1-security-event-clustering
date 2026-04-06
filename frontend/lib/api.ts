const API_BASE = 'http://localhost:8000/api';

export interface TrainingRequest {
  events: string[];
  model_type: 'dec' | 'idec' | 'vade' | 'contrastive' | 'ufcm' | 'dmvc';
  n_clusters: number;
  latent_dim: number;
  hidden_dims: number[];
  pretrain_epochs: number;
  finetune_epochs: number;
  batch_size: number;
  learning_rate: number;
}

export interface TrainingProgress {
  job_id: string;
  status: string;
  progress: number;  // Overall progress 0-100
  stage?: string;  // "initializing" | "pretraining" | "initialization" | "fine-tuning" | "postprocessing"
  stage_progress?: number;  // Progress within current stage 0-100
  current_epoch: number;
  total_epochs: number;
  stage_epoch?: number;  // Epoch within current stage
  stage_total_epochs?: number;  // Total epochs for current stage
  current_loss: number;
  metrics: Record<string, unknown> | null;
  message: string;
  /** Clustering algorithm id (e.g. idec, dmvc); set when the job is created */
  model_type?: string;
  n_clusters?: number;
  stages_completed?: string[];  // e.g., ["pretraining"]
  refinement?: {
    applied: boolean;
    method: string;
    elapsed_seconds?: number;
    time_budget_hit?: boolean;
  };
}

export interface SecurityEvent {
  timestamp?: string;
  source_ip?: string;
  dest_ip?: string;
  dest_port?: number;
  subsystem?: string;
  action?: string;
  severity?: string;
  content?: string;
  [key: string]: unknown;
}

export interface ClusterResult {
  cluster_id: number;
  size: number;
  threat_level: string;
  primary_subsystems: string[];
  primary_actions: string[];
  threat_indicators: string[];
  recommended_actions: string[];
  top_source_ips: [string, number][];
  top_dest_ports: [number, number][];
  representative_events: SecurityEvent[];
}

export interface FileUploadResponse {
  filename: string;
  total_events: number;
  events: string[];
  format_detected: string;
  sample_events: string[];
  errors: string[];
}

export interface AnalysisResponse {
  total_events: number;
  n_clusters: number;
  clusters: ClusterResult[];
  summary: {
    total_events: number;
    total_clusters: number;
    threat_distribution: Record<string, number>;
    critical_clusters: number[];
    high_risk_clusters: number[];
    top_threat_indicators: [string, number][];
    avg_cluster_size: number;
    size_range: { min: number; max: number };
  };
  intrinsic_metrics: {
    silhouette?: number;
    davies_bouldin?: number;
    calinski_harabasz?: number;
    n_clusters_found?: number;
    cluster_sizes?: Record<string, number>;
    size_std?: number;
    size_min?: number;
    size_max?: number;
  } | null;
  /** Algorithm id from the training job */
  model_type?: string | null;
  /** Final fine-tune batch-averaged losses from the last epoch */
  training_loss?: {
    total_loss?: number;
    clustering_loss?: number;
    reconstruction_loss?: number;
  } | null;
  latent_visualization: {
    points: { x: number; y: number; cluster: number }[];
    explained_variance: number[];
  } | null;
}

export async function startTraining(request: TrainingRequest): Promise<{ job_id: string }> {
  const res = await fetch(`${API_BASE}/train`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Training failed to start');
  }
  return res.json();
}

export async function getTrainingStatus(jobId: string, signal?: AbortSignal): Promise<TrainingProgress> {
  const res = await fetch(`${API_BASE}/train/${jobId}`, { signal });
  if (!res.ok) throw new Error('Failed to get training status');
  return res.json();
}

export async function getResults(jobId: string): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/results/${jobId}`);
  if (!res.ok) throw new Error('Failed to get results');
  return res.json();
}

/** Column keys aligned with backend event_table_query.ALLOWED_SORT */
export type EventTableSortColumn =
  | 'index'
  | 'timestamp'
  | 'source_ip'
  | 'dest_ip'
  | 'dest_port'
  | 'subsystem'
  | 'action'
  | 'severity'
  | 'content';

export interface EventTableQuery {
  page: number;
  sortBy: EventTableSortColumn;
  sortDir: 'asc' | 'desc';
  filters: Partial<Record<EventTableSortColumn, string>>;
}

export const DEFAULT_EVENT_TABLE_QUERY: EventTableQuery = {
  page: 1,
  sortBy: 'index',
  sortDir: 'asc',
  filters: {},
};

const F_PARAM: Record<EventTableSortColumn, string> = {
  index: 'f_index',
  timestamp: 'f_timestamp',
  source_ip: 'f_source_ip',
  dest_ip: 'f_dest_ip',
  dest_port: 'f_dest_port',
  subsystem: 'f_subsystem',
  action: 'f_action',
  severity: 'f_severity',
  content: 'f_content',
};

export function appendEventTableQueryParams(params: URLSearchParams, q: EventTableQuery): void {
  params.set('page', String(q.page));
  params.set('sort_by', q.sortBy);
  params.set('sort_dir', q.sortDir);
  (Object.keys(q.filters) as EventTableSortColumn[]).forEach((col) => {
    const v = q.filters[col]?.trim();
    if (v) params.set(F_PARAM[col], v);
  });
}

export async function getClusterEvents(
  jobId: string,
  clusterId: number,
  limit: number,
  query: EventTableQuery
): Promise<{
  job_id: string;
  cluster_id: number;
  total_events: number;
  page: number;
  limit: number;
  total_pages: number;
  events: SecurityEvent[];
}> {
  const params = new URLSearchParams({ limit: String(limit) });
  appendEventTableQueryParams(params, query);
  const res = await fetch(`${API_BASE}/cluster-events/${jobId}/${clusterId}?${params}`);
  if (!res.ok) throw new Error('Failed to get cluster events');
  return res.json();
}

export interface ThreatIndicatorEventsResponse {
  job_id: string;
  indicator: string;
  cluster_ids: number[];
  total_events: number;
  page: number;
  limit: number;
  total_pages: number;
  events: SecurityEvent[];
}

/** Events from all clusters whose profile lists this exact indicator (matches summary top_threat_indicators). */
export async function getThreatIndicatorEvents(
  jobId: string,
  indicator: string,
  limit: number,
  query: EventTableQuery
): Promise<ThreatIndicatorEventsResponse> {
  const params = new URLSearchParams({
    indicator,
    limit: String(limit),
  });
  appendEventTableQueryParams(params, query);
  const res = await fetch(`${API_BASE}/threat-indicator-events/${jobId}?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || 'Failed to get threat indicator events');
  }
  return res.json();
}

export async function getDemoEvents(): Promise<{ sample_events: string[] }> {
  const res = await fetch(`${API_BASE}/demo`);
  if (!res.ok) throw new Error('Failed to get demo events');
  return res.json();
}

export async function uploadEventLog(file: File): Promise<FileUploadResponse> {
  const formData = new FormData();
  formData.append('file', file);
  
  const res = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    body: formData,
  });
  
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'File upload failed');
  }
  
  return res.json();
}

export async function getModels(): Promise<{ models: { id: string; name: string; description: string }[] }> {
  const res = await fetch(`${API_BASE}/models`);
  if (!res.ok) throw new Error('Failed to get models');
  return res.json();
}

export async function checkHealth(): Promise<{ status: string; cuda_available: boolean; device: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Backend not available');
  return res.json();
}

// Security Insights API

export interface SecurityInsight {
  insight_id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  event_count: number;
  sample_events: Record<string, unknown>[];
  affected_subsystems: string[];
  source_ips: string[];
  target_assets: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  immediate_actions: string[];
  long_term_actions: string[];
  ioc_indicators: Record<string, unknown>[];
}

export interface Correlation {
  cluster_a: number;
  cluster_b: number;
  correlation_type: string;
  correlation_strength: number;
  shared_indicators: string[];
  description: string;
}

export interface InsightsResponse {
  job_id: string;
  total_events: number;
  total_clusters: number;
  insights: SecurityInsight[];
  correlations: Correlation[];
  executive_summary: {
    overview: Record<string, number>;
    severity_distribution: Record<string, number>;
    category_distribution: Record<string, number>;
    critical_findings: Record<string, unknown>[];
    high_priority_findings: Record<string, unknown>[];
    mitre_coverage: {
      tactics: string[];
      techniques: string[];
    };
    top_threat_actors: string[];
    recommended_priorities: string[];
  };
  threat_landscape: {
    attack_types_detected: Record<string, number>;
    severity_distribution: Record<string, number>;
    subsystem_impact: Record<string, { event_count: number; insight_count: number }>;
    top_threat_sources: { ip: string; insights: string[]; total_events: number }[];
    most_targeted_assets: { ip: string; insights: string[]; total_events: number }[];
    cluster_risk_scores: Record<string, { score: number; level: string; factors: string[]; event_count: number }>;
  };
}

export interface IOCsResponse {
  job_id: string;
  generated_at: string;
  malicious_ips: {
    ip: string;
    contexts: string[];
    event_count: number;
    severity: string;
    recommendation: string;
  }[];
  attack_patterns: {
    pattern: string;
    description: string;
    mitre_techniques: string[];
    source_ips: string[];
    severity: string;
  }[];
  suspicious_users: {
    user: string;
    reasons: string[];
    event_count: number;
  }[];
  firewall_rules: {
    rule_type: string;
    priority: number;
    description: string;
    ips?: string[];
    ports?: number[];
    direction?: string;
    action?: string;
    max_connections_per_minute?: number;
  }[];
  total_unique_threat_ips: number;
  total_attack_patterns: number;
}

export interface MITREResponse {
  job_id: string;
  tactics_coverage: Record<string, {
    techniques: string[];
    insights: string[];
    event_count: number;
  }>;
  techniques_detected: Record<string, {
    insights: string[];
    clusters: number[];
    event_count: number;
  }>;
  total_tactics: number;
  total_techniques: number;
  kill_chain_analysis: {
    stages_detected: string[];
    attack_progression: number;
    assessment: string;
  };
  coverage_assessment: {
    high_impact_tactics_detected: string[];
    high_impact_coverage: number;
    overall_risk: string;
  };
  mitigation_priorities: {
    technique: string;
    event_count: number;
    recommended_mitigations: string[];
  }[];
}

export async function getSecurityInsights(jobId: string): Promise<InsightsResponse> {
  const res = await fetch(`${API_BASE}/insights/${jobId}`);
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Failed to get security insights');
  }
  return res.json();
}

export async function getClusterInsights(jobId: string, clusterId: number): Promise<{
  cluster_id: number;
  event_count: number;
  profile: Record<string, unknown> | null;
  insights: SecurityInsight[];
  risk_assessment: { score: number; level: string; factors: string[]; event_count: number };
  sample_events: Record<string, unknown>[];
}> {
  const res = await fetch(`${API_BASE}/insights/${jobId}/cluster/${clusterId}`);
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Failed to get cluster insights');
  }
  return res.json();
}

export async function getIOCs(jobId: string): Promise<IOCsResponse> {
  const res = await fetch(`${API_BASE}/insights/${jobId}/iocs`);
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Failed to get IOCs');
  }
  return res.json();
}

export async function getMITREMapping(jobId: string): Promise<MITREResponse> {
  const res = await fetch(`${API_BASE}/insights/${jobId}/mitre`);
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Failed to get MITRE mapping');
  }
  return res.json();
}

/** Row returned by GET /insights/{jobId}/mitre/events */
export interface MITREEventsRow {
  index: number;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  dest_port: number;
  subsystem: string;
  action: string;
  severity: string;
  content: string;
}

export interface MITREEventsResponse {
  filter_type: string;
  filter_value: string;
  cluster_ids: number[];
  total_events: number;
  page: number;
  limit: number;
  total_pages: number;
  events: MITREEventsRow[];
}

export type MitreEventFilter =
  | { type: 'tactic'; value: string }
  | { type: 'technique'; value: string }
  | { type: 'kill_chain_stage'; value: string };

export async function getMITREEvents(
  jobId: string,
  params: MitreEventFilter & { limit?: number },
  tableQuery: EventTableQuery
): Promise<MITREEventsResponse> {
  const search = new URLSearchParams();
  if (params.type === 'tactic') search.set('tactic', params.value);
  if (params.type === 'technique') search.set('technique', params.value);
  if (params.type === 'kill_chain_stage') search.set('kill_chain_stage', params.value);
  if (params.limit != null) search.set('limit', String(params.limit));
  appendEventTableQueryParams(search, tableQuery);
  const q = search.toString();
  const res = await fetch(`${API_BASE}/insights/${jobId}/mitre/events?${q}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to load MITRE-related events');
  }
  return res.json();
}

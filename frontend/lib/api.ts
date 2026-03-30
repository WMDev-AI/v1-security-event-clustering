const API_BASE = 'http://localhost:8000/api';

export interface TrainingRequest {
  events: string[];
  model_type: 'dec' | 'idec' | 'vade' | 'contrastive';
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
  progress: number;
  current_epoch: number;
  total_epochs: number;
  current_loss: number;
  metrics: Record<string, unknown> | null;
  message: string;
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

export async function getTrainingStatus(jobId: string): Promise<TrainingProgress> {
  const res = await fetch(`${API_BASE}/train/${jobId}`);
  if (!res.ok) throw new Error('Failed to get training status');
  return res.json();
}

export async function getResults(jobId: string): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/results/${jobId}`);
  if (!res.ok) throw new Error('Failed to get results');
  return res.json();
}

export async function getDemoEvents(): Promise<{ sample_events: string[] }> {
  const res = await fetch(`${API_BASE}/demo`);
  if (!res.ok) throw new Error('Failed to get demo events');
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

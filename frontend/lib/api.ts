const API_BASE = '/api';

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
  representative_events: Record<string, unknown>[];
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

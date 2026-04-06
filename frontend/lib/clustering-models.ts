/** Short labels for compact UI */
export const CLUSTERING_MODEL_SHORT: Record<string, string> = {
  dec: 'DEC',
  idec: 'IDEC',
  vade: 'VaDE',
  contrastive: 'Contrastive',
  ufcm: 'UFCM',
  dmvc: 'DMVC',
  idec_lstm: 'IDEC-LSTM',
  idec_transformer: 'IDEC-Tr',
}

/** Full display names (aligned with training-config MODEL_INFO) */
export const CLUSTERING_MODEL_DISPLAY: Record<string, string> = {
  dec: 'Deep Embedded Clustering (DEC)',
  idec: 'Improved DEC (IDEC)',
  vade: 'Variational Deep Embedding (VaDE)',
  contrastive: 'Contrastive Deep Clustering',
  ufcm: 'Deep Unconstrained Fuzzy C-Means (UFCM)',
  dmvc: 'Deep Multi-View Clustering (DMVC)',
  idec_lstm: 'IDEC with LSTM sequence encoder',
  idec_transformer: 'IDEC with Transformer sequence encoder',
}

export function clusteringModelDisplayName(
  id: string | undefined | null
): string {
  if (!id) return 'Unknown'
  return CLUSTERING_MODEL_DISPLAY[id] ?? id
}

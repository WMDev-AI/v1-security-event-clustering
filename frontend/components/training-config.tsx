"use client"

import { useState, useEffect } from 'react'
import {
  Brain,
  Layers,
  Target,
  Zap,
  Settings2,
  Play,
  Loader2,
  HelpCircle,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Slider } from '@/components/ui/slider'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import type { TrainingRequest } from '@/lib/api'

interface TrainingConfigProps {
  onSubmit: (config: TrainingRequest) => void
  isLoading: boolean
  sampleEvents?: string[]
  preloadedEvents?: string[]
  preloadedFilename?: string
}

const MODEL_INFO = {
  dec: {
    name: 'Deep Embedded Clustering (DEC)',
    description: 'Classic deep clustering using KL divergence to refine cluster assignments iteratively.',
    pros: ['Fast training', 'Stable convergence'],
    best_for: 'General-purpose clustering with clear cluster boundaries'
  },
  idec: {
    name: 'Improved DEC (IDEC)',
    description: 'Enhanced DEC that preserves local structure through reconstruction loss.',
    pros: ['Better representation', 'More robust'],
    best_for: 'Complex data with subtle patterns'
  },
  vade: {
    name: 'Variational Deep Embedding (VaDE)',
    description: 'Probabilistic approach combining VAE with Gaussian Mixture Models.',
    pros: ['Uncertainty estimation', 'Soft assignments'],
    best_for: 'When cluster membership uncertainty matters'
  },
  contrastive: {
    name: 'Contrastive Deep Clustering',
    description: 'Uses contrastive learning for robust feature extraction before clustering.',
    pros: ['Noise resistant', 'Strong features'],
    best_for: 'Noisy data or when augmentation helps'
  },
  ufcm: {
    name: 'Deep Unconstrained Fuzzy C-Means (UFCM)',
    description:
      'UC-FCM-style fuzzy clustering in latent space: optimal memberships from current centers, optimized by gradient descent (IEEE TPAMI 2025), with light reconstruction regularization.',
    pros: ['Soft memberships', 'Smooth optimization vs alternating FCM'],
    best_for: 'Overlapping clusters and gradual threat behavior boundaries'
  },
  dmvc: {
    name: 'Deep Multi-View Clustering (DMVC)',
    description:
      'Splits the feature vector into two views (first and second half), trains a separate autoencoder per view, fuses latents for clustering with the same Student-t / KL objective as DEC/IDEC, and aligns view latents with an MSE consistency term.',
    pros: ['Multi-view structure', 'Reconstruction + clustering'],
    best_for: 'When natural feature groups exist (e.g. early vs late dimensions) or you want explicit cross-view agreement'
  },
  idec_lstm: {
    name: 'IDEC + LSTM (temporal windows)',
    description:
      'Improved DEC where each sample is a time-ordered window of consecutive events (sorted by timestamp). An LSTM encodes the window into a latent vector; clustering and reconstruction target the current (last) event in the window.',
    pros: ['Temporal context', 'Same IDEC objective as the MLP baseline'],
    best_for: 'Logs with trustworthy timestamps when recent context should influence grouping'
  },
  idec_transformer: {
    name: 'IDEC + Transformer (temporal windows)',
    description:
      'Same temporal windowing as LSTM IDEC, but uses a Transformer encoder with positional encoding over the window, then mean-pools to a latent for Student-t clustering and reconstruction.',
    pros: ['Long-range attention within the window', 'Parallelizable encoder'],
    best_for: 'When you want attention over the last T events instead of recurrent pooling'
  },
  idec_gnn: {
    name: 'IDEC + GNN (GCN on k-NN graph)',
    description:
      'Each training batch builds a symmetric k-NN graph on normalized event features; stacked graph convolution layers aggregate neighbor context into a latent vector, then the same IDEC objective (KL + reconstruction) applies.',
    pros: ['Relational signal in feature space', 'No extra log metadata required'],
    best_for: 'When events in a batch that look alike should reinforce each other’s representation'
  }
}

export function TrainingConfig({ onSubmit, isLoading, sampleEvents, preloadedEvents, preloadedFilename }: TrainingConfigProps) {
  const [events, setEvents] = useState<string>(preloadedEvents?.join('\n') || '')
  type ModelChoice = keyof typeof MODEL_INFO
  const [modelType, setModelType] = useState<ModelChoice>('idec')
  const [nClusters, setNClusters] = useState(10)
  const [latentDim, setLatentDim] = useState(32)
  const [pretrainEpochs, setPretrainEpochs] = useState(30)
  const [finetuneEpochs, setFinetuneEpochs] = useState(50)
  const [seqLen, setSeqLen] = useState(16)
  const [gnnK, setGnnK] = useState(10)
  const [gnnHidden, setGnnHidden] = useState(128)
  const [gnnLayers, setGnnLayers] = useState(2)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const usesSequenceModel = modelType === 'idec_lstm' || modelType === 'idec_transformer'
  const usesGnnModel = modelType === 'idec_gnn'
  
  // Update events when preloaded events change
  useEffect(() => {
    if (preloadedEvents && preloadedEvents.length > 0) {
      setEvents(preloadedEvents.join('\n'))
    }
  }, [preloadedEvents])

  const eventLines = events.trim().split('\n').filter(l => l.trim())
  const eventCount = eventLines.length
  const isValid = eventCount >= 100 && preloadedFilename

  const handleSubmit = () => {
    const config: TrainingRequest = {
      events: eventLines,
      model_type: modelType,
      n_clusters: nClusters,
      latent_dim: latentDim,
      hidden_dims: [256, 128, 64],
      pretrain_epochs: pretrainEpochs,
      finetune_epochs: finetuneEpochs,
      batch_size: Math.min(256, Math.max(32, Math.floor(eventCount / 10))),
      learning_rate: 0.001,
      ...(usesSequenceModel ? { seq_len: seqLen } : {}),
      ...(usesGnnModel
        ? {
            gnn_k_neighbors: gnnK,
            gnn_hidden_dim: gnnHidden,
            gnn_num_layers: gnnLayers,
          }
        : {}),
    }
    onSubmit(config)
  }

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Uploaded File Info */}
        {preloadedFilename ? (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Layers className="h-4 w-4" />
                Uploaded Security Events
              </CardTitle>
              <CardDescription>
                Events loaded from your file
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm font-medium text-gray-700">Filename:</span>
                    <span className="text-sm font-mono text-gray-900">{preloadedFilename}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm font-medium text-gray-700">Total Events:</span>
                    <span className={`text-sm font-bold ${eventCount >= 100 ? 'text-green-600' : 'text-red-600'}`}>
                      {eventCount}
                    </span>
                  </div>
                  {eventCount < 100 && (
                    <p className="text-sm text-red-600 font-medium">
                      ⚠️ Minimum 100 events required. Please upload a larger file.
                    </p>
                  )}
                  {eventCount >= 100 && (
                    <p className="text-sm text-green-600 font-medium">
                      ✓ Ready for training
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-red-200 bg-red-50">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2 text-red-900">
                <Layers className="h-4 w-4" />
                No File Uploaded
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-red-700">
                Please upload a security event log file first to proceed. Use the upload section above.
              </p>
            </CardContent>
          </Card>
        )}

        {/* Model Selection */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Brain className="h-4 w-4" />
              Deep Clustering Model
            </CardTitle>
            <CardDescription>
              Choose the clustering algorithm
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Select value={modelType} onValueChange={(v) => setModelType(v as ModelChoice)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(MODEL_INFO).map(([key, info]) => (
                  <SelectItem key={key} value={key}>
                    <div className="flex items-center gap-2">
                      <span>{info.name}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Model Details */}
            <div className="bg-muted/50 rounded-lg p-3 space-y-2">
              <p className="text-sm">{MODEL_INFO[modelType].description}</p>
              <div className="flex flex-wrap gap-1.5">
                {MODEL_INFO[modelType].pros.map((pro, i) => (
                  <span key={i} className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded">
                    {pro}
                  </span>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                Best for: {MODEL_INFO[modelType].best_for}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Clustering Config */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-4 w-4" />
              Clustering Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Number of Clusters */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="flex items-center gap-1.5">
                  Number of Clusters
                  <Tooltip>
                    <TooltipTrigger>
                      <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p className="max-w-[200px] text-xs">
                        The number of groups to divide your events into.
                        Start with 5-15 for initial exploration.
                      </p>
                    </TooltipContent>
                  </Tooltip>
                </Label>
                <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">
                  {nClusters}
                </span>
              </div>
              <Slider
                value={[nClusters]}
                onValueChange={([v]) => setNClusters(v)}
                min={2}
                max={50}
                step={1}
              />
            </div>

            {/* Latent Dimension */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="flex items-center gap-1.5">
                  Latent Dimension
                  <Tooltip>
                    <TooltipTrigger>
                      <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p className="max-w-[200px] text-xs">
                        Size of the learned representation.
                        Higher = more expressive, lower = more compact.
                      </p>
                    </TooltipContent>
                  </Tooltip>
                </Label>
                <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">
                  {latentDim}
                </span>
              </div>
              <Slider
                value={[latentDim]}
                onValueChange={([v]) => setLatentDim(v)}
                min={8}
                max={128}
                step={8}
              />
            </div>
          </CardContent>
        </Card>

        {/* Advanced Settings */}
        <Card>
          <CardHeader
            className="pb-3 cursor-pointer"
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <CardTitle className="text-base flex items-center gap-2">
              <Settings2 className="h-4 w-4" />
              Advanced Settings
              <span className="text-xs text-muted-foreground ml-auto">
                {showAdvanced ? 'Hide' : 'Show'}
              </span>
            </CardTitle>
          </CardHeader>
          {showAdvanced && (
            <CardContent className="space-y-6">
              {/* Pretrain Epochs */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label>Pretraining Epochs</Label>
                  <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">
                    {pretrainEpochs}
                  </span>
                </div>
                <Slider
                  value={[pretrainEpochs]}
                  onValueChange={([v]) => setPretrainEpochs(v)}
                  min={10}
                  max={100}
                  step={5}
                />
              </div>

              {/* Finetune Epochs */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label>Fine-tuning Epochs</Label>
                  <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">
                    {finetuneEpochs}
                  </span>
                </div>
                <Slider
                  value={[finetuneEpochs]}
                  onValueChange={([v]) => setFinetuneEpochs(v)}
                  min={20}
                  max={200}
                  step={10}
                />
              </div>

              {usesGnnModel && (
                <>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <Label className="flex items-center gap-1.5">
                        GNN k-NN neighbors (per batch)
                        <Tooltip>
                          <TooltipTrigger>
                            <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                          </TooltipTrigger>
                          <TooltipContent>
                            <p className="max-w-[220px] text-xs">
                              Each mini-batch forms a graph: each event links to this many nearest neighbors in feature space (within the batch). Larger k increases context but costs more compute.
                            </p>
                          </TooltipContent>
                        </Tooltip>
                      </Label>
                      <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">{gnnK}</span>
                    </div>
                    <Slider
                      value={[gnnK]}
                      onValueChange={([v]) => setGnnK(v)}
                      min={3}
                      max={32}
                      step={1}
                    />
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <Label>GCN hidden size</Label>
                      <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">{gnnHidden}</span>
                    </div>
                    <Slider
                      value={[gnnHidden]}
                      onValueChange={([v]) => setGnnHidden(v)}
                      min={64}
                      max={256}
                      step={32}
                    />
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <Label>GCN layers</Label>
                      <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">{gnnLayers}</span>
                    </div>
                    <Slider
                      value={[gnnLayers]}
                      onValueChange={([v]) => setGnnLayers(v)}
                      min={1}
                      max={6}
                      step={1}
                    />
                  </div>
                </>
              )}

              {usesSequenceModel && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label className="flex items-center gap-1.5">
                      Sequence window (events)
                      <Tooltip>
                        <TooltipTrigger>
                          <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p className="max-w-[220px] text-xs">
                            Number of consecutive time-ordered events per training sample. Larger windows add context but increase memory and noise risk.
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    </Label>
                    <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded">{seqLen}</span>
                  </div>
                  <Slider
                    value={[seqLen]}
                    onValueChange={([v]) => setSeqLen(v)}
                    min={4}
                    max={64}
                    step={1}
                  />
                </div>
              )}
            </CardContent>
          )}
        </Card>

        {/* Submit Button */}
        <Button
          onClick={handleSubmit}
          disabled={!isValid || isLoading}
          className="w-full"
          size="lg"
        >
          {isLoading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Training...
            </>
          ) : (
            <>
              <Zap className="h-4 w-4" />
              Start Deep Clustering
            </>
          )}
        </Button>
      </div>
    </TooltipProvider>
  )
}

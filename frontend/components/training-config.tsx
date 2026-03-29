"use client"

import { useState } from 'react'
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
import { Textarea } from '@/components/ui/textarea'
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
  sampleEvents: string[]
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
  }
}

export function TrainingConfig({ onSubmit, isLoading, sampleEvents }: TrainingConfigProps) {
  const [events, setEvents] = useState<string>(sampleEvents.join('\n'))
  const [modelType, setModelType] = useState<'dec' | 'idec' | 'vade' | 'contrastive'>('idec')
  const [nClusters, setNClusters] = useState(10)
  const [latentDim, setLatentDim] = useState(32)
  const [pretrainEpochs, setPretrainEpochs] = useState(30)
  const [finetuneEpochs, setFinetuneEpochs] = useState(50)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const eventLines = events.trim().split('\n').filter(l => l.trim())
  const eventCount = eventLines.length
  const isValid = eventCount >= 100

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
      learning_rate: 0.001
    }
    onSubmit(config)
  }

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Event Input */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Layers className="h-4 w-4" />
              Security Events
            </CardTitle>
            <CardDescription>
              Paste your security events (one per line, key=value format)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Textarea
              value={events}
              onChange={(e) => setEvents(e.target.value)}
              placeholder="timestamp=2024-01-15 08:30:00 sourceip=192.168.1.100 destip=10.0.0.50 destport=443 subsys=firewall action=allow"
              className="h-[200px] font-mono text-xs"
            />
            <div className="flex items-center justify-between text-sm">
              <span className={eventCount < 100 ? 'text-destructive' : 'text-muted-foreground'}>
                {eventCount} events {eventCount < 100 && '(minimum 100 required)'}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setEvents(sampleEvents.join('\n'))}
              >
                Load Sample Events
              </Button>
            </div>
          </CardContent>
        </Card>

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
            <Select value={modelType} onValueChange={(v) => setModelType(v as typeof modelType)}>
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

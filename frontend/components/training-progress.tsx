"use client"

import { useEffect, useState } from 'react'
import {
  CheckCircle2,
  Loader2,
  XCircle,
  Brain,
  Cpu,
  Activity,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import type { TrainingProgress as TrainingProgressType } from '@/lib/api'

interface TrainingProgressProps {
  progress: TrainingProgressType
}

export function TrainingProgress({ progress }: TrainingProgressProps) {
  const [animatedProgress, setAnimatedProgress] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedProgress(progress.progress)
    }, 100)
    return () => clearTimeout(timer)
  }, [progress.progress])

  const getStatusIcon = () => {
    switch (progress.status) {
      case 'completed':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />
      default:
        return <Loader2 className="h-5 w-5 animate-spin text-primary" />
    }
  }

  const getStatusColor = () => {
    switch (progress.status) {
      case 'completed':
        return 'bg-green-500/20 text-green-400'
      case 'failed':
        return 'bg-red-500/20 text-red-400'
      default:
        return 'bg-blue-500/20 text-blue-400'
    }
  }

  const isTraining = ['training', 'starting'].includes(progress.status)

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Brain className="h-4 w-4" />
            Training Progress
          </CardTitle>
          <Badge className={getStatusColor()}>
            {getStatusIcon()}
            <span className="ml-1.5 capitalize">{progress.status}</span>
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{progress.message}</span>
            <span className="font-mono">{Math.round(animatedProgress)}%</span>
          </div>
          <Progress value={animatedProgress} className="h-2" />
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-muted/50 rounded-lg p-3 text-center">
            <div className="flex items-center justify-center gap-1.5 text-muted-foreground mb-1">
              <Activity className="h-3.5 w-3.5" />
              <span className="text-xs">Epoch</span>
            </div>
            <div className="text-lg font-mono">
              {progress.current_epoch}/{progress.total_epochs}
            </div>
          </div>

          <div className="bg-muted/50 rounded-lg p-3 text-center">
            <div className="flex items-center justify-center gap-1.5 text-muted-foreground mb-1">
              <Cpu className="h-3.5 w-3.5" />
              <span className="text-xs">Loss</span>
            </div>
            <div className="text-lg font-mono">
              {progress.current_loss.toFixed(4)}
            </div>
          </div>

          <div className="bg-muted/50 rounded-lg p-3 text-center">
            <div className="flex items-center justify-center gap-1.5 text-muted-foreground mb-1">
              <Brain className="h-3.5 w-3.5" />
              <span className="text-xs">Phase</span>
            </div>
            <div className="text-sm font-medium truncate">
              {progress.current_epoch <= progress.total_epochs / 2 ? 'Pretrain' : 'Finetune'}
            </div>
          </div>
        </div>

        {/* Metrics Preview */}
        {progress.metrics && (
          <div className="border-t pt-4">
            <h4 className="text-sm font-medium mb-2">Current Metrics</h4>
            <div className="grid grid-cols-2 gap-2 text-sm">
              {progress.metrics.silhouette !== undefined && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Silhouette Score</span>
                  <span className="font-mono">{Number(progress.metrics.silhouette).toFixed(4)}</span>
                </div>
              )}
              {progress.metrics.n_clusters_found !== undefined && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Clusters Found</span>
                  <span className="font-mono">{Number(progress.metrics.n_clusters_found)}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Training Animation */}
        {isTraining && (
          <div className="flex items-center justify-center py-4">
            <div className="relative">
              <div className="w-16 h-16 border-4 border-muted rounded-full" />
              <div
                className="absolute inset-0 w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin"
                style={{ animationDuration: '1.5s' }}
              />
              <Brain className="absolute inset-0 m-auto h-6 w-6 text-primary" />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

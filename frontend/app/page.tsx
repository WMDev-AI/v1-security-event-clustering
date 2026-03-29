"use client"

import { useState, useEffect, useCallback } from 'react'
import {
  Shield,
  Brain,
  Network,
  AlertTriangle,
  CheckCircle2,
  Server,
  RefreshCw,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { TrainingConfig } from '@/components/training-config'
import { TrainingProgress } from '@/components/training-progress'
import { ClusterVisualization } from '@/components/cluster-visualization'
import { ClusterDetails } from '@/components/cluster-details'
import { SecurityInsights } from '@/components/security-insights'
import {
  startTraining,
  getTrainingStatus,
  getResults,
  getDemoEvents,
  checkHealth,
  getSecurityInsights,
  type TrainingRequest,
  type TrainingProgress as TrainingProgressType,
  type AnalysisResponse,
  type InsightsResponse,
} from '@/lib/api'

type AppState = 'idle' | 'configuring' | 'training' | 'completed' | 'error'

export default function SecurityClusteringApp() {
  const [state, setState] = useState<AppState>('idle')
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [deviceInfo, setDeviceInfo] = useState<string>('')
  const [sampleEvents, setSampleEvents] = useState<string[]>([])
  const [jobId, setJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState<TrainingProgressType | null>(null)
  const [results, setResults] = useState<AnalysisResponse | null>(null)
  const [insights, setInsights] = useState<InsightsResponse | null>(null)
  const [insightsLoading, setInsightsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Check backend health on mount
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const health = await checkHealth()
        setBackendStatus('online')
        setDeviceInfo(health.device)
        
        // Load sample events
        const demo = await getDemoEvents()
        setSampleEvents(demo.sample_events)
      } catch {
        setBackendStatus('offline')
      }
    }
    checkBackend()
  }, [])

  // Poll training status
  useEffect(() => {
    if (!jobId || state !== 'training') return

    const pollInterval = setInterval(async () => {
      try {
        const status = await getTrainingStatus(jobId)
        setProgress(status)

        if (status.status === 'completed') {
          const res = await getResults(jobId)
          setResults(res)
          setState('completed')
          
          // Load security insights after completion
          setInsightsLoading(true)
          try {
            const insightsData = await getSecurityInsights(jobId)
            setInsights(insightsData)
          } catch (err) {
            console.error('Failed to load insights:', err)
          } finally {
            setInsightsLoading(false)
          }
        } else if (status.status === 'failed') {
          setError(status.message)
          setState('error')
        }
      } catch (err) {
        console.error('Polling error:', err)
      }
    }, 1000)

    return () => clearInterval(pollInterval)
  }, [jobId, state])

  const handleStartTraining = useCallback(async (config: TrainingRequest) => {
    try {
      setError(null)
      setState('training')
      setProgress(null)
      setResults(null)

      const { job_id } = await startTraining(config)
      setJobId(job_id)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Training failed to start')
      setState('error')
    }
  }, [])

  const handleReset = () => {
    setState('idle')
    setJobId(null)
    setProgress(null)
    setResults(null)
    setInsights(null)
    setInsightsLoading(false)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h1 className="text-xl font-bold">Security Event Deep Clustering</h1>
                <p className="text-sm text-muted-foreground">
                  PyTorch-powered analysis for security events
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant={backendStatus === 'online' ? 'default' : 'destructive'}>
                {backendStatus === 'checking' && 'Checking...'}
                {backendStatus === 'online' && (
                  <>
                    <Server className="h-3 w-3 mr-1" />
                    {deviceInfo.toUpperCase()}
                  </>
                )}
                {backendStatus === 'offline' && 'Backend Offline'}
              </Badge>
              {state !== 'idle' && state !== 'configuring' && (
                <Button variant="outline" size="sm" onClick={handleReset}>
                  <RefreshCw className="h-4 w-4 mr-1.5" />
                  New Analysis
                </Button>
              )}
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Idle State - Feature Overview */}
        {state === 'idle' && (
          <div className="max-w-4xl mx-auto space-y-8">
            {/* Hero */}
            <div className="text-center space-y-4">
              <div className="inline-flex items-center gap-2 bg-primary/10 text-primary px-4 py-1.5 rounded-full text-sm">
                <Brain className="h-4 w-4" />
                Deep Learning Powered
              </div>
              <h2 className="text-4xl font-bold">
                Cluster Your Security Events
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Use deep clustering algorithms to automatically group millions of security 
                events into meaningful clusters and extract actionable threat intelligence.
              </p>
              <Button
                size="lg"
                onClick={() => setState('configuring')}
                disabled={backendStatus !== 'online'}
              >
                Get Started
              </Button>
            </div>

            {/* Features */}
            <div className="grid gap-4 md:grid-cols-3">
              <Card>
                <CardHeader>
                  <Brain className="h-8 w-8 text-primary mb-2" />
                  <CardTitle className="text-base">Deep Clustering Models</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  Choose from DEC, IDEC, VaDE, or Contrastive clustering algorithms
                  for different use cases.
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <Network className="h-8 w-8 text-primary mb-2" />
                  <CardTitle className="text-base">Automatic Feature Extraction</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  Parse key=value formatted logs and automatically extract meaningful
                  features for clustering.
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <AlertTriangle className="h-8 w-8 text-primary mb-2" />
                  <CardTitle className="text-base">Threat Intelligence</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  Get threat assessments, indicators, and recommended actions
                  for each discovered cluster.
                </CardContent>
              </Card>
            </div>

            {/* Supported Subsystems */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Supported Security Subsystems</CardTitle>
                <CardDescription>
                  Analyze events from any of these security systems
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {['Firewall', 'IPS/IDS', 'DDoS Protection', 'WAF', 'Web Filter', 
                    'Mail Protection', 'VPN', 'Proxy', 'DNS Security', 'Antivirus',
                    'Sandbox', 'DLP', 'NAT', 'Router', 'Authentication'].map(sys => (
                    <Badge key={sys} variant="outline">{sys}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Configuration State */}
        {state === 'configuring' && (
          <div className="max-w-2xl mx-auto">
            <Button
              variant="ghost"
              className="mb-4"
              onClick={() => setState('idle')}
            >
              ← Back
            </Button>
            <TrainingConfig
              onSubmit={handleStartTraining}
              isLoading={false}
              sampleEvents={sampleEvents}
            />
          </div>
        )}

        {/* Training State */}
        {state === 'training' && progress && (
          <div className="max-w-2xl mx-auto">
            <TrainingProgress progress={progress} />
          </div>
        )}

        {/* Error State */}
        {state === 'error' && (
          <div className="max-w-md mx-auto">
            <Card className="border-destructive">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2 text-destructive">
                  <AlertTriangle className="h-5 w-5" />
                  Training Failed
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">{error}</p>
                <Button onClick={handleReset} variant="outline" className="w-full">
                  Try Again
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Results State */}
        {state === 'completed' && results && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid gap-4 md:grid-cols-4">
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Total Events</CardDescription>
                  <CardTitle className="text-2xl">{results.total_events.toLocaleString()}</CardTitle>
                </CardHeader>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Clusters Found</CardDescription>
                  <CardTitle className="text-2xl">{results.n_clusters}</CardTitle>
                </CardHeader>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Critical Clusters</CardDescription>
                  <CardTitle className="text-2xl text-red-500">
                    {results.summary.critical_clusters.length}
                  </CardTitle>
                </CardHeader>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>High Risk Clusters</CardDescription>
                  <CardTitle className="text-2xl text-orange-500">
                    {results.summary.high_risk_clusters.length}
                  </CardTitle>
                </CardHeader>
              </Card>
            </div>

            {/* Main Results */}
            <Tabs defaultValue="insights" className="space-y-4">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="insights">Security Insights</TabsTrigger>
                <TabsTrigger value="visualization">Visualization</TabsTrigger>
                <TabsTrigger value="clusters">Cluster Details</TabsTrigger>
                <TabsTrigger value="threats">Threat Analysis</TabsTrigger>
              </TabsList>

              <TabsContent value="insights">
                <SecurityInsights data={insights} loading={insightsLoading} />
              </TabsContent>

              <TabsContent value="visualization">
                <ClusterVisualization data={results} />
              </TabsContent>

              <TabsContent value="clusters">
                <ScrollArea className="h-[calc(100vh-400px)]">
                  <ClusterDetails clusters={results.clusters} />
                </ScrollArea>
              </TabsContent>

              <TabsContent value="threats">
                <div className="grid gap-4 md:grid-cols-2">
                  {/* Top Threat Indicators */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Top Threat Indicators</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {results.summary.top_threat_indicators.slice(0, 10).map(([indicator, count], i) => (
                          <div key={i} className="flex items-center justify-between">
                            <span className="text-sm truncate">{indicator}</span>
                            <Badge variant="outline">{count}</Badge>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  {/* Critical Clusters */}
                  <Card className="border-red-500/50">
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-red-500" />
                        Priority Clusters
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {results.clusters
                          .filter(c => c.threat_level === 'critical' || c.threat_level === 'high')
                          .map(cluster => (
                            <div key={cluster.cluster_id} className="bg-muted/50 rounded-lg p-3">
                              <div className="flex items-center justify-between mb-2">
                                <span className="font-medium">Cluster {cluster.cluster_id}</span>
                                <Badge variant={cluster.threat_level as 'critical' | 'high'}>
                                  {cluster.threat_level}
                                </Badge>
                              </div>
                              <p className="text-xs text-muted-foreground">
                                {cluster.size} events • {cluster.primary_subsystems.join(', ')}
                              </p>
                              {cluster.threat_indicators[0] && (
                                <p className="text-xs text-red-400 mt-1">
                                  {cluster.threat_indicators[0]}
                                </p>
                              )}
                            </div>
                          ))}
                        {results.clusters.filter(c => 
                          c.threat_level === 'critical' || c.threat_level === 'high'
                        ).length === 0 && (
                          <div className="text-center py-4 text-muted-foreground">
                            <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-green-500" />
                            <p className="text-sm">No critical or high-risk clusters detected</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </main>
    </div>
  )
}

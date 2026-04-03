import { useState, useEffect, useCallback } from 'react'
import {
  Shield,
  Brain,
  Network,
  AlertTriangle,
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
import { VisualizationTab } from '@/components/visualization-tab'
import { ClusterDetails } from '@/components/cluster-details'
import { ThreatAnalysis } from '@/components/threat-analysis'
import { SecurityInsights } from '@/components/security-insights'
import { EventLogUpload } from '@/components/event-log-upload'
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

export default function App() {
  const [state, setState] = useState<AppState>('idle')
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [deviceInfo, setDeviceInfo] = useState<string>('')
  const [, setSampleEvents] = useState<string[]>([])
  const [loadedEvents, setLoadedEvents] = useState<string[]>([])
  const [uploadedFilename, setUploadedFilename] = useState<string>('')
  const [jobId, setJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState<TrainingProgressType | null>(null)
  const [results, setResults] = useState<AnalysisResponse | null>(null)
  const [insights, setInsights] = useState<InsightsResponse | null>(null)
  const [insightsLoading, setInsightsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  /** Keeps the visualization (Recharts) chunk off the main path until the tab is opened */
  const [resultsTab, setResultsTab] = useState('insights')

  useEffect(() => {
    setResultsTab('insights')
  }, [jobId])

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const health = await checkHealth()
        setBackendStatus('online')
        setDeviceInfo(health.device)

        const demo = await getDemoEvents()
        setSampleEvents(demo.sample_events)
      } catch {
        setBackendStatus('offline')
      }
    }
    checkBackend()
  }, [])

  useEffect(() => {
    if (!jobId || state !== 'training') return

    let pollInterval: ReturnType<typeof setInterval> | null = null
    let abortController: AbortController | null = null
    let isPolling = false

    const poll = async () => {
      if (isPolling) return
      isPolling = true

      try {
        if (abortController) {
          abortController.abort()
        }
        abortController = new AbortController()

        const status = await getTrainingStatus(jobId, abortController.signal)
        setProgress(status)

        if (status.status === 'completed') {
          const res = await getResults(jobId)
          setResults(res)
          setState('completed')

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
        if (err instanceof Error && err.name !== 'AbortError') {
          console.error('Polling error:', err)
        }
      } finally {
        isPolling = false
      }
    }

    pollInterval = setInterval(poll, 1500)
    poll()

    return () => {
      if (pollInterval) clearInterval(pollInterval)
      if (abortController) abortController.abort()
    }
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

  const formatMetric = (value?: number) => {
    if (value === undefined || value === null || value < 0 || Number.isNaN(value)) {
      return 'N/A'
    }
    return value.toFixed(4)
  }

  return (
    <div className="min-h-screen bg-background">
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
        {state === 'idle' && (
          <div className="max-w-4xl mx-auto space-y-8">
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

        {state === 'configuring' && (
          <div className="max-w-4xl mx-auto space-y-6">
            <Button
              variant="ghost"
              className="mb-4"
              onClick={() => {
                setState('idle')
                setLoadedEvents([])
                setUploadedFilename('')
              }}
            >
              ← Back
            </Button>

            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <span>Step 1: Upload Event Log File</span>
                {uploadedFilename && (
                  <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded-full">✓ Uploaded</span>
                )}
              </h3>
              <EventLogUpload
                onEventsLoaded={(events, filename) => {
                  setLoadedEvents(events)
                  setUploadedFilename(filename)
                }}
              />
            </div>

            {uploadedFilename && (
              <div>
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                  Step 2: Configure Training
                </h3>
                <TrainingConfig
                  onSubmit={handleStartTraining}
                  isLoading={false}
                  preloadedEvents={loadedEvents}
                  preloadedFilename={uploadedFilename}
                />
              </div>
            )}
          </div>
        )}

        {state === 'training' && progress && (
          <div className="max-w-2xl mx-auto">
            <TrainingProgress progress={progress} />
          </div>
        )}

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

        {state === 'completed' && results && (
          <div className="space-y-6">
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

            <div className="grid gap-4 md:grid-cols-3">
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Silhouette Score</CardDescription>
                  <CardTitle className="text-2xl">
                    {formatMetric(results.intrinsic_metrics?.silhouette)}
                  </CardTitle>
                </CardHeader>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Davies-Bouldin Index</CardDescription>
                  <CardTitle className="text-2xl">
                    {formatMetric(results.intrinsic_metrics?.davies_bouldin)}
                  </CardTitle>
                </CardHeader>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Calinski-Harabasz Score</CardDescription>
                  <CardTitle className="text-2xl">
                    {formatMetric(results.intrinsic_metrics?.calinski_harabasz)}
                  </CardTitle>
                </CardHeader>
              </Card>
            </div>

            <Tabs value={resultsTab} onValueChange={setResultsTab} className="space-y-4">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="insights">Security Insights</TabsTrigger>
                <TabsTrigger value="visualization">Visualization</TabsTrigger>
                <TabsTrigger value="clusters">Cluster Details</TabsTrigger>
                <TabsTrigger value="threats">Threat Analysis</TabsTrigger>
              </TabsList>

              <TabsContent value="insights">
                <SecurityInsights
                  data={insights}
                  loading={insightsLoading}
                  jobId={jobId ?? undefined}
                />
              </TabsContent>

              <TabsContent value="visualization">
                {resultsTab === 'visualization' && results && (
                  <VisualizationTab data={results} />
                )}
              </TabsContent>

              <TabsContent value="clusters">
                <ScrollArea className="h-[calc(100vh-400px)]">
                  <ClusterDetails clusters={results.clusters} jobId={jobId || undefined} />
                </ScrollArea>
              </TabsContent>

              <TabsContent value="threats">
                {resultsTab === 'threats' && (
                  <ThreatAnalysis data={results} jobId={jobId || undefined} />
                )}
              </TabsContent>
            </Tabs>
          </div>
        )}
      </main>
    </div>
  )
}

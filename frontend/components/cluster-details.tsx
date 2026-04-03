"use client"

import { useState, useCallback } from "react"
import {
  Shield,
  AlertTriangle,
  Network,
  Server,
  Clock,
  ChevronDown,
  ChevronRight,
  Table2,
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import type { ClusterResult } from "@/lib/api"
import { getClusterEvents } from "@/lib/api"
import { EventsPopupTable } from "@/components/events-popup-table"
import { cn } from "@/lib/utils"

const POPUP_PAGE_SIZE = 50

interface ClusterDetailsProps {
  clusters: ClusterResult[]
  jobId?: string
}

function ThreatBadge({ level }: { level: string }) {
  const variant = level as "critical" | "high" | "medium" | "low" | "info"
  return (
    <Badge variant={variant} className="uppercase text-[10px]">
      {level}
    </Badge>
  )
}

type ClusterEventsPayload = Awaited<ReturnType<typeof getClusterEvents>>

function ClusterCard({ cluster, jobId }: { cluster: ClusterResult; jobId?: string }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [eventsDialogOpen, setEventsDialogOpen] = useState(false)
  const [clusterEventsData, setClusterEventsData] = useState<ClusterEventsPayload | null>(null)
  const [clusterEventsLoading, setClusterEventsLoading] = useState(false)
  const [clusterEventsError, setClusterEventsError] = useState<string | null>(null)

  const loadClusterEventsPage = useCallback(
    async (page: number) => {
      if (!jobId) return
      setClusterEventsLoading(true)
      setClusterEventsError(null)
      try {
        const res = await getClusterEvents(jobId, cluster.cluster_id, page, POPUP_PAGE_SIZE)
        setClusterEventsData(res)
      } catch (err) {
        setClusterEventsError(
          err instanceof Error ? err.message : "Failed to load cluster events"
        )
        setClusterEventsData(null)
      } finally {
        setClusterEventsLoading(false)
      }
    },
    [jobId, cluster.cluster_id]
  )

  const openEventsDialog = () => {
    setEventsDialogOpen(true)
    void loadClusterEventsPage(1)
  }

  const closeEventsDialog = (open: boolean) => {
    setEventsDialogOpen(open)
    if (!open) {
      setClusterEventsData(null)
      setClusterEventsError(null)
    }
  }

  return (
    <Card
      className={cn(
        "transition-all",
        cluster.threat_level === "critical" && "border-red-500/50",
        cluster.threat_level === "high" && "border-orange-500/50"
      )}
    >
      <CardHeader
        className="cursor-pointer pb-3"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <CardTitle className="text-base">Cluster {cluster.cluster_id}</CardTitle>
              <ThreatBadge level={cluster.threat_level} />
            </div>
            <CardDescription className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <Server className="h-3 w-3" />
                {cluster.size} events
              </span>
              {cluster.primary_subsystems.length > 0 && (
                <span className="flex items-center gap-1">
                  <Shield className="h-3 w-3" />
                  {cluster.primary_subsystems.join(", ")}
                </span>
              )}
            </CardDescription>
          </div>
          <Button variant="ghost" size="icon" className="h-6 w-6">
            {isExpanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </Button>
        </div>
      </CardHeader>

      {isExpanded && (
        <CardContent className="pt-0 space-y-4">
          {cluster.threat_indicators.length > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                Threat Indicators
              </h4>
              <ul className="space-y-1">
                {cluster.threat_indicators.map((indicator, i) => (
                  <li
                    key={i}
                    className="text-sm text-muted-foreground pl-5 relative before:content-['•'] before:absolute before:left-1.5"
                  >
                    {indicator}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            {cluster.top_source_ips.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                  <Network className="h-4 w-4" />
                  Top Source IPs
                </h4>
                <div className="space-y-1">
                  {cluster.top_source_ips.slice(0, 5).map(([ip, count], i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{ip}</code>
                      <span className="text-muted-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {cluster.top_dest_ports.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                  <Server className="h-4 w-4" />
                  Top Destination Ports
                </h4>
                <div className="space-y-1">
                  {cluster.top_dest_ports.slice(0, 5).map(([port, count], i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{port}</code>
                      <span className="text-muted-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {cluster.primary_actions.length > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2">Actions</h4>
              <div className="flex flex-wrap gap-1.5">
                {cluster.primary_actions.map((action, i) => (
                  <Badge key={i} variant="outline" className="text-xs">
                    {action}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {cluster.recommended_actions.length > 0 && (
            <div className="bg-muted/50 rounded-lg p-3">
              <h4 className="text-sm font-medium mb-2">Recommended Actions</h4>
              <ol className="space-y-1.5">
                {cluster.recommended_actions.map((action, i) => (
                  <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                    <span className="bg-primary text-primary-foreground w-5 h-5 rounded-full flex items-center justify-center text-xs flex-shrink-0">
                      {i + 1}
                    </span>
                    {action}
                  </li>
                ))}
              </ol>
            </div>
          )}

          <div className="rounded-lg border bg-muted/30 p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="flex items-start gap-2">
              <Clock className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />
              <div>
                <h4 className="text-sm font-medium">Cluster events</h4>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {jobId
                    ? `Open a full-screen table with pagination (${cluster.size.toLocaleString()} events in this cluster).`
                    : "Job id is required to load events from the API."}
                </p>
              </div>
            </div>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="shrink-0 gap-1.5"
              disabled={!jobId}
              onClick={(e) => {
                e.stopPropagation()
                openEventsDialog()
              }}
            >
              <Table2 className="h-4 w-4" />
              View events
            </Button>
          </div>
        </CardContent>
      )}

      <Dialog open={eventsDialogOpen} onOpenChange={closeEventsDialog}>
        <DialogContent className="max-w-[96vw] md:max-w-6xl max-h-[90vh] flex flex-col gap-0 p-6">
          <DialogHeader>
            <DialogTitle>Cluster {cluster.cluster_id} — events</DialogTitle>
            <DialogDescription>
              Paginated security events assigned to this cluster (same layout as MITRE related
              events).
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 pt-2 overflow-hidden flex flex-col min-h-0 flex-1">
            {clusterEventsData && (
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <Badge variant="outline">
                  {clusterEventsData.total_events.toLocaleString()} events
                </Badge>
                <Badge variant="outline">Cluster C{cluster.cluster_id}</Badge>
                <Badge variant="outline">
                  Page {clusterEventsData.page} / {clusterEventsData.total_pages}
                </Badge>
              </div>
            )}

            {clusterEventsLoading && (
              <div className="flex items-center justify-center py-12 text-muted-foreground">
                <div className="h-5 w-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-2" />
                Loading cluster events…
              </div>
            )}

            {clusterEventsError && !clusterEventsLoading && (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
                {clusterEventsError}
              </div>
            )}

            {!clusterEventsLoading && !clusterEventsError && clusterEventsData && (
              <EventsPopupTable
                events={clusterEventsData.events}
                page={clusterEventsData.page}
                totalPages={Math.max(1, clusterEventsData.total_pages)}
                totalEvents={clusterEventsData.total_events}
                loading={clusterEventsLoading}
                onPageChange={(p) => void loadClusterEventsPage(p)}
                disabled={!jobId}
              />
            )}
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  )
}

export function ClusterDetails({ clusters, jobId }: ClusterDetailsProps) {
  const sortedClusters = [...clusters].sort((a, b) => {
    const threatOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }
    const orderA = threatOrder[a.threat_level as keyof typeof threatOrder] ?? 5
    const orderB = threatOrder[b.threat_level as keyof typeof threatOrder] ?? 5
    return orderA - orderB || b.size - a.size
  })

  const criticalCount = clusters.filter((c) => c.threat_level === "critical").length
  const highCount = clusters.filter((c) => c.threat_level === "high").length

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4 text-sm">
        <span className="text-muted-foreground">{clusters.length} clusters analyzed</span>
        {criticalCount > 0 && <Badge variant="critical">{criticalCount} Critical</Badge>}
        {highCount > 0 && <Badge variant="high">{highCount} High Risk</Badge>}
      </div>

      <div className="space-y-3">
        {sortedClusters.map((cluster) => (
          <ClusterCard key={cluster.cluster_id} cluster={cluster} jobId={jobId} />
        ))}
      </div>
    </div>
  )
}

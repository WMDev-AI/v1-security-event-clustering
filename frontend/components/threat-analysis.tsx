"use client"

import { useState, useEffect } from "react"
import { AlertTriangle, CheckCircle2, Table2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { EventsPopupTable } from "@/components/events-popup-table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import type { AnalysisResponse, ClusterResult } from "@/lib/api"
import {
  getClusterEvents,
  getThreatIndicatorEvents,
  DEFAULT_EVENT_TABLE_QUERY,
  type ThreatIndicatorEventsResponse,
  type EventTableQuery,
} from "@/lib/api"

const PAGE_SIZE = 50

type ClusterEventsPayload = Awaited<ReturnType<typeof getClusterEvents>>
type EventsPayload = ClusterEventsPayload | ThreatIndicatorEventsResponse

type ThreatPopup =
  | { kind: "cluster"; clusterId: number }
  | { kind: "indicator"; indicator: string }

interface ThreatAnalysisProps {
  data: AnalysisResponse
  jobId?: string
}

export function ThreatAnalysis({ data, jobId }: ThreatAnalysisProps) {
  const [popup, setPopup] = useState<ThreatPopup | null>(null)
  const [eventsData, setEventsData] = useState<EventsPayload | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [eventQuery, setEventQuery] = useState<EventTableQuery>(DEFAULT_EVENT_TABLE_QUERY)

  useEffect(() => {
    if (!popup || !jobId) return
    let cancelled = false
    setLoading(true)
    setError(null)
    const run = async () => {
      try {
        if (popup.kind === "cluster") {
          const res = await getClusterEvents(jobId, popup.clusterId, PAGE_SIZE, eventQuery)
          if (!cancelled) setEventsData(res)
        } else {
          const res = await getThreatIndicatorEvents(jobId, popup.indicator, PAGE_SIZE, eventQuery)
          if (!cancelled) setEventsData(res)
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load events")
          setEventsData(null)
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [popup, jobId, eventQuery])

  const openClusterEvents = (cluster: ClusterResult) => {
    setEventQuery({ ...DEFAULT_EVENT_TABLE_QUERY })
    setPopup({ kind: "cluster", clusterId: cluster.cluster_id })
  }

  const openIndicatorEvents = (indicator: string) => {
    setEventQuery({ ...DEFAULT_EVENT_TABLE_QUERY })
    setPopup({ kind: "indicator", indicator })
  }

  const closeDialog = (open: boolean) => {
    if (!open) {
      setPopup(null)
      setEventsData(null)
      setError(null)
      setEventQuery({ ...DEFAULT_EVENT_TABLE_QUERY })
    }
  }

  const priorityClusters = data.clusters.filter(
    (c) => c.threat_level === "critical" || c.threat_level === "high"
  )

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Top Threat Indicators</CardTitle>
          <CardDescription>
            Aggregated indicator strings from cluster profiles. Open the table to see events in
            clusters that raised each indicator.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {data.summary.top_threat_indicators.slice(0, 10).map(([indicator, count], i) => (
              <div
                key={i}
                className="flex flex-col gap-2 rounded-md border border-border/60 bg-muted/20 p-2 sm:flex-row sm:items-center sm:justify-between"
              >
                <span className="text-sm break-words pr-2">{indicator}</span>
                <div className="flex shrink-0 items-center gap-2 self-end sm:self-center">
                  <Badge variant="outline">{count}</Badge>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="gap-1"
                    disabled={!jobId}
                    onClick={() => openIndicatorEvents(indicator)}
                  >
                    <Table2 className="h-3.5 w-3.5" />
                    Events
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="border-red-500/50">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500" />
            Priority Clusters
          </CardTitle>
          <CardDescription>
            Critical and high-risk clusters. View all events assigned to each cluster.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {priorityClusters.map((cluster) => (
              <div key={cluster.cluster_id} className="bg-muted/50 rounded-lg p-3 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">Cluster {cluster.cluster_id}</span>
                  <Badge variant={cluster.threat_level as "critical" | "high"}>
                    {cluster.threat_level}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  {cluster.size} events • {cluster.primary_subsystems.join(", ")}
                </p>
                {cluster.threat_indicators[0] && (
                  <p className="text-xs text-red-400">{cluster.threat_indicators[0]}</p>
                )}
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  className="w-full sm:w-auto gap-1.5"
                  disabled={!jobId}
                  onClick={() => openClusterEvents(cluster)}
                >
                  <Table2 className="h-3.5 w-3.5" />
                  View events
                </Button>
              </div>
            ))}
            {priorityClusters.length === 0 && (
              <div className="text-center py-4 text-muted-foreground">
                <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-green-500" />
                <p className="text-sm">No critical or high-risk clusters detected</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Dialog open={popup !== null} onOpenChange={closeDialog}>
        <DialogContent className="max-w-[96vw] md:max-w-6xl max-h-[90vh] flex flex-col gap-0 p-6">
          <DialogHeader>
            <DialogTitle>
              {popup?.kind === "cluster"
                ? `Cluster ${popup.clusterId} — events`
                : "Events for threat indicator"}
            </DialogTitle>
            <DialogDescription className="break-words">
              {popup?.kind === "indicator" ? (
                <span>{popup.indicator}</span>
              ) : (
                <span>Paginated events assigned to this cluster.</span>
              )}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 pt-2 overflow-hidden flex flex-col min-h-0 flex-1">
            {eventsData && (
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <Badge variant="outline">
                  {eventsData.total_events.toLocaleString()} events
                </Badge>
                {"cluster_id" in eventsData ? (
                  <Badge variant="outline">Cluster C{eventsData.cluster_id}</Badge>
                ) : (
                  <Badge variant="outline">
                    Clusters:{" "}
                    {eventsData.cluster_ids.length > 0
                      ? eventsData.cluster_ids.map((c) => `C${c}`).join(", ")
                      : "—"}
                  </Badge>
                )}
                <Badge variant="outline">
                  Page {eventsData.page} / {eventsData.total_pages}
                </Badge>
              </div>
            )}

            {loading && (
              <div className="flex items-center justify-center py-12 text-muted-foreground">
                <div className="h-5 w-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-2" />
                Loading events…
              </div>
            )}

            {error && !loading && (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
                {error}
              </div>
            )}

            {!loading && !error && eventsData && popup && (
              <EventsPopupTable
                key={
                  popup.kind === "cluster"
                    ? `c-${popup.clusterId}`
                    : `i-${popup.indicator.slice(0, 80)}`
                }
                events={eventsData.events}
                page={eventsData.page}
                totalPages={Math.max(1, eventsData.total_pages)}
                totalEvents={eventsData.total_events}
                loading={loading}
                query={eventQuery}
                onQueryChange={setEventQuery}
                disabled={!jobId}
              />
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

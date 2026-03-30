"use client"

import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Shield,
  AlertTriangle,
  Network,
  Server,
  User,
  Clock,
  ChevronDown,
  ChevronRight,
  ExternalLink,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import type { ClusterResult, SecurityEvent } from '@/lib/api'
import { getClusterEvents } from '@/lib/api'
import { cn } from '@/lib/utils'

interface ClusterDetailsProps {
  clusters: ClusterResult[]
  jobId?: string
}

function ThreatBadge({ level }: { level: string }) {
  const variant = level as 'critical' | 'high' | 'medium' | 'low' | 'info'
  return (
    <Badge variant={variant} className="uppercase text-[10px]">
      {level}
    </Badge>
  )
}

function ClusterCard({ cluster, jobId }: { cluster: ClusterResult; jobId?: string }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [displayedEvents, setDisplayedEvents] = useState<SecurityEvent[]>([])
  const [totalEvents, setTotalEvents] = useState(0)
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(0)
  const [isLoadingMore, setIsLoadingMore] = useState(false)
  const [hasLoadedInitial, setHasLoadedInitial] = useState(false)
  const scrollAreaRef = useRef<HTMLDivElement>(null)
  const loaderRef = useRef<HTMLDivElement>(null)
  const PAGE_SIZE = 30

  // Load initial events on expansion
  useEffect(() => {
    if (isExpanded && jobId && !hasLoadedInitial) {
      setHasLoadedInitial(true)
      loadPage(1)
    }
  }, [isExpanded, jobId, hasLoadedInitial])

  // Load a specific page
  const loadPage = useCallback(async (pageNum: number) => {
    if (!jobId) return
    
    try {
      setIsLoadingMore(true)
      const response = await getClusterEvents(jobId, cluster.cluster_id, pageNum, PAGE_SIZE)
      
      if (pageNum === 1) {
        // First page - replace with representative events then loaded events
        setDisplayedEvents(response.events)
      } else {
        // Subsequent pages - append to existing
        setDisplayedEvents(prev => [...prev, ...response.events])
      }
      
      setTotalEvents(response.total_events)
      setTotalPages(response.total_pages)
      setCurrentPage(pageNum)
    } catch (error) {
      console.error('Failed to load cluster events:', error)
      // On error, fall back to representative events for first page
      if (pageNum === 1) {
        setDisplayedEvents(cluster.representative_events)
      }
    } finally {
      setIsLoadingMore(false)
    }
  }, [jobId, cluster.cluster_id, cluster.representative_events])

  // Load more on scroll
  useEffect(() => {
    if (!scrollAreaRef.current || !isExpanded || isLoadingMore) return

    const scrollElement = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]') as HTMLElement
    if (!scrollElement) return

    const handleScroll = () => {
      // Check if user scrolled near bottom (within 200px)
      const isNearBottom = 
        scrollElement.scrollHeight - scrollElement.scrollTop - scrollElement.clientHeight < 200

      if (isNearBottom && currentPage < totalPages && !isLoadingMore) {
        loadPage(currentPage + 1)
      }
    }

    scrollElement.addEventListener('scroll', handleScroll)
    return () => scrollElement.removeEventListener('scroll', handleScroll)
  }, [currentPage, totalPages, isLoadingMore, isExpanded, loadPage])

  return (
    <Card className={cn(
      "transition-all",
      cluster.threat_level === 'critical' && "border-red-500/50",
      cluster.threat_level === 'high' && "border-orange-500/50"
    )}>
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
                  {cluster.primary_subsystems.join(', ')}
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
          {/* Threat Indicators */}
          {cluster.threat_indicators.length > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                Threat Indicators
              </h4>
              <ul className="space-y-1">
                {cluster.threat_indicators.map((indicator, i) => (
                  <li key={i} className="text-sm text-muted-foreground pl-5 relative before:content-['•'] before:absolute before:left-1.5">
                    {indicator}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Network Info */}
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

          {/* Actions */}
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

          {/* Recommendations */}
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

          {/* Events Table with Lazy Loading */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-medium flex items-center gap-1.5">
                <Clock className="h-4 w-4" />
                Cluster Events {totalEvents > 0 && `(${displayedEvents.length}/${totalEvents})`}
              </h4>
              {isLoadingMore && (
                <span className="text-xs text-muted-foreground flex items-center gap-1">
                  <div className="w-3 h-3 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                  Loading...
                </span>
              )}
            </div>

            <div className="border rounded-lg overflow-hidden">
              <ScrollArea ref={scrollAreaRef} className="w-full h-[500px]">
                {displayedEvents.length > 0 ? (
                  <>
                    <Table className="text-xs">
                      <TableHeader className="sticky top-0 bg-muted/80 z-10">
                        <TableRow>
                          <TableHead className="w-12">#</TableHead>
                          <TableHead className="w-24">Timestamp</TableHead>
                          <TableHead className="w-20">Source IP</TableHead>
                          <TableHead className="w-20">Dest IP</TableHead>
                          <TableHead className="w-12">Port</TableHead>
                          <TableHead className="w-16">Subsystem</TableHead>
                          <TableHead className="w-16">Action</TableHead>
                          <TableHead className="w-12">Severity</TableHead>
                          <TableHead>Content</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {displayedEvents.map((event: SecurityEvent, i: number) => (
                          <TableRow key={i} className="hover:bg-muted/50">
                            <TableCell className="font-mono text-xs">{i + 1}</TableCell>
                            <TableCell className="font-mono text-xs truncate">
                              {event.timestamp ? new Date(event.timestamp).toLocaleString('en-US', {
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                hour12: false
                              }) : '-'}
                            </TableCell>
                            <TableCell className="font-mono text-xs truncate" title={event.source_ip}>
                              {event.source_ip || '-'}
                            </TableCell>
                            <TableCell className="font-mono text-xs truncate" title={event.dest_ip}>
                              {event.dest_ip || '-'}
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {event.dest_port || '-'}
                            </TableCell>
                            <TableCell className="text-xs">
                              {event.subsystem && (
                                <Badge variant="outline" className="text-xs px-1 py-0">
                                  {event.subsystem}
                                </Badge>
                              )}
                              {!event.subsystem && '-'}
                            </TableCell>
                            <TableCell className="text-xs">
                              {event.action && (
                                <Badge variant="secondary" className="text-xs px-1 py-0">
                                  {event.action}
                                </Badge>
                              )}
                              {!event.action && '-'}
                            </TableCell>
                            <TableCell className="text-xs">
                              {event.severity && (
                                <Badge 
                                  variant={event.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info'} 
                                  className="text-xs px-1 py-0"
                                >
                                  {event.severity}
                                </Badge>
                              )}
                              {!event.severity && '-'}
                            </TableCell>
                            <TableCell className="text-xs truncate max-w-xs" title={event.content}>
                              {event.content || '-'}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>

                    {/* Loading indicator at bottom */}
                    {isLoadingMore && (
                      <div ref={loaderRef} className="flex items-center justify-center py-4">
                        <div className="w-4 h-4 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                      </div>
                    )}

                    {/* End of results message */}
                    {currentPage >= totalPages && totalEvents > 0 && (
                      <div className="flex items-center justify-center py-4 text-xs text-muted-foreground">
                        End of results ({totalEvents} total events)
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
                    No events available for this cluster
                  </div>
                )}
              </ScrollArea>
            </div>
          </div>
        </CardContent>
      )}
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

  const criticalCount = clusters.filter(c => c.threat_level === 'critical').length
  const highCount = clusters.filter(c => c.threat_level === 'high').length

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="flex items-center gap-4 text-sm">
        <span className="text-muted-foreground">
          {clusters.length} clusters analyzed
        </span>
        {criticalCount > 0 && (
          <Badge variant="critical">{criticalCount} Critical</Badge>
        )}
        {highCount > 0 && (
          <Badge variant="high">{highCount} High Risk</Badge>
        )}
      </div>

      {/* Cluster Cards */}
      <div className="space-y-3">
        {sortedClusters.map(cluster => (
          <ClusterCard key={cluster.cluster_id} cluster={cluster} jobId={jobId} />
        ))}
      </div>
    </div>
  )
}

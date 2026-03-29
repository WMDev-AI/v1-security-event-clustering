"use client"

import { useState } from 'react'
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
import type { ClusterResult } from '@/lib/api'
import { cn } from '@/lib/utils'

interface ClusterDetailsProps {
  clusters: ClusterResult[]
}

function ThreatBadge({ level }: { level: string }) {
  const variant = level as 'critical' | 'high' | 'medium' | 'low' | 'info'
  return (
    <Badge variant={variant} className="uppercase text-[10px]">
      {level}
    </Badge>
  )
}

function ClusterCard({ cluster }: { cluster: ClusterResult }) {
  const [isExpanded, setIsExpanded] = useState(false)

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

          {/* Representative Events */}
          {cluster.representative_events.length > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                <Clock className="h-4 w-4" />
                Sample Events
              </h4>
              <ScrollArea className="h-[150px]">
                <div className="space-y-2">
                  {cluster.representative_events.map((event, i) => (
                    <div key={i} className="text-xs bg-muted/50 rounded p-2 font-mono">
                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground">
                        {event.timestamp && <span>ts={String(event.timestamp)}</span>}
                        {event.source_ip && <span>src={String(event.source_ip)}</span>}
                        {event.dest_ip && <span>dst={String(event.dest_ip)}</span>}
                        {event.dest_port && <span>port={String(event.dest_port)}</span>}
                        {event.subsystem && <span>sys={String(event.subsystem)}</span>}
                        {event.action && <span>act={String(event.action)}</span>}
                        {event.severity && <span>sev={String(event.severity)}</span>}
                      </div>
                      {event.content && (
                        <div className="mt-1 text-foreground truncate">
                          content=&apos;{String(event.content)}&apos;
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  )
}

export function ClusterDetails({ clusters }: ClusterDetailsProps) {
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
          <ClusterCard key={cluster.cluster_id} cluster={cluster} />
        ))}
      </div>
    </div>
  )
}

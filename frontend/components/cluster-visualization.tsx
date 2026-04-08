"use client"

import { useMemo } from 'react'
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  Legend,
  PieChart,
  Pie,
  BarChart,
  Bar,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import type { AnalysisResponse } from '@/lib/api'

const CLUSTER_COLORS = [
  '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
  '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
  '#14b8a6', '#a855f7', '#f43f5e', '#22c55e', '#0ea5e9',
]

/** Cap scatter points so Recharts does not block the main thread on huge jobs */
const MAX_SCATTER_POINTS = 4_000

interface ClusterVisualizationProps {
  data: AnalysisResponse
}

const ALLOWED_SUBSYSTEMS = new Set([
  "ddos",
  "firewall",
  "ips",
  "appcontrol",
  "waf",
  "websec",
  "mail",
  "vpn",
])

export function ClusterVisualization({ data }: ClusterVisualizationProps) {
  const scatterTotal = data.latent_visualization?.points?.length ?? 0

  const scatterData = useMemo(() => {
    const raw = data.latent_visualization?.points
    if (!raw?.length) return []
    if (raw.length <= MAX_SCATTER_POINTS) return raw
    const step = Math.ceil(raw.length / MAX_SCATTER_POINTS)
    const out: typeof raw = []
    for (let i = 0; i < raw.length; i += step) out.push(raw[i])
    return out
  }, [data.latent_visualization])

  const threatDistData = useMemo(() => {
    if (!data.summary?.threat_distribution) return []
    return Object.entries(data.summary.threat_distribution).map(([level, count]) => ({
      name: level.charAt(0).toUpperCase() + level.slice(1),
      value: count,
      fill: level === 'critical' ? '#ef4444' :
            level === 'high' ? '#f97316' :
            level === 'medium' ? '#eab308' :
            level === 'low' ? '#3b82f6' : '#6b7280'
    }))
  }, [data.summary])

  const clusterSizeData = useMemo(() => {
    return data.clusters.map(c => ({
      name: `Cluster ${c.cluster_id}`,
      size: c.size,
      threat: c.threat_level,
      fill: CLUSTER_COLORS[c.cluster_id % CLUSTER_COLORS.length]
    })).sort((a, b) => b.size - a.size)
  }, [data.clusters])

  const clusterSizeBarData = useMemo(
    () => clusterSizeData.slice(0, 10),
    [clusterSizeData]
  )

  const subsystemData = useMemo(() => {
    const counts: Record<string, number> = {}
    data.clusters.forEach(c => {
      c.primary_subsystems.forEach(s => {
        counts[s] = (counts[s] || 0) + c.size
      })
    })
    return Object.entries(counts)
      .filter(([name]) => ALLOWED_SUBSYSTEMS.has(name))
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10)
  }, [data.clusters])

  return (
    <div className="grid gap-4">
      {/* Latent Space Visualization */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Latent Space Visualization</CardTitle>
          <CardDescription>
            2D PCA projection of event embeddings (Variance explained:{' '}
            {data.latent_visualization?.explained_variance
              ? `${(data.latent_visualization.explained_variance[0] * 100).toFixed(1)}% + ${(data.latent_visualization.explained_variance[1] * 100).toFixed(1)}%`
              : 'N/A'}
            ).
            {scatterTotal > MAX_SCATTER_POINTS && (
              <span className="block mt-1 text-amber-600/90 dark:text-amber-400/90">
                Showing {scatterData.length.toLocaleString()} of {scatterTotal.toLocaleString()} points for
                responsiveness.
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 10, bottom: 10, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  type="number"
                  dataKey="x"
                  name="PC1"
                  tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
                  axisLine={{ stroke: 'hsl(var(--border))' }}
                />
                <YAxis
                  type="number"
                  dataKey="y"
                  name="PC2"
                  tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
                  axisLine={{ stroke: 'hsl(var(--border))' }}
                />
                <ZAxis range={[20, 60]} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const point = payload[0].payload
                      return (
                        <div className="rounded-lg border bg-background p-2 shadow-sm">
                          <p className="text-xs text-muted-foreground">Cluster {point.cluster}</p>
                        </div>
                      )
                    }
                    return null
                  }}
                />
                <Legend />
                <Scatter name="Events" data={scatterData}>
                  {scatterData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={CLUSTER_COLORS[entry.cluster % CLUSTER_COLORS.length]}
                      fillOpacity={0.7}
                    />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Threat Distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Threat Level Distribution</CardTitle>
            <CardDescription>Clusters by severity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={threatDistData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                    labelLine={false}
                  >
                    {threatDistData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        return (
                          <div className="rounded-lg border bg-background p-2 shadow-sm">
                            <p className="text-sm font-medium">{payload[0].name}</p>
                            <p className="text-xs text-muted-foreground">
                              {payload[0].value} clusters
                            </p>
                          </div>
                        )
                      }
                      return null
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Cluster Sizes */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Cluster Sizes</CardTitle>
            <CardDescription>Events per cluster</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={clusterSizeBarData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis type="number" tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={70}
                    tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
                  />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const row = payload[0].payload
                        return (
                          <div className="rounded-lg border bg-background p-2 shadow-sm">
                            <p className="text-sm font-medium">{row.name}</p>
                            <p className="text-xs text-muted-foreground">
                              {row.size} events • {row.threat} threat
                            </p>
                          </div>
                        )
                      }
                      return null
                    }}
                  />
                  <Bar dataKey="size" radius={[0, 4, 4, 0]}>
                    {clusterSizeBarData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Subsystem Distribution */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Events by Subsystem</CardTitle>
          <CardDescription>Event volume for the 8 supported subsystems</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={subsystemData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
                  axisLine={{ stroke: 'hsl(var(--border))' }}
                />
                <YAxis
                  tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
                  axisLine={{ stroke: 'hsl(var(--border))' }}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="rounded-lg border bg-background p-2 shadow-sm">
                          <p className="text-sm font-medium">{payload[0].payload.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {payload[0].value} events
                          </p>
                        </div>
                      )
                    }
                    return null
                  }}
                />
                <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

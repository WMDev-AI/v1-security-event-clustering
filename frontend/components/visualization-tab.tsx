"use client"

import { Suspense, lazy, useEffect, useState } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import type { AnalysisResponse } from "@/lib/api"

const ClusterVisualization = lazy(() =>
  import("@/components/cluster-visualization").then((m) => ({
    default: m.ClusterVisualization,
  }))
)

/** Shown while the visualization chunk loads and Recharts initializes */
function VisualizationLoadFallback() {
  const [value, setValue] = useState(8)

  useEffect(() => {
    const id = window.setInterval(() => {
      setValue((v) => {
        if (v >= 92) return 18 + Math.floor(Math.random() * 12)
        return Math.min(92, v + 5 + Math.floor(Math.random() * 9))
      })
    }, 240)
    return () => window.clearInterval(id)
  }, [])

  return (
    <Card className="bg-card border-dashed">
      <CardContent className="pt-8 pb-8 space-y-4">
        <div className="space-y-1">
          <p className="text-sm font-medium">Loading visualization</p>
          <p className="text-xs text-muted-foreground">
            Fetching chart bundle and preparing the canvas. This runs only when this tab is open.
          </p>
        </div>
        <Progress value={value} className="h-2" />
      </CardContent>
    </Card>
  )
}

export function VisualizationTab({ data }: { data: AnalysisResponse }) {
  return (
    <Suspense fallback={<VisualizationLoadFallback />}>
      <ClusterVisualization data={data} />
    </Suspense>
  )
}

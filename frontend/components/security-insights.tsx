"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import type { SecurityEvent } from "@/lib/api";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface SecurityInsight {
  insight_id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  event_count: number;
  sample_events: SecurityEvent[];
  affected_subsystems: string[];
  source_ips: string[];
  target_assets: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  immediate_actions: string[];
  long_term_actions: string[];
  ioc_indicators: Array<Record<string, unknown>>;
}

interface Correlation {
  cluster_a: number;
  cluster_b: number;
  correlation_type: string;
  correlation_strength: number;
  shared_indicators: string[];
  description: string;
}

interface InsightsData {
  job_id: string;
  total_events: number;
  total_clusters: number;
  insights: SecurityInsight[];
  correlations: Correlation[];
  executive_summary: {
    overview: Record<string, number>;
    severity_distribution: Record<string, number>;
    category_distribution: Record<string, number>;
    critical_findings: Array<Record<string, unknown>>;
    high_priority_findings: Array<Record<string, unknown>>;
    mitre_coverage: {
      tactics: string[];
      techniques: string[];
    };
    top_threat_actors: string[];
    recommended_priorities: string[];
  };
  threat_landscape: {
    attack_types_detected: Record<string, number>;
    severity_distribution: Record<string, number>;
    subsystem_impact: Record<string, { event_count: number; insight_count: number }>;
    top_threat_sources: Array<{ ip: string; insights: string[]; total_events: number }>;
    most_targeted_assets: Array<{ ip: string; insights: string[]; total_events: number }>;
    cluster_risk_scores: Record<string, { score: number; level: string; factors: string[]; event_count: number }>;
  };
}

interface SecurityInsightsProps {
  data: InsightsData | null;
  loading: boolean;
}

const severityColors: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-gray-500 text-white",
};

const categoryIcons: Record<string, string> = {
  attack: "Shield",
  policy_violation: "FileWarning",
  anomaly: "Activity",
  reconnaissance: "Search",
  misconfiguration: "Settings",
};

export function SecurityInsights({ data, loading }: SecurityInsightsProps) {
  const [selectedInsight, setSelectedInsight] = useState<SecurityInsight | null>(null);
  const [activeTab, setActiveTab] = useState("overview");

  if (loading) {
    return (
      <Card className="bg-card">
        <CardContent className="flex items-center justify-center h-96">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <span className="text-muted-foreground">Generating security insights...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card className="bg-card">
        <CardContent className="flex items-center justify-center h-96">
          <span className="text-muted-foreground">
            Complete clustering to view security insights
          </span>
        </CardContent>
      </Card>
    );
  }

  const { insights, correlations, executive_summary, threat_landscape } = data;

  return (
    <div className="space-y-6">
      {/* Executive Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardDescription>Total Events</CardDescription>
            <CardTitle className="text-2xl">{data.total_events.toLocaleString()}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardDescription>Clusters Identified</CardDescription>
            <CardTitle className="text-2xl">{data.total_clusters}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardDescription>Security Insights</CardDescription>
            <CardTitle className="text-2xl">{insights.length}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardDescription>Threat IPs</CardDescription>
            <CardTitle className="text-2xl">
              {executive_summary.top_threat_actors?.length || 0}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Severity Distribution */}
      <Card className="bg-card">
        <CardHeader>
          <CardTitle>Threat Severity Distribution</CardTitle>
          <CardDescription>Breakdown of detected threats by severity level</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 flex-wrap">
            {Object.entries(executive_summary.severity_distribution || {}).map(([severity, count]) => (
              <div key={severity} className="flex items-center gap-2">
                <Badge className={severityColors[severity] || "bg-gray-500"}>
                  {severity.toUpperCase()}
                </Badge>
                <span className="text-lg font-semibold">{count as number}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Priority Actions */}
      {executive_summary.recommended_priorities && executive_summary.recommended_priorities.length > 0 && (
        <Card className="bg-card border-red-500/50">
          <CardHeader>
            <CardTitle className="text-red-400">Priority Actions Required</CardTitle>
            <CardDescription>Immediate actions recommended based on analysis</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {executive_summary.recommended_priorities.map((priority, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-red-400 font-bold">{idx + 1}.</span>
                  <span>{priority}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="insights">All Insights</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ATT&CK</TabsTrigger>
          <TabsTrigger value="correlations">Correlations</TabsTrigger>
          <TabsTrigger value="iocs">IOCs</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 mt-4">
          {/* Attack Types */}
          <Card className="bg-card">
            <CardHeader>
              <CardTitle>Attack Types Detected</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {Object.entries(threat_landscape.attack_types_detected || {}).map(([type, count]) => (
                  <div key={type} className="p-4 rounded-lg bg-muted">
                    <div className="text-sm text-muted-foreground truncate">{type}</div>
                    <div className="text-2xl font-bold">{(count as number).toLocaleString()}</div>
                    <div className="text-xs text-muted-foreground">events</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Top Threat Sources */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card">
              <CardHeader>
                <CardTitle>Top Threat Sources</CardTitle>
                <CardDescription>IPs generating the most malicious activity</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-3">
                    {(threat_landscape.top_threat_sources || []).map((source, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-3 rounded-lg bg-muted"
                      >
                        <div>
                          <div className="font-mono text-sm">{source.ip}</div>
                          <div className="text-xs text-muted-foreground">
                            {source.insights.slice(0, 2).join(", ")}
                          </div>
                        </div>
                        <Badge variant="outline">{source.total_events} events</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card className="bg-card">
              <CardHeader>
                <CardTitle>Most Targeted Assets</CardTitle>
                <CardDescription>Systems receiving the most attacks</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-3">
                    {(threat_landscape.most_targeted_assets || []).map((target, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-3 rounded-lg bg-muted"
                      >
                        <div>
                          <div className="font-mono text-sm">{target.ip}</div>
                          <div className="text-xs text-muted-foreground">
                            {target.insights.slice(0, 2).join(", ")}
                          </div>
                        </div>
                        <Badge variant="outline">{target.total_events} events</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          {/* Cluster Risk Scores */}
          <Card className="bg-card">
            <CardHeader>
              <CardTitle>Cluster Risk Assessment</CardTitle>
              <CardDescription>Risk scores for each identified cluster</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                {Object.entries(threat_landscape.cluster_risk_scores || {}).map(([clusterId, risk]) => {
                  const riskData = risk as { score: number; level: string; factors: string[]; event_count: number };
                  return (
                    <TooltipProvider key={clusterId}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div
                            className={`p-3 rounded-lg cursor-pointer transition-colors ${
                              riskData.level === "critical"
                                ? "bg-red-500/20 border border-red-500/50"
                                : riskData.level === "high"
                                ? "bg-orange-500/20 border border-orange-500/50"
                                : riskData.level === "medium"
                                ? "bg-yellow-500/20 border border-yellow-500/50"
                                : "bg-green-500/20 border border-green-500/50"
                            }`}
                          >
                            <div className="text-xs text-muted-foreground">Cluster {clusterId}</div>
                            <div className="text-xl font-bold">{riskData.score}</div>
                            <Badge
                              className={`text-xs ${
                                severityColors[riskData.level] || "bg-gray-500"
                              }`}
                            >
                              {riskData.level}
                            </Badge>
                          </div>
                        </TooltipTrigger>
                        <TooltipContent>
                          <div className="max-w-xs">
                            <div className="font-semibold mb-1">
                              {riskData.event_count} events
                            </div>
                            <div className="text-sm">
                              {riskData.factors.join(", ") || "No specific factors"}
                            </div>
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="insights" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Insights List */}
            <div className="lg:col-span-1">
              <Card className="bg-card">
                <CardHeader>
                  <CardTitle>Security Insights ({insights.length})</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[600px]">
                    <div className="space-y-2 p-4">
                      {insights.map((insight) => (
                        <div
                          key={insight.insight_id}
                          className={`p-3 rounded-lg cursor-pointer transition-colors ${
                            selectedInsight?.insight_id === insight.insight_id
                              ? "bg-primary/20 border border-primary"
                              : "bg-muted hover:bg-muted/80"
                          }`}
                          onClick={() => setSelectedInsight(insight)}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <Badge className={severityColors[insight.severity]}>
                              {insight.severity}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {insight.event_count} events
                            </span>
                          </div>
                          <div className="font-medium text-sm line-clamp-2">{insight.title}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {insight.category}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Insight Detail */}
            <div className="lg:col-span-2">
              {selectedInsight ? (
                <Card className="bg-card">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <Badge className={severityColors[selectedInsight.severity]}>
                        {selectedInsight.severity.toUpperCase()}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        Confidence: {(selectedInsight.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                    <CardTitle className="mt-2">{selectedInsight.title}</CardTitle>
                    <CardDescription>{selectedInsight.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {/* MITRE ATT&CK */}
                    {selectedInsight.mitre_techniques.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-2">MITRE ATT&CK Mapping</h4>
                        <div className="flex flex-wrap gap-2">
                          {selectedInsight.mitre_tactics.map((tactic, idx) => (
                            <Badge key={idx} variant="outline" className="text-blue-400 border-blue-400">
                              {tactic}
                            </Badge>
                          ))}
                          {selectedInsight.mitre_techniques.map((technique, idx) => (
                            <Badge key={idx} variant="secondary">
                              {technique}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Source IPs */}
                    {selectedInsight.source_ips.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-2">Source IPs</h4>
                        <div className="flex flex-wrap gap-2">
                          {selectedInsight.source_ips.map((ip, idx) => (
                            <Badge key={idx} variant="outline" className="font-mono">
                              {ip}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Immediate Actions */}
                    {selectedInsight.immediate_actions.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-2 text-red-400">Immediate Actions</h4>
                        <ul className="space-y-1">
                          {selectedInsight.immediate_actions.map((action, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-sm">
                              <span className="text-red-400">•</span>
                              {action}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Long Term Actions */}
                    {selectedInsight.long_term_actions.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-2 text-blue-400">Long-term Recommendations</h4>
                        <ul className="space-y-1">
                          {selectedInsight.long_term_actions.map((action, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-sm">
                              <span className="text-blue-400">•</span>
                              {action}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Sample Events */}
                    {selectedInsight.sample_events.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-2">Sample Events</h4>
                        <ScrollArea className="h-48">
                          <div className="space-y-2">
                            {selectedInsight.sample_events.map((event, idx) => (
                              <div key={idx} className="p-2 rounded bg-muted text-xs font-mono">
                                <div className="text-muted-foreground">
                                  {event.timestamp}
                                </div>
                                <div>
                                  {event.source_ip} -&gt; {event.dest_ip}:
                                  {event.dest_port}
                                </div>
                                {event.content && (
                                  <div className="text-muted-foreground mt-1 truncate">
                                    {event.content}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ) : (
                <Card className="bg-card">
                  <CardContent className="flex items-center justify-center h-[600px]">
                    <span className="text-muted-foreground">
                      Select an insight to view details
                    </span>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="mitre" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card">
              <CardHeader>
                <CardTitle>MITRE ATT&CK Tactics</CardTitle>
                <CardDescription>Detected attack tactics mapped to the MITRE framework</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {executive_summary.mitre_coverage?.tactics?.map((tactic, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-muted flex items-center justify-between">
                      <span className="font-medium">{tactic}</span>
                      <Badge variant="outline">Detected</Badge>
                    </div>
                  )) || (
                    <div className="text-muted-foreground">No tactics detected</div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card">
              <CardHeader>
                <CardTitle>MITRE ATT&CK Techniques</CardTitle>
                <CardDescription>Specific techniques identified in the analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-2">
                    {executive_summary.mitre_coverage?.techniques?.map((technique, idx) => (
                      <div key={idx} className="p-2 rounded-lg bg-muted">
                        <span className="text-sm">{technique}</span>
                      </div>
                    )) || (
                      <div className="text-muted-foreground">No techniques detected</div>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="correlations" className="mt-4">
          <Card className="bg-card">
            <CardHeader>
              <CardTitle>Cluster Correlations</CardTitle>
              <CardDescription>
                Relationships and potential attack chains between clusters
              </CardDescription>
            </CardHeader>
            <CardContent>
              {correlations.length > 0 ? (
                <div className="space-y-4">
                  {correlations.map((correlation, idx) => (
                    <div key={idx} className="p-4 rounded-lg bg-muted">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge>Cluster {correlation.cluster_a}</Badge>
                          <span className="text-muted-foreground">↔</span>
                          <Badge>Cluster {correlation.cluster_b}</Badge>
                        </div>
                        <Badge
                          variant="outline"
                          className={
                            correlation.correlation_type === "attack_chain"
                              ? "border-red-500 text-red-400"
                              : ""
                          }
                        >
                          {correlation.correlation_type.replace("_", " ")}
                        </Badge>
                      </div>
                      <div className="text-sm text-muted-foreground mb-2">
                        {correlation.description}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Strength:</span>
                        <div className="flex-1 h-2 bg-background rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary"
                            style={{ width: `${correlation.correlation_strength * 100}%` }}
                          />
                        </div>
                        <span className="text-xs">
                          {(correlation.correlation_strength * 100).toFixed(0)}%
                        </span>
                      </div>
                      {correlation.shared_indicators.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {correlation.shared_indicators.slice(0, 5).map((indicator, i) => (
                            <Badge key={i} variant="secondary" className="text-xs font-mono">
                              {indicator}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-muted-foreground py-8">
                  No significant correlations detected between clusters
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="iocs" className="mt-4">
          <Card className="bg-card">
            <CardHeader>
              <CardTitle>Indicators of Compromise (IOCs)</CardTitle>
              <CardDescription>
                Extracted threat indicators that can be used for detection and blocking
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Threat IPs</h4>
                  <div className="flex flex-wrap gap-2">
                    {executive_summary.top_threat_actors?.map((ip, idx) => (
                      <Badge key={idx} variant="destructive" className="font-mono">
                        {ip}
                      </Badge>
                    )) || <span className="text-muted-foreground">No threat IPs identified</span>}
                  </div>
                </div>

                <div className="mt-4 p-4 bg-muted rounded-lg">
                  <h4 className="font-semibold mb-2">Export IOCs</h4>
                  <p className="text-sm text-muted-foreground mb-3">
                    Use the API endpoint to export IOCs in various formats for integration with
                    your security tools.
                  </p>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm">
                      Export as JSON
                    </Button>
                    <Button variant="outline" size="sm">
                      Export as CSV
                    </Button>
                    <Button variant="outline" size="sm">
                      Generate Firewall Rules
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

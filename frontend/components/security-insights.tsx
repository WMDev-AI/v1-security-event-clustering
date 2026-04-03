"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  getMITREMapping,
  getMITREEvents,
  getIOCs,
  type MITREResponse,
  type SecurityEvent,
  type MITREEventsResponse,
  type MitreEventFilter,
  type IOCsResponse,
} from "@/lib/api";
import {
  exportIOCsJson,
  exportIOCsCsvFile,
  exportFirewallRulesFile,
} from "@/lib/ioc-export";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import {
  Crosshair,
  GitBranch,
  Layers,
  ShieldAlert,
  Target,
} from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

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
  /** When set, loads `/insights/{jobId}/mitre` for the enriched MITRE ATT&CK dashboard */
  jobId?: string;
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

function overallRiskStyles(risk: string): string {
  const r = (risk || "").toLowerCase();
  if (r === "critical") return "border-red-500/60 bg-red-500/10 text-red-200";
  if (r === "high") return "border-orange-500/60 bg-orange-500/10 text-orange-200";
  if (r === "medium") return "border-amber-500/60 bg-amber-500/10 text-amber-100";
  if (r === "low") return "border-sky-500/60 bg-sky-500/10 text-sky-100";
  return "border-muted bg-muted/50 text-muted-foreground";
}

function formatKillStage(stage: string): string {
  return stage
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

interface MitrePopupState {
  open: boolean;
  title: string;
  description: string;
  filter?: MitreEventFilter;
}

export function SecurityInsights({ data, loading, jobId }: SecurityInsightsProps) {
  const [selectedInsight, setSelectedInsight] = useState<SecurityInsight | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [mitreDetail, setMitreDetail] = useState<MITREResponse | null>(null);
  const [mitreLoading, setMitreLoading] = useState(false);
  const [mitreError, setMitreError] = useState<string | null>(null);
  const [mitrePopup, setMitrePopup] = useState<MitrePopupState>({
    open: false,
    title: "",
    description: "",
  });
  const [mitrePopupEvents, setMitrePopupEvents] = useState<MITREEventsResponse | null>(null);
  const [mitrePopupLoading, setMitrePopupLoading] = useState(false);
  const [mitrePopupError, setMitrePopupError] = useState<string | null>(null);
  const [iocsData, setIocsData] = useState<IOCsResponse | null>(null);
  const [iocsLoading, setIocsLoading] = useState(false);
  const [iocsError, setIocsError] = useState<string | null>(null);

  const fetchIOCs = useCallback(async (id: string) => {
    setIocsLoading(true);
    setIocsError(null);
    try {
      const res = await getIOCs(id);
      setIocsData(res);
    } catch (err) {
      setIocsError(err instanceof Error ? err.message : "Failed to load IOCs");
      setIocsData(null);
    } finally {
      setIocsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab !== "iocs") return;
    const id = jobId ?? data?.job_id;
    if (!id) return;
    void fetchIOCs(id);
  }, [activeTab, jobId, data?.job_id, fetchIOCs]);

  useEffect(() => {
    if (!jobId || !data) {
      setMitreDetail(null);
      setMitreError(null);
      return;
    }
    let cancelled = false;
    setMitreLoading(true);
    setMitreError(null);
    getMITREMapping(jobId)
      .then((res) => {
        if (!cancelled) setMitreDetail(res);
      })
      .catch((err: Error) => {
        if (!cancelled) setMitreError(err.message || "Failed to load MITRE mapping");
      })
      .finally(() => {
        if (!cancelled) setMitreLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, data?.job_id]);

  const loadMitrePopupEvents = async (filter: MitreEventFilter, page = 1) => {
    if (!jobId) return;
    setMitrePopupLoading(true);
    setMitrePopupError(null);
    try {
      const res = await getMITREEvents(jobId, { ...filter, page, limit: 50 });
      setMitrePopupEvents(res);
    } catch (err) {
      setMitrePopupError(err instanceof Error ? err.message : "Failed to load related events");
      setMitrePopupEvents(null);
    } finally {
      setMitrePopupLoading(false);
    }
  };

  const openMitrePopup = (title: string, description: string, filter: MitreEventFilter) => {
    setMitrePopup({ open: true, title, description, filter });
    void loadMitrePopupEvents(filter, 1);
  };

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

        <TabsContent value="mitre" className="mt-4 space-y-4">
          {mitreLoading && (
            <Card className="bg-card border-dashed">
              <CardContent className="flex items-center justify-center gap-3 py-12">
                <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <span className="text-muted-foreground">Loading MITRE ATT&CK coverage from API…</span>
              </CardContent>
            </Card>
          )}

          {mitreError && (
            <Card className="bg-card border-amber-500/40">
              <CardContent className="py-4 text-sm text-amber-200/90">
                {mitreError} — showing executive-summary MITRE lists only below.
              </CardContent>
            </Card>
          )}

          {/* Summary strip — from /insights/{job}/mitre when available */}
          {mitreDetail && !mitreLoading && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Card className="bg-card border-border/80">
                  <CardHeader className="pb-2">
                    <CardDescription className="flex items-center gap-1.5">
                      <Layers className="h-3.5 w-3.5" />
                      Tactics (enterprise)
                    </CardDescription>
                    <CardTitle className="text-2xl tabular-nums">{mitreDetail.total_tactics}</CardTitle>
                  </CardHeader>
                </Card>
                <Card className="bg-card border-border/80">
                  <CardHeader className="pb-2">
                    <CardDescription className="flex items-center gap-1.5">
                      <Crosshair className="h-3.5 w-3.5" />
                      Techniques
                    </CardDescription>
                    <CardTitle className="text-2xl tabular-nums">{mitreDetail.total_techniques}</CardTitle>
                  </CardHeader>
                </Card>
                <Card className="bg-card border-border/80">
                  <CardHeader className="pb-2">
                    <CardDescription className="flex items-center gap-1.5">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Overall risk
                    </CardDescription>
                    <CardTitle className="text-lg">
                      <span
                        className={`inline-flex rounded-md border px-2 py-0.5 font-semibold ${overallRiskStyles(
                          mitreDetail.coverage_assessment?.overall_risk || ""
                        )}`}
                      >
                        {mitreDetail.coverage_assessment?.overall_risk || "—"}
                      </span>
                    </CardTitle>
                  </CardHeader>
                </Card>
                <Card className="bg-card border-border/80">
                  <CardHeader className="pb-2">
                    <CardDescription className="flex items-center gap-1.5">
                      <Target className="h-3.5 w-3.5" />
                      High-impact tactic coverage
                    </CardDescription>
                    <CardTitle className="text-2xl tabular-nums">
                      {Math.round(mitreDetail.coverage_assessment?.high_impact_coverage ?? 0)}%
                    </CardTitle>
                  </CardHeader>
                </Card>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card className="bg-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-base">
                      <GitBranch className="h-4 w-4 text-primary" />
                      Kill chain view
                    </CardTitle>
                    <CardDescription>
                      {mitreDetail.kill_chain_analysis?.assessment || "Assessment from detected tactics"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex justify-between text-xs text-muted-foreground mb-1.5">
                        <span>Attack progression (stages represented)</span>
                        <span className="tabular-nums">
                          {Math.round(mitreDetail.kill_chain_analysis?.attack_progression ?? 0)}%
                        </span>
                      </div>
                      <Progress
                        value={Math.min(100, Math.max(0, mitreDetail.kill_chain_analysis?.attack_progression ?? 0))}
                        className="h-2"
                      />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Stages with matching tactic families</p>
                      <div className="flex flex-wrap gap-1.5">
                        {(mitreDetail.kill_chain_analysis?.stages_detected || []).length > 0 ? (
                          mitreDetail.kill_chain_analysis.stages_detected.map((s) => (
                            <Button
                              key={s}
                              variant="secondary"
                              size="sm"
                              className="h-auto py-1"
                              onClick={() =>
                                openMitrePopup(
                                  `Kill Chain Stage: ${formatKillStage(s)}`,
                                  "Events from clusters mapped to tactics in this kill-chain stage.",
                                  { type: "kill_chain_stage", value: s }
                                )
                              }
                            >
                              {formatKillStage(s)}
                            </Button>
                          ))
                        ) : (
                          <span className="text-sm text-muted-foreground">No kill-chain stages inferred</span>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-card">
                  <CardHeader>
                    <CardTitle className="text-base">High-impact tactics detected</CardTitle>
                    <CardDescription>
                      Subset of enterprise tactics considered high impact for SOC prioritization
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-1.5 mb-3">
                      {(mitreDetail.coverage_assessment?.high_impact_tactics_detected || []).length > 0 ? (
                        mitreDetail.coverage_assessment.high_impact_tactics_detected.map((t) => (
                          <Button
                            key={t}
                            variant="outline"
                            size="sm"
                            className="h-auto py-1 border-orange-500/50 text-orange-100/90"
                            onClick={() =>
                              openMitrePopup(
                                `High-Impact Tactic: ${t}`,
                                "Events from clusters whose insights include this MITRE tactic.",
                                { type: "tactic", value: t }
                              )
                            }
                          >
                            {t}
                          </Button>
                        ))
                      ) : (
                        <span className="text-sm text-muted-foreground">None in the high-impact watchlist</span>
                      )}
                    </div>
                    <div>
                      <div className="flex justify-between text-xs text-muted-foreground mb-1">
                        <span>Share of watchlist tactics seen</span>
                        <span>
                          {mitreDetail.coverage_assessment?.high_impact_tactics_detected?.length ?? 0} / 5
                        </span>
                      </div>
                      <Progress
                        value={Math.min(
                          100,
                          Math.max(0, mitreDetail.coverage_assessment?.high_impact_coverage ?? 0)
                        )}
                        className="h-2"
                      />
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Event-weighted tactics */}
              {(() => {
                const chartData = Object.entries(mitreDetail.tactics_coverage || {})
                  .map(([tactic, info]) => ({
                    label: tactic.length > 22 ? `${tactic.slice(0, 20)}…` : tactic,
                    full: tactic,
                    events: info.event_count,
                  }))
                  .sort((a, b) => b.events - a.events)
                  .slice(0, 14);
                if (chartData.length === 0) return null;
                return (
                  <Card className="bg-card">
                    <CardHeader>
                      <CardTitle className="text-base">Tactic exposure by event weight</CardTitle>
                      <CardDescription>
                        Aggregated insight-level event counts per MITRE tactic (heuristic mapping from cluster
                        insights)
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="h-[280px] w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 16, top: 8, bottom: 8 }}>
                          <CartesianGrid strokeDasharray="3 3" className="stroke-muted/40" horizontal={false} />
                          <XAxis type="number" tick={{ fontSize: 11 }} allowDecimals={false} />
                          <YAxis
                            type="category"
                            dataKey="label"
                            width={120}
                            tick={{ fontSize: 10 }}
                            interval={0}
                          />
                          <RechartsTooltip
                            formatter={(value: number) => [value, "Weighted events"]}
                            labelFormatter={(_, payload) => {
                              const p = payload as { payload?: { full?: string } }[] | undefined;
                              return p?.[0]?.payload?.full != null ? String(p[0].payload.full) : "";
                            }}
                            contentStyle={{
                              backgroundColor: "hsl(var(--card))",
                              border: "1px solid hsl(var(--border))",
                              borderRadius: "8px",
                              fontSize: "12px",
                            }}
                          />
                          <Bar
                            dataKey="events"
                            fill="#3b82f6"
                            radius={[0, 4, 4, 0]}
                            onClick={(entry: { full?: string } | undefined) => {
                              const tactic = entry?.full;
                              if (!tactic) return;
                              openMitrePopup(
                                `Tactic Exposure: ${tactic}`,
                                "Events from clusters mapped to this tactic (bar-chart selection).",
                                { type: "tactic", value: tactic }
                              );
                            }}
                          />
                        </BarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                );
              })()}

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <Card className="bg-card">
                  <CardHeader>
                    <CardTitle className="text-base">Tactics → techniques & insight titles</CardTitle>
                    <CardDescription>Per-tactic rollup from cluster insight analysis</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[320px] pr-3">
                      <div className="space-y-3">
                        {Object.entries(mitreDetail.tactics_coverage || {}).length > 0 ? (
                          Object.entries(mitreDetail.tactics_coverage)
                            .sort((a, b) => b[1].event_count - a[1].event_count)
                            .map(([tactic, info]) => (
                              <button
                                key={tactic}
                                className="w-full text-left rounded-lg border border-border/60 bg-muted/30 p-3 space-y-2 hover:border-primary/50 transition-colors"
                                onClick={() =>
                                  openMitrePopup(
                                    `Tactic: ${tactic}`,
                                    "Events from clusters whose insights include this tactic.",
                                    { type: "tactic", value: tactic }
                                  )
                                }
                              >
                                <div className="flex items-start justify-between gap-2">
                                  <span className="font-medium text-sm leading-snug">{tactic}</span>
                                  <Badge variant="secondary" className="shrink-0 tabular-nums">
                                    {info.event_count} evt
                                  </Badge>
                                </div>
                                {info.techniques?.length > 0 && (
                                  <div className="flex flex-wrap gap-1">
                                    {info.techniques.map((tech) => (
                                      <Badge key={tech} variant="outline" className="text-xs font-mono font-normal">
                                        {tech}
                                      </Badge>
                                    ))}
                                  </div>
                                )}
                                {info.insights?.length > 0 && (
                                  <ul className="text-xs text-muted-foreground list-disc pl-4 space-y-0.5">
                                    {info.insights.slice(0, 5).map((title) => (
                                      <li key={title}>{title}</li>
                                    ))}
                                  </ul>
                                )}
                              </button>
                            ))
                        ) : (
                          <p className="text-sm text-muted-foreground">No tactic buckets in this run</p>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>

                <Card className="bg-card">
                  <CardHeader>
                    <CardTitle className="text-base">Techniques → clusters</CardTitle>
                    <CardDescription>Technique strings with contributing clusters and event weight</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[320px] pr-3">
                      <div className="space-y-2">
                        {Object.entries(mitreDetail.techniques_detected || {}).length > 0 ? (
                          Object.entries(mitreDetail.techniques_detected)
                            .sort((a, b) => b[1].event_count - a[1].event_count)
                            .map(([technique, info]) => (
                              <button
                                key={technique}
                                className="w-full text-left rounded-md border border-border/50 bg-background/50 p-2.5 flex flex-col gap-1.5 hover:border-primary/50 transition-colors"
                                onClick={() =>
                                  openMitrePopup(
                                    `Technique: ${technique}`,
                                    "Events from clusters whose insights include this MITRE technique.",
                                    { type: "technique", value: technique }
                                  )
                                }
                              >
                                <div className="flex justify-between gap-2">
                                  <span className="text-sm font-mono leading-tight">{technique}</span>
                                  <Badge variant="secondary" className="shrink-0 tabular-nums text-xs">
                                    {info.event_count}
                                  </Badge>
                                </div>
                                <div className="flex flex-wrap gap-1">
                                  {(info.clusters || []).map((c) => (
                                    <Badge key={c} variant="outline" className="text-[10px] px-1.5 py-0">
                                      C{c}
                                    </Badge>
                                  ))}
                                </div>
                              </button>
                            ))
                        ) : (
                          <p className="text-sm text-muted-foreground">No techniques extracted</p>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </div>

              {mitreDetail.mitigation_priorities?.length > 0 && (
                <Card className="bg-card border-primary/20">
                  <CardHeader>
                    <CardTitle className="text-base">Mitigation priorities</CardTitle>
                    <CardDescription>
                      Template recommendations keyed to known technique IDs (see backend mapping)
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid gap-3 md:grid-cols-2">
                      {(mitreDetail.mitigation_priorities ?? []).map((row) => (
                        <button
                          key={row.technique}
                          className="w-full text-left rounded-lg border border-border/60 bg-muted/20 p-3 space-y-2 hover:border-primary/50 transition-colors"
                          onClick={() =>
                            openMitrePopup(
                              `Mitigation Priority: ${row.technique}`,
                              "Events tied to this priority technique from MITRE mappings.",
                              { type: "technique", value: row.technique }
                            )
                          }
                        >
                          <div className="flex justify-between gap-2">
                            <span className="text-sm font-mono font-medium leading-snug">{row.technique}</span>
                            <Badge variant="outline" className="shrink-0 tabular-nums">
                              {row.event_count} evt
                            </Badge>
                          </div>
                          <ul className="text-xs text-muted-foreground space-y-1 list-disc pl-4">
                            {(row.recommended_mitigations || []).map((m, i) => (
                              <li key={i}>{m}</li>
                            ))}
                          </ul>
                        </button>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          )}

          {/* Fallback: executive summary lists when detailed MITRE API unavailable */}
          {!mitreLoading && (!mitreDetail || mitreError) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="bg-card">
                <CardHeader>
                  <CardTitle>MITRE ATT&CK Tactics</CardTitle>
                  <CardDescription>Executive summary — detected tactic names</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {executive_summary.mitre_coverage?.tactics?.map((tactic, idx) => (
                      <div key={idx} className="p-3 rounded-lg bg-muted flex items-center justify-between">
                        <span className="font-medium">{tactic}</span>
                        <Badge variant="outline">Detected</Badge>
                      </div>
                    )) || (
                      <div className="text-muted-foreground">No tactics in executive summary</div>
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-card">
                <CardHeader>
                  <CardTitle>MITRE ATT&CK Techniques</CardTitle>
                  <CardDescription>Executive summary — technique strings</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-64">
                    <div className="space-y-2">
                      {executive_summary.mitre_coverage?.techniques?.map((technique, idx) => (
                        <div key={idx} className="p-2 rounded-lg bg-muted">
                          <span className="text-sm">{technique}</span>
                        </div>
                      )) || (
                        <div className="text-muted-foreground">No techniques in executive summary</div>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          )}

          {!jobId && !mitreLoading && (
            <p className="text-xs text-center text-muted-foreground">
              Detailed MITRE coverage loads when a training job id is available (completed run).
            </p>
          )}
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
                {iocsLoading && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    Loading IOCs from analysis…
                  </div>
                )}
                {iocsError && (
                  <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm flex flex-wrap items-center gap-2">
                    <span>{iocsError}</span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => void fetchIOCs(jobId ?? data.job_id)}
                    >
                      Retry
                    </Button>
                  </div>
                )}

                <div>
                  <h4 className="font-semibold mb-2">Threat IPs</h4>
                  <div className="flex flex-wrap gap-2">
                    {iocsData && iocsData.malicious_ips.length > 0 ? (
                      <TooltipProvider delayDuration={300}>
                        {iocsData.malicious_ips.map((row) => (
                          <Tooltip key={row.ip}>
                            <TooltipTrigger asChild>
                              <Badge
                                variant="destructive"
                                className={`font-mono cursor-default ${severityColors[row.severity] ?? ""}`}
                              >
                                {row.ip}
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-xs">
                              <p className="font-semibold capitalize">{row.severity}</p>
                              <p className="text-xs text-muted-foreground">
                                {row.event_count.toLocaleString()} events · {row.recommendation}
                              </p>
                              {row.contexts.length > 0 && (
                                <p className="text-xs mt-1">{row.contexts.join(" · ")}</p>
                              )}
                            </TooltipContent>
                          </Tooltip>
                        ))}
                      </TooltipProvider>
                    ) : !iocsLoading && !iocsError ? (
                      executive_summary.top_threat_actors?.map((ip, idx) => (
                        <Badge key={idx} variant="destructive" className="font-mono">
                          {ip}
                        </Badge>
                      ))
                    ) : null}
                    {!iocsLoading &&
                      !iocsError &&
                      (!iocsData || iocsData.malicious_ips.length === 0) &&
                      (!executive_summary.top_threat_actors ||
                        executive_summary.top_threat_actors.length === 0) && (
                        <span className="text-muted-foreground">No threat IPs identified</span>
                      )}
                  </div>
                  {iocsData && iocsData.total_unique_threat_ips > 0 && (
                    <p className="text-xs text-muted-foreground mt-2">
                      {iocsData.total_unique_threat_ips.toLocaleString()} unique threat IPs in
                      corpus (showing top {iocsData.malicious_ips.length})
                    </p>
                  )}
                </div>

                <div className="mt-4 p-4 bg-muted rounded-lg">
                  <h4 className="font-semibold mb-2">Export IOCs</h4>
                  <p className="text-sm text-muted-foreground mb-3">
                    Download the full IOC payload (JSON), a spreadsheet-friendly CSV, or suggested
                    firewall rules as a text summary plus embedded JSON.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={iocsLoading || !iocsData || !!iocsError}
                      onClick={() => iocsData && exportIOCsJson(iocsData)}
                    >
                      Export as JSON
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={iocsLoading || !iocsData || !!iocsError}
                      onClick={() => iocsData && exportIOCsCsvFile(iocsData)}
                    >
                      Export as CSV
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={iocsLoading || !iocsData || !!iocsError}
                      onClick={() => iocsData && exportFirewallRulesFile(iocsData)}
                    >
                      Generate Firewall Rules
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog
        open={mitrePopup.open}
        onOpenChange={(open) => {
          setMitrePopup((prev) => ({ ...prev, open }));
          if (!open) {
            setMitrePopupEvents(null);
            setMitrePopupError(null);
          }
        }}
      >
        <DialogContent className="max-w-[96vw] md:max-w-6xl">
          <DialogHeader>
            <DialogTitle>{mitrePopup.title || "MITRE Related Events"}</DialogTitle>
            <DialogDescription>{mitrePopup.description}</DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            {mitrePopupEvents && (
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <Badge variant="outline">
                  {mitrePopupEvents.total_events.toLocaleString()} events
                </Badge>
                <Badge variant="outline">
                  Clusters:{" "}
                  {mitrePopupEvents.cluster_ids.length > 0
                    ? mitrePopupEvents.cluster_ids.map((c) => `C${c}`).join(", ")
                    : "none"}
                </Badge>
                <Badge variant="outline">
                  Page {mitrePopupEvents.page} / {mitrePopupEvents.total_pages}
                </Badge>
              </div>
            )}

            {mitrePopupLoading && (
              <div className="flex items-center justify-center py-12 text-muted-foreground">
                <div className="h-5 w-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-2" />
                Loading related events…
              </div>
            )}

            {mitrePopupError && !mitrePopupLoading && (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
                {mitrePopupError}
              </div>
            )}

            {!mitrePopupLoading && !mitrePopupError && mitrePopupEvents && (
              <>
                <ScrollArea className="h-[56vh] rounded-md border">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 z-10 bg-muted/80 backdrop-blur">
                      <tr className="text-left">
                        <th className="px-3 py-2 font-medium w-[70px]">#</th>
                        <th className="px-3 py-2 font-medium w-[170px]">Time</th>
                        <th className="px-3 py-2 font-medium w-[140px]">Source</th>
                        <th className="px-3 py-2 font-medium w-[160px]">Destination</th>
                        <th className="px-3 py-2 font-medium w-[90px]">Port</th>
                        <th className="px-3 py-2 font-medium w-[120px]">Subsystem</th>
                        <th className="px-3 py-2 font-medium w-[120px]">Action</th>
                        <th className="px-3 py-2 font-medium w-[100px]">Severity</th>
                        <th className="px-3 py-2 font-medium">Content</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mitrePopupEvents.events.map((e) => (
                        <tr key={e.index} className="border-t border-border/50 align-top">
                          <td className="px-3 py-2 text-xs text-muted-foreground">{e.index}</td>
                          <td className="px-3 py-2 font-mono text-xs">{e.timestamp || "-"}</td>
                          <td className="px-3 py-2 font-mono text-xs">{e.source_ip || "-"}</td>
                          <td className="px-3 py-2 font-mono text-xs">{e.dest_ip || "-"}</td>
                          <td className="px-3 py-2 text-xs">{e.dest_port ?? "-"}</td>
                          <td className="px-3 py-2 text-xs">{e.subsystem || "-"}</td>
                          <td className="px-3 py-2 text-xs">{e.action || "-"}</td>
                          <td className="px-3 py-2 text-xs">{e.severity || "-"}</td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">{e.content || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </ScrollArea>

                <div className="flex items-center justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={mitrePopupEvents.page <= 1 || mitrePopupLoading || !mitrePopup.filter}
                    onClick={() => {
                      if (!mitrePopup.filter) return;
                      void loadMitrePopupEvents(mitrePopup.filter, mitrePopupEvents.page - 1);
                    }}
                  >
                    Previous
                  </Button>
                  <span className="text-xs text-muted-foreground">
                    Showing {mitrePopupEvents.events.length} rows
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={
                      mitrePopupEvents.page >= mitrePopupEvents.total_pages ||
                      mitrePopupLoading ||
                      !mitrePopup.filter
                    }
                    onClick={() => {
                      if (!mitrePopup.filter) return;
                      void loadMitrePopupEvents(mitrePopup.filter, mitrePopupEvents.page + 1);
                    }}
                  >
                    Next
                  </Button>
                </div>
              </>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

import type { IOCsResponse } from "@/lib/api";

export function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value: unknown): string {
  if (value == null) return "";
  const s = String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Multi-section CSV for spreadsheets: malicious IPs, patterns, users, firewall rules */
export function buildIOCsCsv(data: IOCsResponse): string {
  const lines: string[] = [];

  lines.push("# IOC export");
  lines.push(`# job_id,${csvCell(data.job_id)}`);
  lines.push(`# generated_at,${csvCell(data.generated_at)}`);
  lines.push("");

  lines.push("## malicious_ips");
  lines.push("ip,contexts,event_count,severity,recommendation");
  for (const row of data.malicious_ips) {
    lines.push(
      [
        csvCell(row.ip),
        csvCell(row.contexts.join("; ")),
        csvCell(row.event_count),
        csvCell(row.severity),
        csvCell(row.recommendation),
      ].join(",")
    );
  }

  lines.push("");
  lines.push("## attack_patterns");
  lines.push("pattern,description,mitre_techniques,source_ips,severity");
  for (const row of data.attack_patterns) {
    lines.push(
      [
        csvCell(row.pattern),
        csvCell(row.description),
        csvCell(row.mitre_techniques.join("; ")),
        csvCell(row.source_ips.join("; ")),
        csvCell(row.severity),
      ].join(",")
    );
  }

  lines.push("");
  lines.push("## suspicious_users");
  lines.push("user,reasons,event_count");
  for (const row of data.suspicious_users) {
    lines.push(
      [csvCell(row.user), csvCell(row.reasons.join("; ")), csvCell(row.event_count)].join(",")
    );
  }

  lines.push("");
  lines.push("## firewall_rules");
  lines.push(
    "rule_type,priority,description,direction,action,ips,ports,max_connections_per_minute"
  );
  for (const r of data.firewall_rules) {
    lines.push(
      [
        csvCell(r.rule_type),
        csvCell(r.priority),
        csvCell(r.description),
        csvCell(r.direction ?? ""),
        csvCell(r.action ?? ""),
        csvCell((r.ips ?? []).join("; ")),
        csvCell((r.ports ?? []).join("; ")),
        csvCell(r.max_connections_per_minute ?? ""),
      ].join(",")
    );
  }

  return lines.join("\n");
}

/** Human-readable firewall suggestions for SOC handoff */
export function buildFirewallRulesText(data: IOCsResponse): string {
  const out: string[] = [];
  out.push("Firewall rule suggestions (heuristic — validate before production use)");
  out.push(`Job ID: ${data.job_id}`);
  out.push(`Generated: ${data.generated_at}`);
  out.push(`Threat IPs in corpus: ${data.total_unique_threat_ips}`);
  out.push("");
  if (!data.firewall_rules.length) {
    out.push("No automated rules were generated for this dataset (insufficient high-severity IOCs / patterns).");
    out.push("");
    out.push("JSON machine-readable copy (empty rules array):");
    out.push(JSON.stringify({ job_id: data.job_id, generated_at: data.generated_at, firewall_rules: [] }, null, 2));
    return out.join("\n");
  }
  data.firewall_rules.forEach((r, i) => {
    out.push(`--- Rule ${i + 1}: ${r.rule_type} (priority ${r.priority}) ---`);
    out.push(r.description);
    if (r.direction) out.push(`  Direction: ${r.direction}`);
    if (r.action) out.push(`  Action: ${r.action}`);
    if (r.ips?.length) out.push(`  IPs: ${r.ips.join(", ")}`);
    if (r.ports?.length) out.push(`  Ports: ${r.ports.join(", ")}`);
    if (r.max_connections_per_minute != null)
      out.push(`  Max connections/min: ${r.max_connections_per_minute}`);
    out.push("");
  });
  out.push("--- JSON (same rules, for automation) ---");
  out.push(JSON.stringify({ job_id: data.job_id, generated_at: data.generated_at, firewall_rules: data.firewall_rules }, null, 2));
  return out.join("\n");
}

export function exportIOCsJson(data: IOCsResponse): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  downloadBlob(`iocs-${data.job_id}.json`, blob);
}

export function exportIOCsCsvFile(data: IOCsResponse): void {
  const blob = new Blob([buildIOCsCsv(data)], { type: "text/csv;charset=utf-8" });
  downloadBlob(`iocs-${data.job_id}.csv`, blob);
}

export function exportFirewallRulesFile(data: IOCsResponse): void {
  const blob = new Blob([buildFirewallRulesText(data)], {
    type: "text/plain;charset=utf-8",
  });
  downloadBlob(`firewall-suggestions-${data.job_id}.txt`, blob);
}

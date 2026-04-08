"use client"

import { useState, useEffect, useRef, useMemo } from "react"
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronDown, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import type { SecurityEvent, EventTableQuery, EventTableSortColumn } from "@/lib/api"
import { formatEventDateTime } from "@/lib/format-event-datetime"
import { cn } from "@/lib/utils"

export type EventTableRow = SecurityEvent & { index?: number }

const COLUMNS: { key: EventTableSortColumn; label: string; width: string }[] = [
  { key: "index", label: "#", width: "w-[72px]" },
  { key: "timestamp", label: "Time", width: "min-w-[180px]" },
  { key: "source_ip", label: "Source", width: "min-w-[120px]" },
  { key: "dest_ip", label: "Destination", width: "min-w-[120px]" },
  { key: "dest_port", label: "Port", width: "w-[72px]" },
  { key: "subsystem", label: "Subsystem", width: "min-w-[100px]" },
  { key: "action", label: "Action", width: "min-w-[90px]" },
  { key: "severity", label: "Severity", width: "min-w-[80px]" },
  { key: "content", label: "Content", width: "min-w-[160px]" },
]

const inputClass =
  "h-7 w-full min-w-0 rounded border border-input bg-background px-1.5 text-[11px] placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"

const FILTER_DEBOUNCE_MS = 350
const SUBSYSTEMS = ["ddos", "firewall", "ips", "appcontrol", "waf", "websec", "mail", "vpn"] as const
const CORE_KEYS = new Set([
  "index",
  "timestamp",
  "source_ip",
  "dest_ip",
  "dest_port",
  "subsystem",
  "action",
  "severity",
  "content",
])

function renderExtraFields(e: EventTableRow): string[] {
  const out: string[] = []
  const row = e as Record<string, unknown>
  const pushIf = (label: string, value: unknown) => {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      out.push(`${label}: ${String(value)}`)
    }
  }

  pushIf("rule", row["rule"])
  pushIf("attacktype", row["ddos_attack_type"])
  pushIf("groupid", row["ips_groupid"])
  pushIf("vhost", row["waf_vhost"])
  pushIf("serverity", row["mail_severity"])
  pushIf("reason", row["reason"] ?? row["ips_reason"])
  pushIf(
    "count",
    row["ddos_count"] ?? row["fw_count"] ?? row["app_count"] ?? row["waf_count"] ?? row["vpn_count"]
  )

  return out.slice(0, 4)
}

export interface EventsPopupTableProps {
  events: EventTableRow[]
  page: number
  totalPages: number
  totalEvents: number
  loading?: boolean
  disabled?: boolean
  query: EventTableQuery
  onQueryChange: (next: EventTableQuery) => void
}

export function EventsPopupTable({
  events,
  page,
  totalPages,
  totalEvents,
  loading = false,
  disabled = false,
  query,
  onQueryChange,
}: EventsPopupTableProps) {
  const [pageInput, setPageInput] = useState(String(page))
  const [filterDraft, setFilterDraft] = useState(query.filters)
  const [selectedEventKey, setSelectedEventKey] = useState<string | null>(null)
  const [showAttributes, setShowAttributes] = useState(true)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    setPageInput(String(page))
  }, [page])

  useEffect(() => {
    setFilterDraft(query.filters)
  }, [query.filters])

  const toggleSort = (key: EventTableSortColumn) => {
    if (query.sortBy === key) {
      onQueryChange({
        ...query,
        sortDir: query.sortDir === "asc" ? "desc" : "asc",
        page: 1,
      })
    } else {
      onQueryChange({
        ...query,
        sortBy: key,
        sortDir: "asc",
        page: 1,
      })
    }
  }

  const scheduleFilterCommit = (nextFilters: Partial<Record<EventTableSortColumn, string>>) => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      onQueryChange({ ...query, filters: nextFilters, page: 1 })
    }, FILTER_DEBOUNCE_MS)
  }

  const onFilterChange = (key: EventTableSortColumn, value: string) => {
    const next = { ...filterDraft, [key]: value }
    setFilterDraft(next)
    scheduleFilterCommit(next)
  }

  const goToPage = () => {
    const n = parseInt(pageInput, 10)
    if (Number.isNaN(n)) return
    const max = Math.max(1, totalPages)
    const clamped = Math.min(Math.max(1, n), max)
    onQueryChange({ ...query, page: clamped })
  }

  const SortIcon = ({ col }: { col: EventTableSortColumn }) => {
    if (query.sortBy !== col) return <ArrowUpDown className="h-3 w-3 opacity-50" />
    return query.sortDir === "asc" ? (
      <ArrowUp className="h-3 w-3" />
    ) : (
      <ArrowDown className="h-3 w-3" />
    )
  }

  const rowKey = (e: EventTableRow, rowIdx: number) =>
    e.index !== undefined ? `i-${e.index}` : `r-${rowIdx}-${String(e.timestamp ?? "")}`

  const selectedEvent = useMemo(
    () => events.find((e, idx) => rowKey(e, idx) === selectedEventKey) ?? null,
    [events, selectedEventKey]
  )

  const selectedAttributes = useMemo(() => {
    if (!selectedEvent) return []
    return Object.entries(selectedEvent as Record<string, unknown>)
      .filter(([k, v]) => !CORE_KEYS.has(k) && v !== undefined && v !== null && String(v).trim() !== "")
      .sort(([a], [b]) => a.localeCompare(b))
  }, [selectedEvent])

  return (
    <div className="space-y-3">
      <ScrollArea className="h-[56vh] rounded-md border">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-20 bg-muted/95 backdrop-blur supports-[backdrop-filter]:bg-muted/80">
            <tr className="text-left">
              {COLUMNS.map((col) => (
                <th key={col.key} className={cn("px-2 py-1.5 align-bottom", col.width)}>
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 font-medium text-left hover:text-foreground"
                    onClick={() => toggleSort(col.key)}
                  >
                    {col.label}
                    <SortIcon col={col.key} />
                  </button>
                </th>
              ))}
            </tr>
            <tr className="border-t border-border/50">
              {COLUMNS.map((col) => (
                <th key={`f-${col.key}`} className={cn("px-2 py-1", col.width)}>
                  {col.key === "subsystem" ? (
                    <Select
                      value={(filterDraft[col.key] ?? "").toLowerCase()}
                      onValueChange={(v) => onFilterChange(col.key, v === "__all__" ? "" : v)}
                    >
                      <SelectTrigger className={cn(inputClass, "h-7 text-[11px]")}>
                        <SelectValue placeholder="Subsystem" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__all__">All subsystems</SelectItem>
                        {SUBSYSTEMS.map((s) => (
                          <SelectItem key={s} value={s}>
                            {s}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <input
                      type="search"
                      placeholder="Filter…"
                      className={inputClass}
                      value={filterDraft[col.key] ?? ""}
                      onChange={(e) => onFilterChange(col.key, e.target.value)}
                      aria-label={`Filter ${col.label}`}
                    />
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((e, rowIdx) => (
              <tr
                key={rowKey(e, rowIdx)}
                className={cn(
                  "border-t border-border/50 align-top cursor-pointer",
                  selectedEventKey === rowKey(e, rowIdx) && "bg-muted/40"
                )}
                onClick={() => setSelectedEventKey(rowKey(e, rowIdx))}
              >
                <td className="px-2 py-1.5 text-xs text-muted-foreground font-mono">
                  {e.index ?? "—"}
                </td>
                <td className="px-2 py-1.5 font-mono text-xs whitespace-nowrap">
                  {formatEventDateTime(e.timestamp)}
                </td>
                <td className="px-2 py-1.5 font-mono text-xs break-all">{e.source_ip || "—"}</td>
                <td className="px-2 py-1.5 font-mono text-xs break-all">{e.dest_ip || "—"}</td>
                <td className="px-2 py-1.5 text-xs">{e.dest_port ?? "—"}</td>
                <td className="px-2 py-1.5 text-xs break-words">{e.subsystem || "—"}</td>
                <td className="px-2 py-1.5 text-xs break-words">{e.action || "—"}</td>
                <td className="px-2 py-1.5 text-xs">{e.severity || "—"}</td>
                <td className="px-2 py-1.5 text-xs text-muted-foreground break-words max-w-md">
                  <div className="space-y-1">
                    <div>{e.content || "—"}</div>
                    {renderExtraFields(e).length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {renderExtraFields(e).map((x) => (
                          <span
                            key={x}
                            className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-foreground/80"
                          >
                            {x}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ScrollArea>

      {selectedEvent && (
        <div className="rounded-md border bg-muted/20">
          <button
            type="button"
            className="w-full flex items-center justify-between px-3 py-2 text-sm font-medium"
            onClick={() => setShowAttributes((v) => !v)}
          >
            <span>Event Attributes</span>
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              {selectedAttributes.length} fields
              {showAttributes ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            </span>
          </button>
          {showAttributes && (
            <div className="border-t px-3 py-2">
              {selectedAttributes.length === 0 ? (
                <p className="text-xs text-muted-foreground">No extra parsed fields on this event.</p>
              ) : (
                <div className="grid gap-1.5 sm:grid-cols-2">
                  {selectedAttributes.map(([k, v]) => (
                    <div key={k} className="rounded border bg-background px-2 py-1.5 text-xs">
                      <span className="text-muted-foreground">{k}</span>
                      <div className="font-mono break-all">{String(v)}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
        <p className="text-xs text-muted-foreground">
          <span className="font-medium text-foreground">{totalEvents.toLocaleString()}</span> matching
          globally · <span className="font-medium text-foreground">{events.length}</span> rows on this
          page
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1 || loading || disabled}
            onClick={() => onQueryChange({ ...query, page: page - 1 })}
          >
            Previous
          </Button>
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-muted-foreground">Page</span>
            <input
              type="number"
              min={1}
              max={Math.max(1, totalPages)}
              className={cn(inputClass, "w-14 text-center")}
              value={pageInput}
              onChange={(e) => setPageInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") goToPage()
              }}
              aria-label="Page number"
            />
            <span className="text-muted-foreground">/ {Math.max(1, totalPages)}</span>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7 px-2"
              onClick={goToPage}
              disabled={loading || disabled}
            >
              Go
            </Button>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= totalPages || totalPages < 1 || loading || disabled}
            onClick={() => onQueryChange({ ...query, page: page + 1 })}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  )
}

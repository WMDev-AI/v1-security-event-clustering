"use client"

import { useMemo, useState, useEffect } from "react"
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import type { SecurityEvent } from "@/lib/api"
import { formatEventDateTime } from "@/lib/format-event-datetime"
import { cn } from "@/lib/utils"

export type EventTableRow = SecurityEvent & { index?: number }

const COLUMNS = [
  { key: "index" as const, label: "#", width: "w-[72px]" },
  { key: "timestamp" as const, label: "Time", width: "min-w-[180px]" },
  { key: "source_ip" as const, label: "Source", width: "min-w-[120px]" },
  { key: "dest_ip" as const, label: "Destination", width: "min-w-[120px]" },
  { key: "dest_port" as const, label: "Port", width: "w-[72px]" },
  { key: "subsystem" as const, label: "Subsystem", width: "min-w-[100px]" },
  { key: "action" as const, label: "Action", width: "min-w-[90px]" },
  { key: "severity" as const, label: "Severity", width: "min-w-[80px]" },
  { key: "content" as const, label: "Content", width: "min-w-[160px]" },
]

type SortKey = (typeof COLUMNS)[number]["key"]

function cellText(e: EventTableRow, key: SortKey): string {
  switch (key) {
    case "index":
      return e.index !== undefined ? String(e.index) : ""
    case "timestamp":
      return e.timestamp != null ? String(e.timestamp) : ""
    case "dest_port":
      return e.dest_port != null ? String(e.dest_port) : ""
    default:
      return e[key] != null ? String(e[key]) : ""
  }
}

function sortValue(e: EventTableRow, key: SortKey): number | string {
  switch (key) {
    case "index": {
      const n = e.index
      return typeof n === "number" ? n : parseInt(String(n), 10) || 0
    }
    case "dest_port": {
      const p = e.dest_port
      return typeof p === "number" ? p : parseInt(String(p), 10) || 0
    }
    case "timestamp": {
      const t = e.timestamp
      if (t == null) return 0
      const ms = Date.parse(String(t))
      return Number.isNaN(ms) ? String(t) : ms
    }
    default:
      return cellText(e, key).toLowerCase()
  }
}

function compare(a: EventTableRow, b: EventTableRow, key: SortKey, dir: 1 | -1): number {
  const va = sortValue(a, key)
  const vb = sortValue(b, key)
  if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir
  return String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" }) * dir
}

const inputClass =
  "h-7 w-full min-w-0 rounded border border-input bg-background px-1.5 text-[11px] placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"

export interface EventsPopupTableProps {
  events: EventTableRow[]
  page: number
  totalPages: number
  totalEvents: number
  loading?: boolean
  onPageChange: (page: number) => void
  disabled?: boolean
}

export function EventsPopupTable({
  events,
  page,
  totalPages,
  totalEvents,
  loading = false,
  onPageChange,
  disabled = false,
}: EventsPopupTableProps) {
  const [filters, setFilters] = useState<Partial<Record<SortKey, string>>>({})
  const [sortKey, setSortKey] = useState<SortKey>("index")
  const [sortDir, setSortDir] = useState<1 | -1>(1)
  const [pageInput, setPageInput] = useState(String(page))

  useEffect(() => {
    setPageInput(String(page))
  }, [page])

  const filteredSorted = useMemo(() => {
    const needle = (key: SortKey) => (filters[key] || "").trim().toLowerCase()
    let rows = events.filter((e) => {
      for (const col of COLUMNS) {
        const q = needle(col.key)
        if (!q) continue
        const text = cellText(e, col.key).toLowerCase()
        if (!text.includes(q)) return false
      }
      return true
    })
    rows = [...rows].sort((a, b) => compare(a, b, sortKey, sortDir))
    return rows
  }, [events, filters, sortKey, sortDir])

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 1 ? -1 : 1))
    else {
      setSortKey(key)
      setSortDir(1)
    }
  }

  const goToPage = () => {
    const n = parseInt(pageInput, 10)
    if (Number.isNaN(n)) return
    const clamped = Math.min(Math.max(1, n), Math.max(1, totalPages))
    onPageChange(clamped)
  }

  const SortIcon = ({ col }: { col: SortKey }) => {
    if (sortKey !== col) return <ArrowUpDown className="h-3 w-3 opacity-50" />
    return sortDir === 1 ? (
      <ArrowUp className="h-3 w-3" />
    ) : (
      <ArrowDown className="h-3 w-3" />
    )
  }

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
                  <input
                    type="search"
                    placeholder="Filter…"
                    className={inputClass}
                    value={filters[col.key] ?? ""}
                    onChange={(e) =>
                      setFilters((prev) => ({ ...prev, [col.key]: e.target.value }))
                    }
                    aria-label={`Filter ${col.label}`}
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredSorted.map((e, rowIdx) => (
              <tr
                key={
                  e.index !== undefined
                    ? `i-${e.index}`
                    : `r-${rowIdx}-${cellText(e, "timestamp")}`
                }
                className="border-t border-border/50 align-top"
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
                  {e.content || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ScrollArea>

      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
        <p className="text-xs text-muted-foreground">
          {totalEvents.toLocaleString()} total events · this page: {events.length} loaded · showing{" "}
          {filteredSorted.length} after filter
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1 || loading || disabled}
            onClick={() => onPageChange(page - 1)}
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
            <Button type="button" variant="secondary" size="sm" className="h-7 px-2" onClick={goToPage} disabled={loading || disabled}>
              Go
            </Button>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= totalPages || totalPages < 1 || loading || disabled}
            onClick={() => onPageChange(page + 1)}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  )
}

/** Format API timestamps for event tables (date + time when available). */
export function formatEventDateTime(value: unknown): string {
  if (value == null || value === "") return "—"
  const raw = String(value).trim()
  if (!raw) return "—"

  const parsed = Date.parse(raw)
  if (!Number.isNaN(parsed)) {
    const d = new Date(parsed)
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    })
  }

  return raw
}

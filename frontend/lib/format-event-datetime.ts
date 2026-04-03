/** Fixed display for event tables: YYYY-MM-DD HH:mm:ss (24h, local time). */
function pad2(n: number): string {
  return String(n).padStart(2, "0")
}

export function formatEventDateTime(value: unknown): string {
  if (value == null || value === "") return "—"
  const raw = String(value).trim()
  if (!raw) return "—"

  const ms = Date.parse(raw)
  if (Number.isNaN(ms)) return raw

  const d = new Date(ms)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}

export interface Alert {
  ts: number;
  ip: string;
  score: number;
  kind: string;
  severity: "critical" | "high" | "medium" | "low" | string;
  summary: string;
  firewall_rule: string;
  path: string;
  status: number;
}

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export const severityRank = (s: Severity) => SEVERITIES.length - SEVERITIES.indexOf(s);

export interface Finding {
  /** Stable check id, e.g. `secret/stripe-live`. Used for SARIF rule ids and ignores. */
  check: string;
  severity: Severity;
  title: string;
  /** What to do about it, one sentence. */
  fix: string;
  /** Repo-relative path, or a URL for web findings. */
  location: string;
  line?: number;
  /** Masked evidence. Never contains a full secret. */
  evidence?: string;
  /** Set for secrets that are only in git history, no longer in the current files. */
  historyOnly?: boolean;
}

export interface ScanResult {
  target: string;
  kind: "repo" | "url";
  findings: Finding[];
  /** Unique pieces of content examined (files, history blobs, fetched web assets). */
  filesChecked: number;
  /** Of those, how many were new content and therefore billable. */
  billableFiles: number;
  notes: string[];
}

"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  AlertCircle,
} from "lucide-react";
import { Header } from "@/components/Header";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, AuditLog } from "@/lib/api";

const ACTION_FILTERS = ["ALL", "BLOCK", "REDACT", "ALLOW", "ERROR"] as const;

function getActionBadgeStyle(action: string, isBlocked: boolean): string {
  if (action === "ERROR") {
    return "bg-orange-500/15 text-orange-400 border border-orange-500/30";
  }
  if (action === "BLOCK" || isBlocked) {
    return "bg-rose-500/15 text-rose-400 border border-rose-500/30";
  }
  if (action === "REDACT") {
    return "bg-amber-500/15 text-amber-400 border border-amber-500/30";
  }
  return "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30";
}

export default function AuditLogsPage() {
  const { token } = useAuth();
  const { activeWorkspace } = useWorkspace();

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [filterAction, setFilterAction] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [logsError, setLogsError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchLogs = useCallback(
    async (isCancelled?: () => boolean) => {
      if (!token || !activeWorkspace) return;
      try {
        const data = await api.getLogs(token, activeWorkspace.id, 100);
        if (isCancelled?.()) return;
        setLogs(data);
        setLogsError(null);
      } catch (err: unknown) {
        if (isCancelled?.()) return;
        setLogsError(err instanceof Error ? err.message : "Failed to load audit logs");
      } finally {
        if (!isCancelled?.()) {
          setLastUpdated(new Date());
          setIsLoading(false);
        }
      }
    },
    [token, activeWorkspace]
  );

  const loadLogs = useCallback(async () => {
    if (!token || !activeWorkspace) return;
    setIsLoading(true);
    await fetchLogs();
  }, [token, activeWorkspace, fetchLogs]);

  useEffect(() => {
    let cancelled = false;
    if (!token || !activeWorkspace) return;

    queueMicrotask(() => {
      if (cancelled) return;
      setIsLoading(true);
      setLogs([]);
      setLogsError(null);
      void fetchLogs(() => cancelled);
    });

    const intervalId = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchLogs(() => cancelled);
      }
    }, 15000);

    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        fetchLogs(() => cancelled);
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [token, activeWorkspace, fetchLogs]);

  // Filter logs based on selection & search
  const filteredLogs = logs.filter((l) => {
    const matchesAction = filterAction === "ALL" || l.action === filterAction;
    const matchesSearch =
      !searchTerm.trim() ||
      l.model.toLowerCase().includes(searchTerm.toLowerCase()) ||
      l.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      l.block_reason?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      l.findings?.some((f) => f.type.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesAction && matchesSearch;
  });

  return (
    <div className="flex-1 pb-12">
      <Header
        title="Firewall Audit Logs"
        subtitle="Inspection ledger, threat detections, and latency breakdown (auto-refreshes every 15s)"
      />

      <div className="max-w-7xl mx-auto px-8 py-6 space-y-6">
        {/* Filters and Search Bar */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider mr-1">
              Filter Action:
            </span>
            {ACTION_FILTERS.map((action) => (
              <button
                key={action}
                onClick={() => setFilterAction(action)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  filterAction === action
                    ? action === "BLOCK"
                      ? "bg-rose-500 text-slate-950"
                      : action === "REDACT"
                      ? "bg-amber-500 text-slate-950"
                      : action === "ERROR"
                      ? "bg-orange-500 text-slate-950"
                      : action === "ALLOW"
                      ? "bg-emerald-500 text-slate-950"
                      : "bg-slate-200 text-slate-950"
                    : "bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                {action}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            {lastUpdated && (
              <span className="text-[11px] text-slate-500 font-mono hidden sm:inline">
                Updated {lastUpdated.toLocaleTimeString()}
              </span>
            )}
            <div className="relative flex-1 md:w-64">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search model, threat, rule..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <button
              onClick={loadLogs}
              title="Refresh Logs"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors shrink-0"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* Audit Logs Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          {logsError ? (
            <div className="p-6 flex flex-wrap items-center justify-between gap-3 bg-rose-500/10 text-rose-300 text-xs">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Failed to load audit logs: {logsError}</span>
              </div>
              <button
                type="button"
                onClick={loadLogs}
                className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 font-semibold"
              >
                Retry
              </button>
            </div>
          ) : isLoading && !lastUpdated ? (
            <div className="text-center py-12 text-xs text-slate-400">
              Loading audit logs...
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-12 text-xs text-slate-500">
              {logs.length === 0
                ? "No audit records recorded yet for this workspace."
                : "No logs match the current filter criteria."}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Model</th>
                    <th className="py-3 px-4">Detected Findings / Outcome</th>
                    <th className="py-3 px-4">Latency (Insp. / Total)</th>
                    <th className="py-3 px-4 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {filteredLogs.map((log) => {
                    const isExpanded = expandedLogId === log.id;
                    const isErrorEntry = log.action === "ERROR";

                    return (
                      <React.Fragment key={log.id}>
                        <tr
                          onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                          className="hover:bg-slate-800/30 cursor-pointer transition-colors"
                        >
                          <td className="py-3 px-4">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${getActionBadgeStyle(
                                log.action,
                                log.is_blocked
                              )}`}
                            >
                              {log.action}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                            {new Date(log.created_at).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-300 font-medium">
                            {log.model}
                          </td>
                          <td className="py-3 px-4">
                            {log.findings && log.findings.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {log.findings.map((f, i) => (
                                  <span
                                    key={i}
                                    className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700"
                                  >
                                    {f.type === "PROMPT_INJECTION" && f.rule_name
                                      ? `Injection: ${f.rule_name.replaceAll("_", " ").toLowerCase()}`
                                      : f.type}
                                  </span>
                                ))}
                              </div>
                            ) : isErrorEntry ? (
                              <span className="text-orange-300 text-[11px]">
                                {log.block_reason ? log.block_reason.slice(0, 60) : "Gateway or upstream error"}
                              </span>
                            ) : (
                              <span className="text-slate-500 text-[11px]">None (Clean)</span>
                            )}
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                            <span className="text-cyan-400">{log.inspection_ms} ms</span>
                            <span className="text-slate-500 mx-1">/</span>
                            <span>{log.total_ms} ms</span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4 text-slate-400 inline" />
                            ) : (
                              <ChevronRight className="w-4 h-4 text-slate-500 inline" />
                            )}
                          </td>
                        </tr>

                        {/* Expanded Inspection Drawer */}
                        {isExpanded && (
                          <tr className="bg-slate-950/70 border-b border-slate-800">
                            <td colSpan={6} className="p-4 pl-12 space-y-3">
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                                <div>
                                  <span className="text-slate-500 uppercase tracking-wider text-[10px] font-semibold block mb-1">
                                    Request ID
                                  </span>
                                  <span className="font-mono text-slate-300 select-all">{log.id}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500 uppercase tracking-wider text-[10px] font-semibold block mb-1">
                                    Upstream Latency
                                  </span>
                                  <span className="font-mono text-slate-300">
                                    {log.upstream_ms !== null && log.upstream_ms !== undefined
                                      ? `${log.upstream_ms} ms`
                                      : isErrorEntry
                                      ? "N/A (Failed before upstream response)"
                                      : "N/A (Blocked before forwarding)"}
                                  </span>
                                </div>
                                <div>
                                  <span className="text-slate-500 uppercase tracking-wider text-[10px] font-semibold block mb-1">
                                    Token Usage
                                  </span>
                                  <span className="font-mono text-slate-300">
                                    Prompt: {log.prompt_tokens ?? "N/A"} | Completion:{" "}
                                    {log.completion_tokens ?? "N/A"}
                                  </span>
                                </div>
                              </div>

                              {log.block_reason && (
                                <div
                                  className={`p-2.5 rounded border text-xs ${
                                    isErrorEntry
                                      ? "bg-orange-500/10 border-orange-500/20 text-orange-300"
                                      : "bg-rose-500/10 border-rose-500/20 text-rose-300"
                                  }`}
                                >
                                  <span className="font-bold">
                                    {isErrorEntry ? "Error Details: " : "Block Reason: "}
                                  </span>
                                  {log.block_reason}
                                </div>
                              )}

                              {log.findings && log.findings.length > 0 && (
                                <div>
                                  <span className="text-slate-400 uppercase tracking-wider text-[10px] font-semibold block mb-1.5">
                                    Matched Findings Breakdown
                                  </span>
                                  <div className="space-y-1.5">
                                    {log.findings.map((f, idx) => (
                                      <div
                                        key={idx}
                                        className="p-2 rounded bg-slate-900 border border-slate-800 text-xs flex items-center justify-between"
                                      >
                                        <div className="flex items-center gap-2">
                                          <span className="font-mono text-emerald-400 font-semibold">
                                            {f.type}
                                          </span>
                                          <span className="text-slate-500">•</span>
                                          <span className="text-slate-400">{f.rule_name}</span>
                                          {f.details && (
                                            <span className="text-slate-500 text-[11px]">
                                              ({f.details})
                                            </span>
                                          )}
                                        </div>
                                        <span className="font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                                          Safe preview: {f.safe_preview}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

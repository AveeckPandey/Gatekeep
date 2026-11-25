"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Flame,
  ArrowRight,
  Sliders,
  Key,
  RefreshCw,
  AlertTriangle,
  AlertCircle,
} from "lucide-react";
import { Header } from "@/components/Header";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, AuditLog, Policy } from "@/lib/api";

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

export default function DashboardOverviewPage() {
  const { token } = useAuth();
  const { activeWorkspace } = useWorkspace();

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [logsError, setLogsError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState<(typeof ACTION_FILTERS)[number]>("ALL");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchTelemetry = useCallback(
    async (isCancelled?: () => boolean) => {
      if (!token || !activeWorkspace) return;
      const [logsResult, policyResult] = await Promise.allSettled([
        api.getLogs(token, activeWorkspace.id, 50),
        api.getPolicy(token, activeWorkspace.id),
      ]);
      if (isCancelled?.()) return;

      if (logsResult.status === "fulfilled") {
        setLogs(logsResult.value);
        setLogsError(null);
      } else {
        setLogsError(
          logsResult.reason instanceof Error
            ? logsResult.reason.message
            : "Failed to load audit logs"
        );
      }

      if (policyResult.status === "fulfilled") {
        setPolicy(policyResult.value);
        setPolicyError(null);
      } else {
        setPolicy(null);
        setPolicyError(
          policyResult.reason instanceof Error
            ? policyResult.reason.message
            : "Failed to load workspace policy"
        );
      }

      setLastUpdated(new Date());
      setIsLoading(false);
    },
    [token, activeWorkspace]
  );

  const loadData = useCallback(async () => {
    if (!token || !activeWorkspace) return;
    setIsLoading(true);
    await fetchTelemetry();
  }, [token, activeWorkspace, fetchTelemetry]);

  useEffect(() => {
    let cancelled = false;
    if (!token || !activeWorkspace) return;

    queueMicrotask(() => {
      if (cancelled) return;
      setIsLoading(true);
      setPolicy(null);
      setLogs([]);
      setPolicyError(null);
      setLogsError(null);
      void fetchTelemetry(() => cancelled);
    });

    const intervalId = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchTelemetry(() => cancelled);
      }
    }, 15000);

    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        fetchTelemetry(() => cancelled);
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [token, activeWorkspace, fetchTelemetry]);

  // Compute live KPI metrics from recent audit logs
  const totalRequests = logs.length;
  const blockedCount = logs.filter((l) => l.action === "BLOCK" || l.is_blocked).length;
  const redactedRequests = logs.filter((l) => l.action === "REDACT");
  const redactedCount = redactedRequests.length;
  const redactedFindingsCount = redactedRequests.reduce(
    (acc, curr) => acc + (curr.findings_count || 0),
    0
  );
  const avgInspectionMs =
    totalRequests > 0
      ? (logs.reduce((acc, curr) => acc + (curr.inspection_ms || 0), 0) / totalRequests).toFixed(2)
      : "0.00";

  const filteredLogs = logs.filter((l) => actionFilter === "ALL" || l.action === actionFilter);

  const policyStatusLabel = isLoading && !policy && !policyError
    ? "LOADING"
    : policy && !policyError
    ? "ACTIVE"
    : "UNAVAILABLE";

  const policyStatusClass =
    policyStatusLabel === "ACTIVE"
      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
      : policyStatusLabel === "LOADING"
      ? "bg-slate-800 text-slate-300 border-slate-700"
      : "bg-rose-500/15 text-rose-300 border-rose-500/30";

  return (
    <div className="flex-1 pb-12">
      <Header
        title="Security Gateway Overview"
        subtitle="Multi-tenant firewall telemetry & attack mitigation (auto-refreshes every 15s)"
      />

      <div className="max-w-7xl mx-auto px-8 py-6 space-y-6">
        <section className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-950/40 via-slate-900 to-slate-900 p-6 md:p-8">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-emerald-400">What GateKeep does</p>
          <h2 className="mt-2 max-w-3xl text-2xl font-bold text-slate-100">A rule-based security checkpoint between your app and an AI model</h2>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            Send chat completion requests to GateKeep instead of directly to your model provider. It inspects supported text fields against regex rules, Luhn credit card checks, entropy thresholds, and heuristic prompt-injection patterns, applies your policy, forwards permitted traffic to a compatible <code className="font-mono text-slate-200">/chat/completions</code> Bearer endpoint, optionally scans model responses, and logs each outcome.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link href="/dashboard/policies" className="rounded-lg bg-emerald-500 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-emerald-400">Set up provider and policy</Link>
            <Link href="/dashboard/playground" className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800">Try a request</Link>
          </div>
        </section>

        <section aria-labelledby="request-flow-title" className="space-y-3">
          <div>
            <h2 id="request-flow-title" className="text-base font-bold text-slate-100">How a request moves through GateKeep</h2>
            <p className="mt-1 text-xs text-slate-400">The same flow applies to the playground and to applications calling the gateway API.</p>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {[
              { number: "01", title: "Authenticate", description: "Your app sends a chat request with a workspace gateway key (gw_live_...)." },
              { number: "02", title: "Inspect the prompt", description: "GateKeep checks supported text and tool fields for emails, Luhn-valid cards, AWS/OpenAI/GitHub keys, high-entropy strings, and English injection heuristics." },
              { number: "03", title: "Call the model", description: "Permitted requests go to the configured compatible AI model provider (/chat/completions with Bearer auth) using its separate, encrypted provider key." },
              { number: "04", title: "Check and log", description: "When response inspection is enabled, GateKeep checks model text and tool arguments for matching patterns, returns a verdict, and records one audit entry." },
            ].map((step) => (
              <div key={step.number} className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <span className="font-mono text-xs font-bold text-emerald-400">{step.number}</span>
                <h3 className="mt-2 text-sm font-semibold text-slate-100">{step.title}</h3>
                <p className="mt-1 text-xs leading-5 text-slate-400">{step.description}</p>
              </div>
            ))}
          </div>
        </section>

        <section aria-labelledby="getting-started-title" className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 id="getting-started-title" className="text-base font-bold text-slate-100">Get started</h2>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <div>
              <Link href="/dashboard/policies" className="text-xs font-semibold text-emerald-400 hover:underline">1. Connect a model provider →</Link>
              <p className="mt-1 text-xs leading-5 text-slate-400">Set a compatible chat completions base URL (Bearer auth) and provider API key in Firewall Policies. Other native APIs require adapters.</p>
            </div>
            <div>
              <Link href="/dashboard/keys" className="text-xs font-semibold text-emerald-400 hover:underline">2. Create a gateway key →</Link>
              <p className="mt-1 text-xs leading-5 text-slate-400">Create a gw_live_ key for this workspace and save the full value. This key authenticates requests to GateKeep; it is different from the provider key.</p>
            </div>
            <div>
              <Link href="/dashboard/playground" className="text-xs font-semibold text-emerald-400 hover:underline">3. Test and review →</Link>
              <p className="mt-1 text-xs leading-5 text-slate-400">Send a safe or attack prompt in the playground, see the firewall verdict, then inspect the request in Audit Logs.</p>
            </div>
          </div>
        </section>

        {/* Top Security Status Banner */}
        <div className="bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 border border-emerald-500/20 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className={`w-10 h-10 rounded-lg border flex items-center justify-center shrink-0 ${
              policyError
                ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
                : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
            }`}>
              {policyError ? <AlertCircle className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-100">
                  Firewall Mode: {policy?.mode || (isLoading ? "Loading..." : "Unavailable")}
                </h3>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold border ${policyStatusClass}`}>
                  {policyStatusLabel}
                </span>
                {lastUpdated && (
                  <span className="text-[11px] text-slate-500 font-mono">
                    Updated {lastUpdated.toLocaleTimeString()}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Upstream LLM:{" "}
                <span className="font-mono text-slate-300">
                  {policy?.upstream_base_url || (isLoading ? "Loading workspace policy" : "Unavailable")}
                </span>{" "}
                • BYOK Key:{" "}
                <span className="text-slate-300">
                  {policy?.has_upstream_api_key ? "Encrypted at rest" : policy ? "Not configured" : "Unknown"}
                </span>
              </p>
              {policyError && (
                <p className="text-xs text-rose-300 mt-1">
                  Could not load workspace policy: {policyError}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <Link
              href="/dashboard/playground"
              className="px-3.5 py-2 text-xs bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg flex items-center gap-1.5 transition-colors"
            >
              <Flame className="w-4 h-4" />
              <span>Launch Playground</span>
            </Link>
            <button
              onClick={loadData}
              title="Refresh Telemetry"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Recent Requests */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Recent Requests</span>
              <Activity className="w-4 h-4 text-slate-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100 font-mono">
              {logsError ? "—" : isLoading && !lastUpdated ? "..." : totalRequests.toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              {logsError ? "Failed to load recent logs" : `Latest ${Math.min(totalRequests, 50)} logged inspections`}
            </div>
          </div>

          {/* Card 2: Blocked Requests */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-rose-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Blocked Requests</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 font-mono">
              {logsError ? "—" : isLoading && !lastUpdated ? "..." : blockedCount}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Requests dropped by policy or injection rules
            </div>
          </div>

          {/* Card 3: Redacted Requests */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-amber-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Redacted Requests</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400 font-mono">
              {logsError ? "—" : isLoading && !lastUpdated ? "..." : redactedCount}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              {logsError
                ? "Audit data unavailable"
                : `${redactedFindingsCount} finding${redactedFindingsCount === 1 ? "" : "s"} masked across recent logs`}
            </div>
          </div>

          {/* Card 4: Avg Inspection Latency */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-cyan-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Avg Inspection</span>
              <Zap className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-cyan-400 font-mono">
              {logsError ? "—" : isLoading && !lastUpdated ? "..." : `${avgInspectionMs} ms`}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Average inspection time in recent logs</div>
          </div>
        </div>

        {/* Quick Config Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex items-start gap-4">
            <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-slate-300 shrink-0">
              <Sliders className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="flex-1">
              <h4 className="text-sm font-semibold text-slate-200">Firewall Rules & BYOK</h4>
              <p className="text-xs text-slate-400 mt-1">
                Configure request inspection, prompt injection defenses, and credentials for your compatible model provider.
              </p>
              <Link
                href="/dashboard/policies"
                className="inline-flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 font-semibold mt-3"
              >
                <span>Edit Policies</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex items-start gap-4">
            <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-slate-300 shrink-0">
              <Key className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="flex-1">
              <h4 className="text-sm font-semibold text-slate-200">Gateway Access Keys</h4>
              <p className="text-xs text-slate-400 mt-1">
                Manage workspace-scoped live keys (<code className="font-mono text-slate-300">gw_live_...</code>) stored securely as SHA-256 hashes.
              </p>
              <Link
                href="/dashboard/keys"
                className="inline-flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 font-semibold mt-3"
              >
                <span>Manage API Keys</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </div>

        {/* Recent Audit Logs Feed */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Recent Firewall Activity</h3>
              <p className="text-xs text-slate-400">Latest inspected proxy requests for this workspace</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1">
                {ACTION_FILTERS.map((action) => (
                  <button
                    key={action}
                    type="button"
                    onClick={() => setActionFilter(action)}
                    className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors ${
                      actionFilter === action
                        ? action === "ERROR"
                          ? "bg-orange-500 text-slate-950"
                          : action === "BLOCK"
                          ? "bg-rose-500 text-slate-950"
                          : action === "REDACT"
                          ? "bg-amber-500 text-slate-950"
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
              <Link
                href="/dashboard/logs"
                className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium ml-2"
              >
                <span>View All Logs</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {logsError ? (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Failed to load recent firewall activity: {logsError}</span>
              </div>
              <button
                type="button"
                onClick={loadData}
                className="px-3 py-1 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 font-semibold"
              >
                Retry
              </button>
            </div>
          ) : isLoading && !lastUpdated ? (
            <div className="text-center py-8 text-xs text-slate-400">
              Loading recent firewall activity...
            </div>
          ) : logs.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500">
              No audit logs recorded yet. Run a prompt through the{" "}
              <Link href="/dashboard/playground" className="text-emerald-400 underline">
                Attack Playground
              </Link>{" "}
              to generate activity!
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500">
              No recent requests match the <span className="font-mono text-slate-300">{actionFilter}</span> filter.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                    <th className="pb-2.5">Action</th>
                    <th className="pb-2.5">Model</th>
                    <th className="pb-2.5">Threats / Outcome</th>
                    <th className="pb-2.5">Inspection</th>
                    <th className="pb-2.5">Total Time</th>
                    <th className="pb-2.5 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredLogs.slice(0, 5).map((log) => {
                    const isErrorEntry = log.action === "ERROR";
                    return (
                      <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${getActionBadgeStyle(
                              log.action,
                              log.is_blocked
                            )}`}
                          >
                            {log.action}
                          </span>
                        </td>
                        <td className="py-2.5 font-mono text-slate-300 truncate max-w-[150px]">
                          {log.model}
                        </td>
                        <td className="py-2.5">
                          {isErrorEntry ? (
                            <span className="text-orange-300">
                              {log.block_reason ? log.block_reason.slice(0, 55) : "Gateway or upstream error"}
                              {log.findings_count > 0 && ` (${log.findings_count} finding${log.findings_count > 1 ? "s" : ""})`}
                            </span>
                          ) : log.findings_count > 0 ? (
                            <span className="text-slate-300">
                              {log.findings_count} finding{log.findings_count > 1 ? "s" : ""}
                              {log.block_reason && ` (${log.block_reason.slice(0, 30)}...)`}
                            </span>
                          ) : (
                            <span className="text-slate-500">None (Clean)</span>
                          )}
                        </td>
                        <td className="py-2.5 font-mono text-slate-400">{log.inspection_ms} ms</td>
                        <td className="py-2.5 font-mono text-slate-400">{log.total_ms} ms</td>
                        <td className="py-2.5 text-right text-slate-500 font-mono">
                          {new Date(log.created_at).toLocaleTimeString()}
                        </td>
                      </tr>
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

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
} from "lucide-react";
import { Header } from "@/components/Header";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, AuditLog, Policy } from "@/lib/api";

export default function DashboardOverviewPage() {
  const { token } = useAuth();
  const { activeWorkspace } = useWorkspace();

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const loadData = useCallback(async () => {
    if (!token || !activeWorkspace) return;
    setIsLoading(true);
    try {
      const [fetchedLogs, fetchedPolicy] = await Promise.all([
        api.getLogs(token, activeWorkspace.id, 50).catch(() => []),
        api.getPolicy(token, activeWorkspace.id).catch(() => null),
      ]);
      setLogs(fetchedLogs);
      setPolicy(fetchedPolicy);
    } finally {
      setIsLoading(false);
    }
  }, [token, activeWorkspace]);

  useEffect(() => {
    let isMounted = true;
    if (!token || !activeWorkspace) return;

    Promise.all([
      api.getLogs(token, activeWorkspace.id, 50).catch(() => []),
      api.getPolicy(token, activeWorkspace.id).catch(() => null),
    ])
      .then(([fetchedLogs, fetchedPolicy]) => {
        if (!isMounted) return;
        setLogs(fetchedLogs);
        setPolicy(fetchedPolicy);
      })
      .finally(() => {
        if (!isMounted) return;
        setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [token, activeWorkspace]);

  // Compute live KPI metrics from audit logs
  const totalRequests = logs.length;
  const blockedCount = logs.filter((l) => l.action === "BLOCK" || l.is_blocked).length;
  const redactedCount = logs.filter((l) => l.action === "REDACT").length;
  const avgInspectionMs =
    totalRequests > 0
      ? (logs.reduce((acc, curr) => acc + (curr.inspection_ms || 0), 0) / totalRequests).toFixed(2)
      : "0.00";

  return (
    <div className="flex-1 pb-12">
      <Header
        title="Security Gateway Overview"
        subtitle="Real-time multi-tenant firewall telemetry & attack mitigation"
      />

      <div className="max-w-7xl mx-auto px-8 py-6 space-y-6">
        <section className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-950/40 via-slate-900 to-slate-900 p-6 md:p-8">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-emerald-400">What GateKeep does</p>
          <h2 className="mt-2 max-w-3xl text-2xl font-bold text-slate-100">A security checkpoint between your app and an AI model</h2>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            Send chat requests to GateKeep instead of directly to your model provider. It checks prompts for sensitive data and prompt injection, applies your firewall policy, forwards permitted requests, optionally checks model responses, and records the result in audit logs.
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
              { number: "02", title: "Inspect the prompt", description: "GateKeep scans for secrets, personal data, and prompt injection patterns, then blocks, redacts, or allows the request according to your policy." },
              { number: "03", title: "Call the model", description: "Permitted requests go to the configured OpenAI compatible provider using its separate, encrypted provider key." },
              { number: "04", title: "Check and log", description: "When response inspection is enabled, GateKeep checks model output for sensitive data. It returns the result and writes an audit entry." },
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
              <p className="mt-1 text-xs leading-5 text-slate-400">Set its chat completions base URL and provider API key in Firewall Policies. Choose what GateKeep blocks or redacts.</p>
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
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-100">
                  Firewall Mode: {policy?.mode || (isLoading ? "Loading..." : "Unavailable")}
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
                  ACTIVE
                </span>
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
          {/* Card 1: Total Requests */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Recent Requests</span>
              <Activity className="w-4 h-4 text-slate-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100 font-mono">
              {totalRequests.toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Latest {Math.min(totalRequests, 50)} logged inspections</div>
          </div>

          {/* Card 2: Blocked Attacks */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-rose-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Blocked Threats</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 font-mono">{blockedCount}</div>
            <div className="text-[11px] text-slate-500 mt-1">
              Prompt injections & forbidden secrets dropped
            </div>
          </div>

          {/* Card 3: Redacted Secrets */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-amber-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Redacted Secrets</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400 font-mono">{redactedCount}</div>
            <div className="text-[11px] text-slate-500 mt-1">PII & credentials masked before LLM</div>
          </div>

          {/* Card 4: Avg Inspection Latency */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between text-cyan-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Avg Latency</span>
              <Zap className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-cyan-400 font-mono">{avgInspectionMs} ms</div>
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
                Configure request inspection, prompt injection defenses, and credentials for your model provider.
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
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Recent Firewall Activity</h3>
              <p className="text-xs text-slate-400">Latest inspected proxy requests for this workspace</p>
            </div>
            <Link
              href="/dashboard/logs"
              className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium"
            >
              <span>View All Logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {logs.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500">
              No audit logs recorded yet. Run a prompt through the{" "}
              <Link href="/dashboard/playground" className="text-emerald-400 underline">
                Attack Playground
              </Link>{" "}
              to generate activity!
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                    <th className="pb-2.5">Action</th>
                    <th className="pb-2.5">Model</th>
                    <th className="pb-2.5">Threats / Findings</th>
                    <th className="pb-2.5">Inspection</th>
                    <th className="pb-2.5">Total Time</th>
                    <th className="pb-2.5 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {logs.slice(0, 5).map((log) => {
                    const isBlock = log.action === "BLOCK" || log.is_blocked;
                    const isRedact = log.action === "REDACT";
                    return (
                      <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                              isBlock
                                ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                                : isRedact
                                ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                                : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                            }`}
                          >
                            {log.action}
                          </span>
                        </td>
                        <td className="py-2.5 font-mono text-slate-300 truncate max-w-[150px]">
                          {log.model}
                        </td>
                        <td className="py-2.5">
                          {log.findings_count > 0 ? (
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

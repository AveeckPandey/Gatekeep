"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Lock,
  Cpu,
  Save,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
} from "lucide-react";
import { Header } from "@/components/Header";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, Policy, PolicyMode, PolicyUpdateRequest } from "@/lib/api";

export default function PoliciesPage() {
  const { token } = useAuth();
  const { activeWorkspace } = useWorkspace();

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [mode, setMode] = useState<PolicyMode>("REDACT");
  const [blockInjections, setBlockInjections] = useState<boolean>(true);
  const [inspectResponses, setInspectResponses] = useState<boolean>(true);
  const [rateLimitRpm, setRateLimitRpm] = useState<number>(60);
  const [upstreamBaseUrl, setUpstreamBaseUrl] = useState<string>("");
  const [upstreamApiKey, setUpstreamApiKey] = useState<string>("");
  const [showKeyInput, setShowKeyInput] = useState<boolean>(false);

  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(
    null
  );

  useEffect(() => {
    let isMounted = true;
    if (!token || !activeWorkspace) return;

    api
      .getPolicy(token, activeWorkspace.id)
      .then((p) => {
        if (!isMounted) return;
        setPolicy(p);
        setMode(p.mode);
        setBlockInjections(p.block_injections);
        setInspectResponses(p.inspect_responses ?? true);
        setRateLimitRpm(p.rate_limit_rpm ?? 60);
        setUpstreamBaseUrl(p.upstream_base_url);
      })
      .catch((err: unknown) => {
        if (!isMounted) return;
        const msg = err instanceof Error ? err.message : "Failed to load policy";
        setStatusMessage({ type: "error", text: msg });
      });

    return () => {
      isMounted = false;
    };
  }, [token, activeWorkspace]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !activeWorkspace) return;

    setIsSaving(true);
    setStatusMessage(null);

    try {
      const payload: PolicyUpdateRequest = {
        mode,
        block_injections: blockInjections,
        inspect_responses: inspectResponses,
        rate_limit_rpm: rateLimitRpm,
        upstream_base_url: upstreamBaseUrl,
      };

      if (upstreamApiKey.trim()) {
        payload.upstream_api_key = upstreamApiKey.trim();
      }

      const updated = await api.updatePolicy(token, activeWorkspace.id, payload);
      setPolicy(updated);
      setUpstreamApiKey("");
      setStatusMessage({
        type: "success",
        text: "Security policy & BYOK credentials updated successfully!",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update policy";
      setStatusMessage({ type: "error", text: msg });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="flex-1 pb-12">
      <Header
        title="Firewall Policies & BYOK"
        subtitle="Manage deterministic inspection rules, prompt injection defenses, and encrypted LLM credentials"
      />

      <div className="max-w-4xl mx-auto px-8 py-6 space-y-6">
        {statusMessage && (
          <div
            className={`p-4 rounded-xl flex items-center gap-3 text-xs ${
              statusMessage.type === "success"
                ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-300"
                : "bg-rose-500/10 border border-rose-500/30 text-rose-300"
            }`}
          >
            {statusMessage.type === "success" ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            )}
            <span>{statusMessage.text}</span>
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-6">
          {/* Section 1: Firewall Policy Mode */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-100">Firewall Operation Mode</h3>
            </div>
            <p className="text-xs text-slate-400 mb-5">
              Select how GateKeep handles requests containing detected PII, API tokens, or high-entropy secrets.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* BLOCK Option */}
              <label
                className={`p-4 rounded-lg border cursor-pointer transition-all flex flex-col justify-between ${
                  mode === "BLOCK"
                    ? "bg-rose-500/10 border-rose-500 text-slate-100"
                    : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-rose-400">BLOCK (Strict)</span>
                    <input
                      type="radio"
                      name="mode"
                      value="BLOCK"
                      checked={mode === "BLOCK"}
                      onChange={() => setMode("BLOCK")}
                      className="accent-rose-500"
                    />
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    Instantly drops requests containing any secret or PII and returns HTTP 403 Forbidden.
                  </p>
                </div>
              </label>

              {/* REDACT Option */}
              <label
                className={`p-4 rounded-lg border cursor-pointer transition-all flex flex-col justify-between ${
                  mode === "REDACT"
                    ? "bg-amber-500/10 border-amber-500 text-slate-100"
                    : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-amber-400">REDACT (Recommended)</span>
                    <input
                      type="radio"
                      name="mode"
                      value="REDACT"
                      checked={mode === "REDACT"}
                      onChange={() => setMode("REDACT")}
                      className="accent-amber-500"
                    />
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    Masks secrets and PII with <code className="text-amber-300 font-mono">[REDACTED_...]</code> and forwards the sanitized prompt.
                  </p>
                </div>
              </label>

              {/* ALLOW Option */}
              <label
                className={`p-4 rounded-lg border cursor-pointer transition-all flex flex-col justify-between ${
                  mode === "ALLOW"
                    ? "bg-slate-800/80 border-slate-600 text-slate-100"
                    : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-slate-300">ALLOW (Audit Only)</span>
                    <input
                      type="radio"
                      name="mode"
                      value="ALLOW"
                      checked={mode === "ALLOW"}
                      onChange={() => setMode("ALLOW")}
                      className="accent-slate-400"
                    />
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    Permits requests untouched. Logs all telemetry and matched findings to audit storage.
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Section 2: Prompt Injection Heuristics */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Prompt Injection & Jailbreak Defense
                </h3>
                <p className="text-xs text-slate-400 mt-1 max-w-xl">
                  Enforces heuristic scanners to detect instruction overrides (e.g. &quot;ignore previous instructions&quot;), DAN roleplay modes, and system prompt extraction attacks.
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockInjections}
                  onChange={(e) => setBlockInjections(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
              </label>
            </div>
          </div>

          {/* Section 3: Output Inspection (Response DLP) */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Response DLP (Output Inspection)
                </h3>
                <p className="text-xs text-slate-400 mt-1 max-w-xl">
                  Inspects returning LLM completions before sending to callers. Automatically detects and redacts leaked API keys, credentials, or PII returned by the model.
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={inspectResponses}
                  onChange={(e) => setInspectResponses(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
              </label>
            </div>
          </div>

          {/* Section 4: Workspace Rate Limiting */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Per-Workspace Rate Limiting
                </h3>
                <p className="text-xs text-slate-400 mt-1 max-w-xl">
                  Enforces a sliding window requests-per-minute (RPM) cap to protect upstream quota and prevent runaway usage. Requests exceeding the limit receive HTTP 429.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={rateLimitRpm}
                  onChange={(e) => setRateLimitRpm(parseInt(e.target.value) || 60)}
                  className="w-24 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 text-center focus:outline-none focus:border-emerald-500"
                />
                <span className="text-xs text-slate-400 font-semibold">RPM</span>
              </div>
            </div>
          </div>

          {/* Section 5: Upstream LLM BYOK Configuration */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg space-y-4">
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-100">Upstream LLM Configuration (BYOK)</h3>
            </div>
            <p className="text-xs text-slate-400">
              Enter any OpenAI compatible chat completions base URL and its key. Server configured providers can also be selected by alias per request in the playground.
            </p>

            <div className="grid grid-cols-1 gap-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Upstream Base URL
                </label>
                <input
                  type="text"
                  required
                  value={upstreamBaseUrl}
                  onChange={(e) => setUpstreamBaseUrl(e.target.value)}
                  placeholder="https://your-provider.example/v1"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-semibold text-slate-300">
                    Upstream API Key (BYOK)
                  </label>
                  {policy?.has_upstream_api_key && (
                    <span className="text-[10px] text-emerald-400 font-medium flex items-center gap-1">
                      <Lock className="w-3 h-3" />
                      Key Encrypted at Rest ({policy.upstream_api_key_preview || "Configured"})
                    </span>
                  )}
                </div>
                <div className="relative">
                  <input
                    type={showKeyInput ? "text" : "password"}
                    value={upstreamApiKey}
                    onChange={(e) => setUpstreamApiKey(e.target.value)}
                    placeholder={
                      policy?.has_upstream_api_key
                        ? "Enter new key to rotate existing encrypted key (leave blank to keep current)"
                        : "Provider API key"
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-3.5 pr-10 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKeyInput(!showKeyInput)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                  >
                    {showKeyInput ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Enter the API key for the selected provider. The model name is set per request in the playground or client.
                </p>
              </div>
            </div>
          </div>

          {/* Submit Button */}
          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSaving}
              className="px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs flex items-center gap-2 transition-colors disabled:opacity-50 shadow-lg shadow-emerald-500/10"
            >
              <Save className="w-4 h-4" />
              <span>{isSaving ? "Saving Policy..." : "Save Policy Configuration"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

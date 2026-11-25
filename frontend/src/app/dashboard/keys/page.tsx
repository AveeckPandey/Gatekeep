"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  Key,
  Plus,
  Copy,
  Check,
  AlertTriangle,
  RefreshCw,
  Eye,
  EyeOff,
} from "lucide-react";
import { Header } from "@/components/Header";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, ApiKey, ApiKeyCreateResponse } from "@/lib/api";

const CREDENTIAL_PREFIXES_LOWER = [
  "gw_live_",
  "nvapi-",
  "sk-",
  "pk_live_",
  "pk_test_",
  "rk_live_",
  "rk_test_",
  "ghp_",
  "gho_",
  "ghu_",
  "ghs_",
  "ghr_",
  "github_pat_",
  "xoxb-",
  "xoxp_",
  "bearer ",
];
const EXACT_CREDENTIAL_PREFIXES = ["AIza", "AKIA", "ABIA", "ACCA", "ASIA"];

function looksLikeCredential(label: string): boolean {
  const trimmed = label.trim();
  if (!trimmed) return false;
  const lower = trimmed.toLowerCase();
  if (
    CREDENTIAL_PREFIXES_LOWER.some((prefix) => lower.startsWith(prefix)) ||
    EXACT_CREDENTIAL_PREFIXES.some((prefix) => trimmed.startsWith(prefix))
  ) {
    return true;
  }
  return trimmed.split(/\s+/).some((tok) => tok.length >= 40 || /^[0-9a-fA-F]{24,}$/.test(tok));
}

export default function ApiKeysPage() {
  const { token } = useAuth();
  const { activeWorkspace } = useWorkspace();

  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [newKeyName, setNewKeyName] = useState<string>("");
  const [createdKeyData, setCreatedKeyData] = useState<ApiKeyCreateResponse | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [cachedKeys, setCachedKeys] = useState<Record<string, string>>({});
  const [visibleKeys, setVisibleKeys] = useState<Record<string, boolean>>({});
  const [showCreatedKey, setShowCreatedKey] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [pendingRevokeKeyId, setPendingRevokeKeyId] = useState<string | null>(null);
  const [isRevoking, setIsRevoking] = useState<boolean>(false);

  const updateCachedKeys = useCallback((list: ApiKey[]) => {
    const available: Record<string, string> = {};
    const latest = sessionStorage.getItem("gatekeep_latest_key");
    const latestPrefix = sessionStorage.getItem("gatekeep_latest_key_prefix");
    for (const key of list) {
      if (key.is_revoked) continue;
      const value = sessionStorage.getItem("gatekeep_active_key_" + key.id) ||
        (key.prefix === latestPrefix ? latest : null);
      if (value && /^gw_live_[A-Za-z0-9]{32}$/.test(value)) {
        available[key.id] = value;
      }
    }
    setCachedKeys(available);
  }, []);

  const loadKeys = useCallback(async () => {
    if (!token || !activeWorkspace) return;
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const list = await api.listKeys(token, activeWorkspace.id);
      setKeys(list);
      updateCachedKeys(list);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load keys";
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  }, [token, activeWorkspace, updateCachedKeys]);

  useEffect(() => {
    let isMounted = true;
    if (!token || !activeWorkspace) return;

    api
      .listKeys(token, activeWorkspace.id)
      .then((list) => {
        if (!isMounted) return;
        setKeys(list);
        updateCachedKeys(list);
      })
      .catch((err: unknown) => {
        if (!isMounted) return;
        const msg = err instanceof Error ? err.message : "Failed to load keys";
        setErrorMessage(msg);
      })
      .finally(() => {
        if (!isMounted) return;
        setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [token, activeWorkspace, updateCachedKeys]);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    const label = newKeyName.trim();
    if (looksLikeCredential(label)) {
      setErrorMessage("This looks like an API credential. Use a short label here and enter provider keys under Firewall Policies.");
      return;
    }
    if (!token || !activeWorkspace) {
      setErrorMessage("Workspace is not ready. Refresh the page or sign in again.");
      return;
    }

    setIsCreating(true);
    setErrorMessage(null);
    try {
      const resp = await api.createKey(token, activeWorkspace.id, label || "Gateway Key");
      setCreatedKeyData(resp);
      setShowCreatedKey(false);
      setNewKeyName("");
      // Cache the full plaintext key in session storage so it can be used in the playground
      if (typeof window !== "undefined") {
        sessionStorage.setItem("gatekeep_active_key_" + resp.id, resp.api_key);
        sessionStorage.setItem("gatekeep_latest_key", resp.api_key);
        sessionStorage.setItem("gatekeep_latest_key_prefix", resp.prefix);
      }
      await loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create API key";
      setErrorMessage(msg);
    } finally {
      setIsCreating(false);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!token || !activeWorkspace) {
      setErrorMessage("Workspace is not ready. Refresh the page or sign in again.");
      return;
    }

    setIsRevoking(true);
    setErrorMessage(null);
    try {
      await api.revokeKey(token, activeWorkspace.id, keyId);
      sessionStorage.removeItem("gatekeep_active_key_" + keyId);
      setVisibleKeys((current) => ({ ...current, [keyId]: false }));
      setPendingRevokeKeyId(null);
      await loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to revoke key";
      setErrorMessage("Failed to revoke key: " + msg);
    } finally {
      setIsRevoking(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex-1 pb-12">
      <Header
        title="Gateway API Keys"
        subtitle="Authenticate proxy completions to /v1/chat/completions using workspace-scoped keys"
      />

      <div className="max-w-6xl mx-auto px-8 py-6 space-y-6">
        {errorMessage && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Create API Key Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
          <div className="flex items-center gap-2 mb-2">
            <Key className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-bold text-slate-100">Create Gateway API Key</h3>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Gateway keys (<code className="font-mono text-slate-300">gw_live_...</code>) are hashed with SHA-256 at rest. Enter only a short human-readable label below—never paste a provider key, secret token, or gateway key into the label field (provider credentials belong in <Link href="/dashboard/policies" className="text-emerald-400 hover:underline">Firewall Policies</Link>). A full gateway key remains viewable only in the browser session where it was created.
          </p>

          <form onSubmit={handleCreateKey} className="space-y-2">
            <label htmlFor="gateway-key-label" className="text-[11px] font-semibold text-slate-300 block">
              Key Label (not a secret or API key)
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                id="gateway-key-label"
                type="text"
                maxLength={100}
                placeholder="Label only, e.g. Production Service (optional)"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={isCreating}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shrink-0"
              >
                <Plus className="w-4 h-4" />
                <span>{isCreating ? "Generating Key..." : "Create Live Key"}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Existing Keys Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Active & Revoked Keys</h3>
              <p className="text-xs text-slate-400">Keys scoped to this workspace</p>
            </div>
            <button
              onClick={loadKeys}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
            </button>
          </div>

          {keys.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500">
              No API keys generated yet. Create a live key above to start securing your LLM traffic!
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                    <th className="pb-3">Name</th>
                    <th className="pb-3">Prefix / Identifier</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3">Created Date</th>
                    <th className="pb-3">Last Used</th>
                    <th className="pb-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {keys.map((k) => (
                    <tr key={k.id} className="hover:bg-slate-800/20 transition-colors">
                      <td className="py-3 font-semibold text-slate-200">
                        {k.name.length > 32 && !/\s/.test(k.name) ? "Credential-like name hidden" : k.name}
                      </td>
                      <td className="py-3 font-mono text-slate-400">
                        <span className="block">{k.prefix}</span>
                        {cachedKeys[k.id] && visibleKeys[k.id] && (
                          <code className="block mt-1 text-emerald-300 break-all select-all">{cachedKeys[k.id]}</code>
                        )}
                      </td>
                      <td className="py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                            k.is_revoked
                              ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                              : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                          }`}
                        >
                          {k.is_revoked ? "REVOKED" : "ACTIVE"}
                        </span>
                      </td>
                      <td className="py-3 text-slate-400">
                        {new Date(k.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 text-slate-400">
                        {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "Never"}
                      </td>
                      <td className="py-3 text-right">
                        <button
                          type="button"
                          disabled={!cachedKeys[k.id]}
                          onClick={() => setVisibleKeys((current) => ({ ...current, [k.id]: !current[k.id] }))}
                          aria-label={visibleKeys[k.id] ? "Hide full gateway key" : "Show full gateway key"}
                          title={cachedKeys[k.id] ? "Full gateway key saved in this browser session" : "Full key unavailable after the creation session; create a new key"}
                          className="text-xs text-slate-300 hover:text-white font-medium px-2 py-1 mr-2 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center gap-1"
                        >
                          {visibleKeys[k.id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          {visibleKeys[k.id] ? "Hide" : "Show"}
                        </button>
                        {!k.is_revoked && (
                          <button
                            onClick={() => setPendingRevokeKeyId(k.id)}
                            className="text-xs text-rose-400 hover:text-rose-300 font-medium px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 transition-colors"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {keys.length > 0 && (
            <p className="mt-3 text-[11px] text-slate-500">
              Show is available only for full keys saved in this browser session. The server stores only key hashes and cannot recover an older full key.
            </p>
          )}
        </div>

        {pendingRevokeKeyId && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true" aria-labelledby="revoke-key-title">
            <div className="bg-slate-900 border border-rose-500/30 rounded-2xl p-6 max-w-md w-full shadow-2xl">
              <h3 id="revoke-key-title" className="text-base font-bold text-slate-100">Revoke gateway key?</h3>
              <p className="text-xs text-slate-400 mt-2">Applications using this key will lose access immediately.</p>
              <div className="flex justify-end gap-3 mt-6">
                <button type="button" disabled={isRevoking} onClick={() => setPendingRevokeKeyId(null)} className="px-4 py-2 rounded-lg text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50">Cancel</button>
                <button type="button" disabled={isRevoking} onClick={() => handleRevokeKey(pendingRevokeKeyId)} className="px-4 py-2 rounded-lg text-xs font-semibold bg-rose-500 text-white hover:bg-rose-400 disabled:opacity-50">
                  {isRevoking ? "Revoking..." : "Revoke key"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* One-Time Key Display Modal */}
        {createdKeyData && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-slate-900 border border-emerald-500/40 rounded-2xl p-6 max-w-lg w-full shadow-2xl">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <Key className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100">Save Your Gateway API Key</h3>
                  <p className="text-xs text-emerald-400 font-medium">Key Generated Successfully</p>
                </div>
              </div>

              <div className="p-3.5 bg-amber-500/10 border border-amber-500/20 rounded-xl text-amber-300 text-xs mb-4 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
                <span>
                  Copy your key now. It is stored on the server only as a SHA-256 hash. You can show it again in this browser session; after the session ends, create a new key if you need a full value.
                </span>
              </div>

              <div className="mb-4">
                <label className="text-xs text-slate-400 block mb-1">Plaintext API Key</label>
                <div className="flex items-center gap-2">
                  <input
                    type={showCreatedKey ? "text" : "password"}
                    readOnly
                    value={createdKeyData.api_key}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs font-mono text-emerald-300 select-all focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowCreatedKey((shown) => !shown)}
                    aria-label={showCreatedKey ? "Hide new gateway key" : "Show new gateway key"}
                    className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                  >
                    {showCreatedKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => copyToClipboard(createdKeyData.api_key)}
                    className="px-4 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs flex items-center gap-1.5 transition-colors shrink-0"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    <span>{copied ? "Copied!" : "Copy Key"}</span>
                  </button>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Link
                  href="/dashboard/playground"
                  className="px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 text-xs font-semibold rounded-lg border border-emerald-500/40 transition-colors"
                >
                  Test in Attack Playground →
                </Link>
                <button
                  onClick={() => setCreatedKeyData(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors"
                >
                  I have saved this key safely
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

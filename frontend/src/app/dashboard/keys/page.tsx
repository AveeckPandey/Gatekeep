"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Key,
  Plus,
  Copy,
  Check,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { Header } from "@/components/Header";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, ApiKey, ApiKeyCreateResponse } from "@/lib/api";

export default function ApiKeysPage() {
  const { token } = useAuth();
  const { activeWorkspace } = useWorkspace();

  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [newKeyName, setNewKeyName] = useState<string>("");
  const [createdKeyData, setCreatedKeyData] = useState<ApiKeyCreateResponse | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loadKeys = useCallback(async () => {
    if (!token || !activeWorkspace) return;
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const list = await api.listKeys(token, activeWorkspace.id);
      setKeys(list);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load keys";
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  }, [token, activeWorkspace]);

  useEffect(() => {
    let isMounted = true;
    if (!token || !activeWorkspace) return;

    api
      .listKeys(token, activeWorkspace.id)
      .then((list) => {
        if (!isMounted) return;
        setKeys(list);
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
  }, [token, activeWorkspace]);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !activeWorkspace || !newKeyName.trim()) return;

    setIsCreating(true);
    setErrorMessage(null);
    try {
      const resp = await api.createKey(token, activeWorkspace.id, newKeyName.trim());
      setCreatedKeyData(resp);
      setNewKeyName("");
      await loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create API key";
      setErrorMessage(msg);
    } finally {
      setIsCreating(false);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!token || !activeWorkspace) return;
    if (!confirm("Are you sure you want to revoke this Gateway API key? Any applications using it will be blocked immediately.")) {
      return;
    }

    try {
      await api.revokeKey(token, activeWorkspace.id, keyId);
      await loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to revoke key";
      alert("Failed to revoke key: " + msg);
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
            Gateway keys (<code className="font-mono text-slate-300">gw_live_...</code>) are hashed with SHA-256 at rest. You will only be able to view the plaintext key once upon generation.
          </p>

          <form onSubmit={handleCreateKey} className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              required
              placeholder="Key Name (e.g. Production Service, Staging Backend)"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              disabled={isCreating || !newKeyName.trim()}
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shrink-0"
            >
              <Plus className="w-4 h-4" />
              <span>{isCreating ? "Generating Key..." : "Create Live Key"}</span>
            </button>
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
                      <td className="py-3 font-semibold text-slate-200">{k.name}</td>
                      <td className="py-3 font-mono text-slate-400">{k.prefix}</td>
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
                        {!k.is_revoked && (
                          <button
                            onClick={() => handleRevokeKey(k.id)}
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
        </div>

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
                  Please copy your key now. For your security, this key is stored strictly as a SHA-256 hash and cannot be displayed again.
                </span>
              </div>

              <div className="mb-4">
                <label className="text-xs text-slate-400 block mb-1">Plaintext API Key</label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={createdKeyData.api_key}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs font-mono text-emerald-300 select-all focus:outline-none"
                  />
                  <button
                    onClick={() => copyToClipboard(createdKeyData.api_key)}
                    className="px-4 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs flex items-center gap-1.5 transition-colors shrink-0"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    <span>{copied ? "Copied!" : "Copy Key"}</span>
                  </button>
                </div>
              </div>

              <div className="flex justify-end pt-2">
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

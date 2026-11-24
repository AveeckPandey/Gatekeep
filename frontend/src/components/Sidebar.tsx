"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  Sliders,
  Key,
  ListFilter,
  Flame,
  LayoutDashboard,
  LogOut,
  FolderGit2,
  Plus,
  ChevronDown,
  Check,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { workspaces, activeWorkspace, setActiveWorkspace, createWorkspace } = useWorkspace();

  const [wsDropdownOpen, setWsDropdownOpen] = useState(false);
  const [showNewWsModal, setShowNewWsModal] = useState(false);
  const [newWsName, setNewWsName] = useState("");
  const [isCreatingWs, setIsCreatingWs] = useState(false);

  const navItems = [
    { name: "Overview", href: "/dashboard", icon: LayoutDashboard },
    { name: "Firewall Policies", href: "/dashboard/policies", icon: Sliders },
    { name: "API Keys", href: "/dashboard/keys", icon: Key },
    { name: "Audit Logs", href: "/dashboard/logs", icon: ListFilter },
    { name: "Attack Playground", href: "/dashboard/playground", icon: Flame },
  ];

  const handleCreateWorkspace = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWsName.trim()) return;
    setIsCreatingWs(true);
    try {
      await createWorkspace(newWsName.trim());
      setNewWsName("");
      setShowNewWsModal(false);
      setWsDropdownOpen(false);
    } finally {
      setIsCreatingWs(false);
    }
  };

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col h-screen select-none">
      {/* Brand & Logo */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:border-emerald-500 transition-colors">
            <ShieldAlert className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="font-bold text-slate-100 tracking-wide text-base">GateKeep</div>
            <div className="text-[10px] text-emerald-400 font-medium uppercase tracking-wider">
              Security Gateway
            </div>
          </div>
        </Link>
        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
          Free Tier
        </span>
      </div>

      {/* Workspace Selector */}
      <div className="p-3 border-b border-slate-800/60 relative">
        <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5 px-1">
          Workspace
        </label>
        <button
          onClick={() => setWsDropdownOpen(!wsDropdownOpen)}
          className="w-full flex items-center justify-between px-3 py-2 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs font-medium transition-colors"
        >
          <div className="flex items-center gap-2 truncate">
            <FolderGit2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="truncate">{activeWorkspace?.name || "Select Workspace"}</span>
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        </button>

        {wsDropdownOpen && (
          <div className="absolute left-3 right-3 top-16 mt-1 bg-slate-900 border border-slate-800 rounded-lg shadow-xl z-50 py-1 overflow-hidden">
            <div className="max-h-48 overflow-y-auto">
              {workspaces.map((ws) => (
                <button
                  key={ws.id}
                  onClick={() => {
                    setActiveWorkspace(ws);
                    setWsDropdownOpen(false);
                  }}
                  className="w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/70 text-slate-300 transition-colors"
                >
                  <span className="truncate">{ws.name}</span>
                  {activeWorkspace?.id === ws.id && (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  )}
                </button>
              ))}
            </div>
            <div className="border-t border-slate-800 p-1">
              <button
                onClick={() => {
                  setWsDropdownOpen(false);
                  setShowNewWsModal(true);
                }}
                className="w-full text-left px-3 py-1.5 text-xs text-emerald-400 hover:bg-emerald-500/10 rounded flex items-center gap-1.5 font-medium transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Workspace</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-all ${
                isActive
                  ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-emerald-400" : "text-slate-400"}`} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* User Info & Logout */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/60">
        <div className="flex items-center justify-between px-2 py-1.5">
          <div className="truncate mr-2">
            <div className="text-xs font-medium text-slate-300 truncate">
              {user?.email || "Authenticated Tenant"}
            </div>
            <div className="text-[10px] text-slate-500 font-mono">Cognito / JWT</div>
          </div>
          <button
            onClick={logout}
            title="Log Out"
            className="p-1.5 rounded-md hover:bg-rose-500/10 text-slate-400 hover:text-rose-400 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* New Workspace Modal */}
      {showNewWsModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-sm w-full shadow-2xl">
            <h3 className="text-base font-semibold text-slate-100 mb-2">Create Workspace</h3>
            <p className="text-xs text-slate-400 mb-4">
              Workspaces isolate firewall policies, API keys, and audit logs.
            </p>
            <form onSubmit={handleCreateWorkspace} className="space-y-4">
              <div>
                <label className="text-xs text-slate-300 block mb-1">Workspace Name</label>
                <input
                  type="text"
                  placeholder="e.g. Production Nemotron Gateway"
                  value={newWsName}
                  onChange={(e) => setNewWsName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500"
                  autoFocus
                  required
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewWsModal(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreatingWs || !newWsName.trim()}
                  className="px-3 py-1.5 text-xs bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold rounded-md transition-colors disabled:opacity-50"
                >
                  {isCreatingWs ? "Creating..." : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </aside>
  );
}

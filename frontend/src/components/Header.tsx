"use client";

import React from "react";
import { ShieldCheck } from "lucide-react";
import { useWorkspace } from "@/context/WorkspaceContext";

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export function Header({ title, subtitle }: HeaderProps) {
  const { activeWorkspace } = useWorkspace();

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur px-8 flex items-center justify-between sticky top-0 z-30">
      <div>
        <h1 className="text-base font-bold text-slate-100">{title}</h1>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-4">
        {/* Active Workspace Pill */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-slate-400">Workspace:</span>
          <span className="font-semibold text-slate-200">
            {activeWorkspace?.name || "Loading..."}
          </span>
        </div>

        {/* Security Shield Indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400">
          <ShieldCheck className="w-4 h-4" />
          <span className="font-medium">Firewall Active</span>
        </div>
      </div>
    </header>
  );
}

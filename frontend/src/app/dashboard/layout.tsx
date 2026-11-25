"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";
import { useAuth } from "@/context/AuthContext";
import { ShieldAlert } from "lucide-react";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { token, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !token) {
      router.push("/login");
    }
  }, [isLoading, token, router]);

  return (
    <div className="relative h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {(isLoading || !token) && (
        <div className="absolute inset-0 z-10 flex flex-col items-center justify-center text-slate-400 gap-3 bg-slate-950">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 animate-pulse">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <p className="text-xs text-slate-400">Loading GateKeep Security Console...</p>
        </div>
      )}
      <div className={`flex h-full ${isLoading || !token ? "invisible" : ""}`}>
        <Sidebar />
        <main className="flex-1 flex flex-col min-w-0 overflow-y-auto bg-slate-950">
          {children}
        </main>
      </div>
    </div>
  );
}

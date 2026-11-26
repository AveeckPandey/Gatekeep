"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ShieldAlert, Lock, Mail, ArrowRight, AlertCircle, Sparkles } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

export default function LoginPage() {
  const { login, demoLogin } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDemoLoading, setIsDemoLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login(email, password);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Invalid credentials. Please try again.";
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDemoAccess = async () => {
    setError(null);
    setIsDemoLoading(true);
    try {
      await demoLogin();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to launch demo workspace.";
      setError(msg);
    } finally {
      setIsDemoLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-md w-full bg-slate-900/90 border border-slate-800 rounded-2xl p-8 shadow-2xl relative z-10 backdrop-blur">
        {/* Logo & Header */}
        <div className="text-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mx-auto mb-4">
            <ShieldAlert className="w-7 h-7" />
          </div>
          <h2 className="text-2xl font-bold text-slate-100">Sign in to GateKeep</h2>
          <p className="text-xs text-slate-400 mt-1.5">
            Multi-Tenant LLM Security Gateway & Prompt Injection Firewall
          </p>
        </div>

        {error && (
          <div className="mb-6 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="email"
                required
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold py-2.5 rounded-lg text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
          >
            <span>{isSubmitting ? "Authenticating..." : "Sign In to Gateway"}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <Link href="/forgot-password" className="mt-4 inline-block text-xs font-medium text-emerald-400 hover:text-emerald-300">
          Forgot your password?
        </Link>

        {/* Recruiter / Quick Demo Access */}
        {process.env.NEXT_PUBLIC_ENABLE_DEMO === "true" && <div className="mt-5 pt-5 border-t border-slate-800">
          <div className="text-center mb-2.5">
            <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
              Recruiter & Quick Evaluation
            </span>
          </div>
          <button
            type="button"
            onClick={handleDemoAccess}
            disabled={isDemoLoading}
            className="w-full bg-gradient-to-r from-emerald-500/20 via-teal-500/20 to-cyan-500/20 hover:from-emerald-500/30 hover:via-teal-500/30 hover:to-cyan-500/30 border border-emerald-500/40 hover:border-emerald-500/70 text-emerald-300 font-bold py-2.5 rounded-lg text-xs flex items-center justify-center gap-2 transition-all shadow-lg shadow-emerald-950/40 disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4 text-emerald-400 animate-pulse" />
            <span>{isDemoLoading ? "Launching Demo Gateway..." : "⚡ Try Demo Workspace (10s Recruiter Access)"}</span>
          </button>
          <p className="text-[11px] text-slate-500 text-center mt-2 leading-relaxed">
            Pre-seeded live attack playground & mock LLM with zero signup or API key setup required.
          </p>
        </div>}

        <div className="mt-5 pt-5 border-t border-slate-800/80 text-center">
          <p className="text-xs text-slate-400">
            Don&apos;t have an account?{" "}
            <Link href="/register" className="text-emerald-400 hover:text-emerald-300 font-semibold">
              Create a tenant account
            </Link>
          </p>
          <Link href="/overview" className="mt-3 inline-block text-xs font-medium text-slate-300 hover:text-emerald-400">
            What does GateKeep do? See the overview →
          </Link>
        </div>
      </div>
    </div>
  );
}

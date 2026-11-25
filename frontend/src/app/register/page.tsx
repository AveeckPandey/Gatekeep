"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Lock, Mail, ArrowRight, AlertCircle, ShieldCheck } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
  const { register } = useAuth();
  const router = useRouter();
  const [confirmationRequired, setConfirmationRequired] = useState(false);
  const [confirmationCode, setConfirmationCode] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isConfirming, setIsConfirming] = useState(false);
  const [isResending, setIsResending] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setIsSubmitting(true);
    try {
      const needsConfirmation = await register(email, password);
      setConfirmationRequired(needsConfirmation);
      if (needsConfirmation) {
        setPassword("");
        setConfirmPassword("");
        setNotice(`A confirmation code was sent to ${email}. Check your inbox and spam folder.`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Registration failed. Please try again.";
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setIsConfirming(true);
    try {
      await api.confirmRegistration(email.trim(), confirmationCode.trim());
      router.push("/login");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Confirmation failed. Please try again.");
    } finally {
      setIsConfirming(false);
    }
  };

  const handleResend = async () => {
    setError(null);
    setNotice(null);
    if (!email.trim()) {
      setError("Enter the email address you used to sign up.");
      return;
    }
    setIsResending(true);
    try {
      const result = await api.resendConfirmation(email.trim());
      setNotice(result.destination
        ? `A new code was sent to ${result.destination}. Check your inbox and spam folder.`
        : "A new code was sent. Check your inbox and spam folder.");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Could not resend the code. Please try again.");
    } finally {
      setIsResending(false);
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
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h2 className="text-2xl font-bold text-slate-100">Create Tenant Account</h2>
          <p className="text-xs text-slate-400 mt-1.5">
            Deploy an isolated LLM Security Firewall for your organisation
          </p>
        </div>

        {error && (
          <div className="mb-6 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {notice && (
          <div role="status" className="mb-6 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-200">
            {notice}
          </div>
        )}

        {confirmationRequired && (
          <form onSubmit={handleConfirm} className="space-y-4 mb-5">
            <div>
              <label htmlFor="confirmation-email" className="text-xs text-slate-300">Signup email address</label>
              <input id="confirmation-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200" />
            </div>
            <div>
              <label htmlFor="confirmation-code" className="text-xs text-slate-300">Email confirmation code</label>
              <input id="confirmation-code" value={confirmationCode} onChange={(e) => setConfirmationCode(e.target.value)} required autoComplete="one-time-code" className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200" />
            </div>
            <button type="submit" disabled={isConfirming} className="bg-emerald-500 text-slate-950 px-4 py-2 rounded-lg disabled:opacity-50">
              {isConfirming ? "Confirming..." : "Confirm account"}
            </button>
            <button type="button" onClick={handleResend} disabled={isResending} className="ml-4 text-sm text-emerald-400 hover:text-emerald-300 disabled:opacity-50">
              {isResending ? "Sending..." : "Resend code"}
            </button>
          </form>
        )}
        {!confirmationRequired && <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="email"
                required
                placeholder="developer@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">
              Password (min. 8 characters)
            </label>
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

          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">
              Confirm Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                required
                placeholder="••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold py-2.5 rounded-lg text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
          >
            <span>{isSubmitting ? "Creating Tenant..." : "Create Tenant Workspace"}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>}

        {!confirmationRequired && (
          <button type="button" onClick={() => { setError(null); setNotice(null); setConfirmationRequired(true); }} className="mt-5 text-xs text-emerald-400 hover:text-emerald-300">
            Already signed up? Enter your confirmation code
          </button>
        )}

        <div className="mt-6 pt-6 border-t border-slate-800/80 text-center">
          <p className="text-xs text-slate-400">
            Already have an account?{" "}
            <Link href="/login" className="text-emerald-400 hover:text-emerald-300 font-semibold">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

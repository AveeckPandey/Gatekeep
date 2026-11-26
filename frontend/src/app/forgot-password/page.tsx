"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [step, setStep] = useState<"email" | "code" | "done">("email");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function sendCode() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await api.forgotPassword(email.trim());
      setNotice(response.message);
      setStep("code");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not request a reset code.");
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (step === "email") return sendCode();
    setError("");
    setNotice("");
    if (password !== confirmation) {
      setError("Passwords do not match.");
      return;
    }
    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
      setError("Use uppercase and lowercase letters, a number and a symbol.");
      return;
    }
    setBusy(true);
    try {
      const response = await api.resetPassword(email.trim(), code.trim(), password);
      setNotice(response.message);
      setPassword("");
      setConfirmation("");
      setCode("");
      setStep("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset your password.");
    } finally {
      setBusy(false);
    }
  }

  const inputStyle = "mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 focus:border-emerald-500 focus:outline-none disabled:opacity-60";
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4">
      <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-xl">
        <ShieldCheck className="mx-auto mb-4 h-10 w-10 text-emerald-400" aria-hidden="true" />
        <h1 className="text-center text-2xl font-bold">Reset your password</h1>
        <p className="mt-2 mb-6 text-center text-sm text-slate-400">Use the email address for your GateKeep account.</p>
        {error && <p role="alert" className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</p>}
        {notice && <p role="status" className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">{notice}</p>}
        {step !== "done" && <form onSubmit={submit} className="space-y-4">
          <div>
            <label htmlFor="reset-email" className="text-sm">Email address</label>
            <input id="reset-email" type="email" autoComplete="email" required value={email} disabled={busy || step === "code"} onChange={(e) => setEmail(e.target.value)} className={inputStyle} />
          </div>
          {step === "code" && <>
            <div>
              <label htmlFor="reset-code" className="text-sm">Email reset code</label>
              <input id="reset-code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={code} disabled={busy} onChange={(e) => setCode(e.target.value)} className={inputStyle} />
            </div>
            <div>
              <label htmlFor="reset-password" className="text-sm">New password</label>
              <input id="reset-password" type="password" autoComplete="new-password" minLength={8} maxLength={72} required value={password} disabled={busy} onChange={(e) => setPassword(e.target.value)} aria-describedby="password-requirements" className={inputStyle} />
              <p id="password-requirements" className="mt-2 text-xs text-slate-400">8–72 characters, with uppercase, lowercase, a number and a symbol.</p>
            </div>
            <div>
              <label htmlFor="reset-confirm" className="text-sm">Confirm new password</label>
              <input id="reset-confirm" type="password" autoComplete="new-password" minLength={8} maxLength={72} required value={confirmation} disabled={busy} onChange={(e) => setConfirmation(e.target.value)} className={inputStyle} />
            </div>
          </>}
          <button disabled={busy} type="submit" className="w-full rounded-lg bg-emerald-500 px-4 py-3 font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50">
            {busy ? "Please wait..." : step === "email" ? "Send reset code" : "Update password"}
          </button>
          {step === "code" && <div className="flex justify-between text-sm text-emerald-400">
            <button disabled={busy} type="button" onClick={sendCode}>Resend code</button>
            <button disabled={busy} type="button" onClick={() => { setStep("email"); setCode(""); setPassword(""); setConfirmation(""); setNotice(""); setError(""); }}>Change email</button>
          </div>}
        </form>}
        <Link href="/login" className="mt-6 block text-center text-sm font-semibold text-emerald-400 hover:text-emerald-300">Back to sign in</Link>
      </section>
    </main>
  );
}

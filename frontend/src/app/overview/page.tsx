import Link from "next/link";
import { ArrowRight, KeyRound, ScanSearch, ShieldCheck, Waypoints } from "lucide-react";

const steps = [
  {
    number: "01",
    title: "Connect a provider",
    text: "In a workspace, set a compatible chat completions base URL (with Bearer auth) for any AI model and its provider API key. Other API formats require dedicated adapters. GateKeep encrypts that key at rest.",
  },
  {
    number: "02",
    title: "Create a gateway key",
    text: "Create a separate gw_live_ key for your app. It authenticates requests to GateKeep and is stored on the server as a hash.",
  },
  {
    number: "03",
    title: "Inspect and forward",
    text: "GateKeep checks supported text and tool fields using deterministic regex, Luhn, entropy, and heuristic injection rules, then blocks, redacts, or allows requests according to your policy.",
  },
  {
    number: "04",
    title: "Review the result",
    text: "When enabled, response inspection checks model text and streamed tool arguments for matching secrets or PII. The gateway returns a verdict and records one audit entry.",
  },
];

export default function OverviewPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-6xl px-6 pb-16">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 py-6">
          <Link href="/overview" className="flex items-center gap-2 text-base font-bold tracking-wide">
            <ShieldCheck className="h-6 w-6 text-emerald-400" /> GateKeep
          </Link>
          <div className="flex items-center gap-3 text-xs font-semibold">
            <Link href="/login" className="text-slate-300 hover:text-white">Sign in</Link>
            <Link href="/register" className="rounded-lg bg-emerald-500 px-4 py-2 text-slate-950 hover:bg-emerald-400">Create account</Link>
          </div>
        </header>

        <section className="py-14 md:py-20">
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-emerald-400">Product overview</p>
          <h1 className="mt-4 max-w-4xl text-3xl font-bold leading-tight md:text-5xl">
            Inspect what reaches your AI model with deterministic gateway rules.
          </h1>
          <p className="mt-6 max-w-3xl text-sm leading-7 text-slate-300 md:text-base">
            GateKeep sits between your application and a compatible <code className="font-mono text-slate-200">/chat/completions</code> provider. It authenticates each request, checks supported text fields against regex, Luhn, entropy, and heuristic injection rules, applies your policy, forwards permitted traffic, and records the outcome.
          </p>
          <Link href="/register" className="mt-8 inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-emerald-400">
            Set up a workspace <ArrowRight className="h-4 w-4" />
          </Link>
        </section>

        <section aria-labelledby="how-it-works" className="border-t border-slate-800 py-10">
          <div className="flex items-center gap-2 text-emerald-400">
            <Waypoints className="h-5 w-5" />
            <h2 id="how-it-works" className="text-xl font-bold text-slate-100">How it works</h2>
          </div>
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            {steps.map((step) => (
              <article key={step.number} className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                <span className="font-mono text-sm font-bold text-emerald-400">{step.number}</span>
                <h3 className="mt-3 text-base font-semibold">{step.title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">{step.text}</p>
              </article>
            ))}
          </div>
        </section>

        <section aria-labelledby="what-you-get" className="border-t border-slate-800 py-10">
          <h2 id="what-you-get" className="text-xl font-bold">What you can do in the dashboard</h2>
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <div className="rounded-xl border border-slate-800 p-5">
              <ScanSearch className="h-6 w-6 text-emerald-400" />
              <h3 className="mt-3 text-sm font-semibold">Test the firewall</h3>
              <p className="mt-2 text-xs leading-5 text-slate-400">Use the playground to send safe prompts and attack examples, then inspect the verdict and model response.</p>
            </div>
            <div className="rounded-xl border border-slate-800 p-5">
              <KeyRound className="h-6 w-6 text-emerald-400" />
              <h3 className="mt-3 text-sm font-semibold">Manage access</h3>
              <p className="mt-2 text-xs leading-5 text-slate-400">Create or revoke workspace gateway keys. Provider credentials belong in the encrypted firewall policy.</p>
            </div>
            <div className="rounded-xl border border-slate-800 p-5">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
              <h3 className="mt-3 text-sm font-semibold">Review activity</h3>
              <p className="mt-2 text-xs leading-5 text-slate-400">See allowed, redacted, blocked, and error outcomes in the audit log, with findings and inspection timing.</p>
            </div>
          </div>
        </section>

        <section aria-labelledby="scope-and-limits" className="border-t border-slate-800 py-10">
          <h2 id="scope-and-limits" className="text-xl font-bold">Protection scope and model compatibility</h2>
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
              <h3 className="text-sm font-semibold text-emerald-400">What is inspected (and known limits)</h3>
              <p className="mt-2 text-xs leading-6 text-slate-300">
                GateKeep uses deterministic pattern matching rather than an LLM classifier. It inspects text strings, <code className="font-mono">type: &quot;text&quot;</code> content parts, tool definitions, tool arguments, and compatible SSE streams for email addresses, Luhn-valid credit cards (13–19 digits), AWS/OpenAI/GitHub key patterns, unbroken high-entropy tokens (&ge;16 chars), and literal English prompt-injection phrases.
              </p>
              <p className="mt-2 text-xs leading-6 text-slate-400">
                Limitations: unlisted PII (such as phone numbers or SSNs) and obfuscated or encoded injections are not caught by these rules, and benign or educational text quoting an attack phrase literally can trigger a match. Unsupported non-text media (images, audio, files) is rejected rather than passed uninspected.
              </p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
              <h3 className="text-sm font-semibold text-emerald-400">Supported AI model endpoints</h3>
              <p className="mt-2 text-xs leading-6 text-slate-300">
                Upstream providers must expose a compatible <code className="font-mono">/chat/completions</code> endpoint using <code className="font-mono">Authorization: Bearer</code> authentication (such as compatible chat-completions endpoints for Gemini, Claude, NVIDIA NIM, or self-hosted gateways).
              </p>
              <p className="mt-2 text-xs leading-6 text-slate-400">
                Native-only provider endpoints (non-compatible Gemini/Anthropic schemas, image generation, embeddings, or audio APIs) require dedicated adapters and are not handled by <code className="font-mono">/v1/chat/completions</code>.
              </p>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

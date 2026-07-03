"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";

export function AuthForm({ mode }: { mode: "login" | "register" }) {
  const { login, register } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isRegister = mode === "register";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (isRegister) await register(email, password);
      else await login(email, password);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  }

  const inputStyle: React.CSSProperties = {
    width: "100%",
    background: "var(--panel)",
    border: "1px solid var(--line)",
    borderRadius: 8,
    color: "var(--tx)",
    padding: "11px 12px",
    fontSize: 14,
    marginTop: 6,
  };

  return (
    <div style={{ maxWidth: 400, margin: "0 auto", paddingTop: 64 }}>
      <h1 style={{ fontSize: 26, textAlign: "center", margin: "0 0 6px" }}>
        {isRegister ? "Create account" : "Sign in"}
      </h1>
      <p className="muted small" style={{ textAlign: "center", margin: "0 0 28px" }}>
        {isRegister
          ? "Your API keys are stored encrypted and used only for your investigations."
          : "Welcome back to ReQuiem."}
      </p>

      <form onSubmit={submit} className="card">
        <label className="small muted">
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            style={inputStyle}
          />
        </label>
        <label className="small muted" style={{ display: "block", marginTop: 14 }}>
          Password{isRegister && " (min 8 characters)"}
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={isRegister ? 8 : undefined}
            autoComplete={isRegister ? "new-password" : "current-password"}
            style={inputStyle}
          />
        </label>

        {error && (
          <div style={{ color: "#fca5a5", fontSize: 13, marginTop: 12 }}>{error}</div>
        )}

        <button
          className="btn"
          disabled={busy}
          style={{ width: "100%", marginTop: 18 }}
          type="submit"
        >
          {busy ? "…" : isRegister ? "Create account" : "Sign in"}
        </button>
      </form>

      <p className="small muted" style={{ textAlign: "center", marginTop: 16 }}>
        {isRegister ? (
          <>
            Already have an account? <a href="/login">Sign in</a>
          </>
        ) : (
          <>
            No account? <a href="/register">Create one</a>
          </>
        )}
      </p>
    </div>
  );
}

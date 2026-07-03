"use client";
import { useRouter } from "next/navigation";
import { useInvestigation } from "@/lib/investigation";
import { useAuth } from "@/lib/auth";

export function NavBar() {
  const { reset } = useInvestigation();
  const { user, loading, logout } = useAuth();
  const router = useRouter();

  const linkStyle: React.CSSProperties = {
    background: "none",
    border: "none",
    cursor: "pointer",
    color: "var(--mut)",
    fontSize: 13,
  };

  async function signOut() {
    await logout();
    router.push("/");
  }

  return (
    <nav className="nav">
      <div className="wrap nav-inner">
        <button
          onClick={() => {
            reset();
            router.push("/");
          }}
          className="logo"
          style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}
        >
          ReQuiem <span>· analysis workbench</span>
        </button>
        <div style={{ flex: 1 }} />

        <button onClick={reset} style={linkStyle}>
          New investigation
        </button>

        {loading ? null : user ? (
          <>
            <span style={{ width: 1, height: 18, background: "var(--line)" }} />
            <button onClick={() => router.push("/settings")} style={linkStyle}>
              API keys
            </button>
            <span className="small muted" style={{ maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis" }}>
              {user.email}
            </span>
            <button onClick={signOut} style={linkStyle}>
              Sign out
            </button>
          </>
        ) : (
          <>
            <span style={{ width: 1, height: 18, background: "var(--line)" }} />
            <button onClick={() => router.push("/login")} style={linkStyle}>
              Sign in
            </button>
            <button
              onClick={() => router.push("/register")}
              className="btn small"
              style={{ padding: "5px 12px" }}
            >
              Register
            </button>
          </>
        )}
      </div>
    </nav>
  );
}

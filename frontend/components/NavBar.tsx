"use client";
import { useInvestigation } from "@/lib/investigation";

export function NavBar() {
  const { reset } = useInvestigation();
  return (
    <nav className="nav">
      <div className="wrap nav-inner">
        <button
          onClick={reset}
          className="logo"
          style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}
        >
          ReQuiem <span>· analysis workbench</span>
        </button>
        <div style={{ flex: 1 }} />
        <button
          onClick={reset}
          className="small muted"
          style={{ background: "none", border: "none", cursor: "pointer" }}
        >
          New investigation
        </button>
      </div>
    </nav>
  );
}

"use client";
import { createContext, useCallback, useContext, useRef } from "react";

// A tiny pub/sub so the nav's "New investigation" link (rendered in the root
// layout) can reset the page-level state that lives in the Home component.
type ResetFn = () => void;

const Ctx = createContext<{
  register: (fn: ResetFn) => void;
  reset: () => void;
} | null>(null);

export function InvestigationProvider({ children }: { children: React.ReactNode }) {
  const ref = useRef<ResetFn | null>(null);
  const register = useCallback((fn: ResetFn) => {
    ref.current = fn;
  }, []);
  const reset = useCallback(() => {
    ref.current?.();
  }, []);
  return <Ctx.Provider value={{ register, reset }}>{children}</Ctx.Provider>;
}

export function useInvestigation() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useInvestigation must be used within InvestigationProvider");
  return ctx;
}

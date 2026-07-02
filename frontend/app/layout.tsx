import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "ReQuiem · Malware Analysis Workbench",
  description:
    "One upload · one investigation · one report · one ATT&CK view · one IOC export.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <nav className="nav">
          <div className="wrap nav-inner">
            <Link href="/" className="logo">
              ReQuiem <span>· analysis workbench</span>
            </Link>
            <div style={{ flex: 1 }} />
            <Link href="/" className="small muted">
              New investigation
            </Link>
          </div>
        </nav>
        <main className="wrap" style={{ paddingBottom: 80 }}>
          {children}
        </main>
      </body>
    </html>
  );
}

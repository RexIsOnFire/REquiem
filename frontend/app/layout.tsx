import "./globals.css";
import type { Metadata } from "next";
import { InvestigationProvider } from "@/lib/investigation";
import { NavBar } from "@/components/NavBar";

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
        <InvestigationProvider>
          <NavBar />
          <main className="wrap" style={{ paddingBottom: 80 }}>
            {children}
          </main>
        </InvestigationProvider>
      </body>
    </html>
  );
}

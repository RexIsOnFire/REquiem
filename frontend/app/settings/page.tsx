"use client";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { deleteKey, getKeyStatus, saveKey } from "@/lib/api";
import { useAuth } from "@/lib/auth";

// Human labels + help for each storable key.
const KEY_INFO: Record<string, { label: string; help: string; url?: string }> = {
  VT_API_KEY: {
    label: "VirusTotal",
    help: "Reputation + by-hash behavior. Free key from your VT account.",
    url: "https://www.virustotal.com/gui/my-apikey",
  },
  MALWAREBAZAAR_API_KEY: {
    label: "MalwareBazaar",
    help: "Hash reputation. Free key required.",
    url: "https://auth.abuse.ch/",
  },
  HYBRIDANALYSIS_API_KEY: {
    label: "Hybrid Analysis",
    help: "By-hash cloud behavior (Falcon Sandbox). Free research tier.",
    url: "https://www.hybrid-analysis.com/",
  },
  TRIAGE_TOKEN: {
    label: "Hatching Triage",
    help: "By-hash cloud behavior. Requires a researcher license.",
    url: "https://tria.ge/",
  },
  CAPE_URL: {
    label: "CAPE URL",
    help: "Your self-hosted CAPE sandbox base URL (optional).",
  },
  CAPE_TOKEN: { label: "CAPE token", help: "Optional CAPE API token." },
};

function KeyRow({
  name,
  isSet,
  onChanged,
}: {
  name: string;
  isSet: boolean;
  onChanged: () => void;
}) {
  const info = KEY_INFO[name] ?? { label: name, help: "" };
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  async function save() {
    if (!value.trim()) return;
    setBusy(true);
    try {
      await saveKey(name, value.trim());
      setValue("");
      onChanged();
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    setBusy(true);
    try {
      await deleteKey(name);
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <b>{info.label}</b>
        <span
          className="badge"
          style={{
            borderColor: isSet ? "#22c55e" : "var(--line)",
            color: isSet ? "#86efac" : "var(--mut)",
          }}
        >
          {isSet ? "configured" : "not set"}
        </span>
        <code className="mono small muted" style={{ marginLeft: "auto" }}>
          {name}
        </code>
      </div>
      <div className="small muted" style={{ marginTop: 4 }}>
        {info.help}{" "}
        {info.url && (
          <a href={info.url} target="_blank" rel="noreferrer">
            get a key ↗
          </a>
        )}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={isSet ? "Enter a new value to replace…" : "Paste your key…"}
          className="mono"
          style={{
            flex: 1,
            background: "var(--panel2)",
            border: "1px solid var(--line)",
            borderRadius: 8,
            color: "var(--tx)",
            padding: "9px 11px",
            fontSize: 13,
          }}
        />
        <button className="btn small" disabled={busy || !value.trim()} onClick={save}>
          Save
        </button>
        {isSet && (
          <button className="btn btn-ghost small" disabled={busy} onClick={remove}>
            Clear
          </button>
        )}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [status, setStatus] = useState<Record<string, boolean>>({});
  const [allowed, setAllowed] = useState<string[]>([]);

  const load = useCallback(async () => {
    try {
      const r = await getKeyStatus();
      setStatus(r.status);
      setAllowed(r.allowed);
    } catch {
      /* not authed — handled below */
    }
  }, []);

  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
      return;
    }
    if (user) load();
  }, [user, loading, router, load]);

  if (loading || !user) {
    return (
      <div style={{ textAlign: "center", paddingTop: 80 }} className="muted">
        Loading…
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 640, margin: "0 auto", paddingTop: 40 }}>
      <h1 style={{ fontSize: 24, margin: "0 0 4px" }}>API Keys</h1>
      <p className="muted small" style={{ margin: "0 0 20px" }}>
        Signed in as <b>{user.email}</b>. Keys are stored <b>encrypted</b> and used
        only to power <i>your</i> investigations — they are never shown back or
        shared. Values are write-only.
      </p>
      {allowed.map((name) => (
        <KeyRow key={name} name={name} isSet={!!status[name]} onChanged={load} />
      ))}
    </div>
  );
}

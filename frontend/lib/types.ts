// TypeScript mirror of requiem.core.models. The Python side serializes enums as
// { name, value }, so we model that shape here.

export interface Enum {
  name: string;
  value: number;
}

export interface Evidence {
  detail: string;
  locator: string | null;
  source: string | null;
}

export interface Finding {
  title: string;
  description: string;
  confidence: Enum;
  severity: Enum;
  evidence: Evidence[];
  attack_techniques: string[];
  tags: string[];
}

export interface FileIdentity {
  filename: string;
  size: number;
  md5: string;
  sha1: string;
  sha256: string;
  magic: string;
  mime: string;
  format: string;
  arch: string;
  bitness: number;
  entrypoint: number | null;
}

export interface LanguageGuess {
  language: string;
  confidence: Enum;
  compiler: string | null;
  evidence: Evidence[];
}

export interface PackerGuess {
  name: string;
  confidence: Enum;
  evidence: Evidence[];
}

export interface SectionInfo {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  characteristics: string[];
}

export interface IOCSet {
  ipv4: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  file_paths: string[];
  registry_keys: string[];
  mutexes: string[];
  bitcoin: string[];
}

export interface IntelResult {
  source: string;
  known: boolean;
  family: string | null;
  first_seen: string | null;
  prevalence: number | null;
  tags: string[];
  detail: string | null;
}

export interface ProcessNode {
  pid: number;
  name: string;
  cmdline: string;
  children: ProcessNode[];
}

export interface DynamicBehavior {
  executed: boolean;
  backend: string;
  simulated: boolean;
  process_tree: ProcessNode[];
  network: Record<string, unknown>[];
  filesystem: Record<string, unknown>[];
  registry: Record<string, unknown>[];
  memory: Finding[];
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  confidence: Enum;
  evidence: Evidence[];
}

export interface AnalysisReport {
  identity: FileIdentity;
  created_at: string;
  engine_version: string;
  languages: LanguageGuess[];
  packers: PackerGuess[];
  sections: SectionInfo[];
  imports: string[];
  exports: string[];
  strings_of_interest: string[];
  iocs: IOCSet;
  yara_matches: string[];
  intel: IntelResult[];
  dynamic: DynamicBehavior;
  findings: Finding[];
  attack: AttackTechnique[];
  verdict: string;
  verdict_confidence: Enum;
  classification: string | null;
  summary: string;
}

export interface AttackMatrix {
  tactics: string[];
  techniques: { id: string; name: string; tactic: string }[];
}

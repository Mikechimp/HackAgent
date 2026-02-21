/**
 * HackAgent — Shared TypeScript Types
 */

export interface ChatRequest {
  message: string;
  session_id?: string;
  model?: string;
}

export interface ChatResponse {
  response: string;
  tokens: number;
  model: string;
}

export interface AnalyzeUrlRequest {
  url: string;
}

export interface SetupKeyRequest {
  api_key: string;
}

export interface StatusResponse {
  status: string;
  api_configured: boolean;
  version: string;
}

export interface PageData {
  url: string;
  status_code: number | null;
  headers: Record<string, string>;
  cookies: CookieInfo[];
  html: string;
  scripts: ScriptInfo[];
  forms: FormInfo[];
  links: string[];
  comments: string[];
  technologies: TechInfo[];
  security_headers: Record<string, SecurityHeaderCheck>;
  errors: string[];
}

export interface CookieInfo {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httponly: boolean;
}

export interface ScriptInfo {
  type: 'external' | 'inline';
  src?: string;
  preview?: string;
  length?: number;
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: { name: string; type: string }[];
}

export interface TechInfo {
  name: string;
  value?: string;
  source: string;
}

export interface SecurityHeaderCheck {
  present: boolean;
  value: string | null;
  severity: string;
}

export interface Finding {
  type: string;
  severity: string;
  title: string;
  description: string;
}

export interface ApiResult {
  raw: string;
  raw_text: string;
  tokens_estimated: number;
  meta: {
    model: string;
    timestamp: string;
    attempt: number;
  };
}

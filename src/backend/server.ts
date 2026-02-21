/**
 * HackAgent — Express Backend Server (v2 — Unified Pipelines)
 * Both URL scan and extension analysis now get full Jhaddix-powered detection.
 */
import express from 'express';
import cors from 'cors';
import * as fs from 'fs';
import * as path from 'path';
import {
  chatWithHackagent,
  analyzeUrlContent,
  analyzePageWithVision,
  isApiConfigured,
  resetClient,
} from './services/openai-client';
import { fetchPage, quickVulnCheck, detectTechnologies } from './services/page-analyzer';

const app = express();
const PORT = parseInt(process.env.HACKAGENT_PORT || '5175', 10);

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ─── In-memory conversation storage ───
const conversations: Record<string, { role: string; content: string }[]> = {};

// ─── Projects / Saved Analyses ───
const PROJECTS_DIR = path.join(__dirname, '..', '..', 'data', 'projects');
if (!fs.existsSync(PROJECTS_DIR)) {
  fs.mkdirSync(PROJECTS_DIR, { recursive: true });
}

let latestExtensionProjectId: string | null = null;

function generateProjectId(): string {
  return 'proj_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
}

function saveProject(project: any): void {
  fs.writeFileSync(
    path.join(PROJECTS_DIR, project.id + '.json'),
    JSON.stringify(project, null, 2),
  );
}

function loadProject(id: string): any | null {
  const fp = path.join(PROJECTS_DIR, id + '.json');
  if (!fs.existsSync(fp)) return null;
  return JSON.parse(fs.readFileSync(fp, 'utf-8'));
}

function listProjects(): any[] {
  if (!fs.existsSync(PROJECTS_DIR)) return [];
  return fs
    .readdirSync(PROJECTS_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      const d = JSON.parse(fs.readFileSync(path.join(PROJECTS_DIR, f), 'utf-8'));
      return {
        id: d.id,
        name: d.name,
        url: d.url,
        source: d.source,
        created_at: d.created_at,
        finding_count: (d.findings?.quick_findings?.length || 0),
        has_ai: !!d.findings?.ai_analysis,
        notes: d.notes || '',
      };
    })
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
}

function deleteProject(id: string): boolean {
  const fp = path.join(PROJECTS_DIR, id + '.json');
  if (!fs.existsSync(fp)) return false;
  fs.unlinkSync(fp);
  return true;
}

// ─── Load attack surface knowledge base ───
let attackSurfaceDb: any = {};
const dataPath = path.join(__dirname, '..', '..', 'data', 'attack_surface.json');
if (fs.existsSync(dataPath)) {
  attackSurfaceDb = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
  console.log('[Server] Jhaddix attack surface DB loaded ✓');
}

// ─── Load .env on startup ───
function loadDotenv(): void {
  const envPath = path.join(__dirname, '..', '..', '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();
    if (key && !(key in process.env)) {
      process.env[key] = value;
    }
  }
}

loadDotenv();

// ─── Middleware: check API key ───
function checkApiKey(): string | null {
  const key = process.env.OPENAI_API_KEY || '';
  if (!key || key.startsWith('sk-proj-your')) {
    return 'No OpenAI API key configured. Enter your key in the setup screen.';
  }
  return null;
}

// ─── Attack Surface Matching ───
function matchAttackSurface(technologies: any[]): any[] {
  const matches: any[] = [];
  const categories = attackSurfaceDb?.categories || {};
  const techNames = new Set(technologies.map((t: any) => (t.name || '').toLowerCase()));

  for (const [catName, catData] of Object.entries(categories)) {
    for (const [toolName, toolData] of Object.entries((catData as any)?.tools || {})) {
      const lower = toolName.toLowerCase();
      if (techNames.has(lower) || [...techNames].some(t => t.includes(lower) || lower.includes(t))) {
        matches.push({
          technology: toolName,
          category: catName,
          attack_vectors: (toolData as any).attack_vectors || [],
          default_creds: (toolData as any).default_creds || [],
          critical_cves: (toolData as any).critical_cves || [],
        });
      }
    }
  }

  // Also check default_credentials section
  const defaultCreds = attackSurfaceDb?.default_credentials || {};
  for (const [, services] of Object.entries(defaultCreds)) {
    for (const [serviceName, creds] of Object.entries(services as any)) {
      const lower = serviceName.toLowerCase();
      if (techNames.has(lower) || [...techNames].some(t => t.includes(lower) || lower.includes(t))) {
        const existing = matches.find(m => m.technology.toLowerCase() === lower);
        if (existing) {
          existing.default_creds = [...existing.default_creds, ...(creds as any[])];
        } else {
          matches.push({
            technology: serviceName,
            category: 'default_credentials',
            attack_vectors: [],
            default_creds: creds as any[],
            critical_cves: [],
          });
        }
      }
    }
  }

  return matches;
}

// ─── Routes ───

app.get('/api/status', (_req, res) => {
  res.json({
    status: 'online',
    api_configured: isApiConfigured(),
    version: '2.0.0',
    pending_extension_result: latestExtensionProjectId,
  });
});

app.post('/api/setup-key', (req, res) => {
  const { api_key } = req.body;
  if (!api_key?.trim()) {
    return res.status(400).json({ error: 'API key cannot be empty' });
  }

  const key = api_key.trim();
  const envPath = path.join(__dirname, '..', '..', '.env');

  try {
    if (fs.existsSync(envPath)) {
      const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
      let found = false;
      for (let i = 0; i < lines.length; i++) {
        const stripped = lines[i].trim();
        if (stripped.startsWith('OPENAI_API_KEY=') || stripped.startsWith('# OPENAI_API_KEY=')) {
          lines[i] = `OPENAI_API_KEY=${key}`;
          found = true;
          break;
        }
      }
      if (!found) lines.push(`OPENAI_API_KEY=${key}`);
      fs.writeFileSync(envPath, lines.join('\n') + '\n');
    } else {
      fs.writeFileSync(envPath, `OPENAI_API_KEY=${key}\n`);
    }

    process.env.OPENAI_API_KEY = key;
    resetClient();

    console.log('[Server] API key saved and activated');
    res.json({ status: 'ok' });
  } catch (e: any) {
    console.error('[Server] Failed to save API key:', e.message);
    res.status(500).json({ error: `Failed to save key: ${e.message}` });
  }
});

app.post('/api/chat', async (req, res) => {
  const { message, session_id = 'default', model = 'gpt-4o' } = req.body;
  if (!message) {
    return res.status(400).json({ error: "Missing 'message' field" });
  }

  const keyErr = checkApiKey();
  if (keyErr) return res.status(503).json({ error: keyErr });

  if (!conversations[session_id]) conversations[session_id] = [];
  const history = conversations[session_id];

  try {
    const result = await chatWithHackagent(message, history, model);

    history.push({ role: 'user', content: message });
    history.push({ role: 'assistant', content: result.raw_text });

    if (history.length > 20) {
      conversations[session_id] = history.slice(-20);
    }

    res.json({
      response: result.raw_text,
      tokens: result.tokens_estimated,
      model: result.meta.model,
    });
  } catch (e: any) {
    console.error('[Server] Chat error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── URL Analysis (full pipeline) ───
app.post('/api/analyze-url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing 'url' field" });

  const keyErr = checkApiKey();
  if (keyErr) return res.status(503).json({ error: keyErr });

  console.log(`[Server] Analyzing URL: ${url}`);

  try {
    // Phase 1: Fetch and extract
    const pageData = await fetchPage(url);

    // Phase 2: Automated vulnerability checks (now 20+ check categories)
    const quickFindings = quickVulnCheck(pageData);

    // Phase 3: Match against Jhaddix attack surface DB
    const matchedTech = matchAttackSurface(pageData.technologies);

    // Phase 4: AI analysis with FULL context (Jhaddix data + automated findings)
    const aiResult = await analyzeUrlContent(
      url,
      pageData.headers,
      pageData.html,
      pageData.scripts,
      pageData.forms,
      pageData.cookies,
      'gpt-4o',
      matchedTech,
      attackSurfaceDb?.common_vulnerability_patterns,
      quickFindings,
      pageData.technologies,
    );

    // Auto-save as project
    let hostname = url;
    try { hostname = new URL(url).hostname; } catch (_) {}
    const project = {
      id: generateProjectId(),
      name: hostname + ' — URL Scan',
      url,
      source: 'url-scan',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      findings: {
        quick_findings: quickFindings,
        ai_analysis: aiResult.raw_text,
        attack_surface_matches: matchedTech,
        technologies: pageData.technologies,
        security_headers: pageData.security_headers,
      },
      metadata: {
        status_code: pageData.status_code,
        forms_count: pageData.forms.length,
        scripts_count: pageData.scripts.length,
        comments_count: pageData.comments.length,
        links_count: pageData.links.length,
        finding_count: quickFindings.length,
        errors: pageData.errors,
      },
      notes: '',
    };
    saveProject(project);
    console.log(`[Server] Saved project ${project.id} — ${quickFindings.length} automated findings, ${matchedTech.length} attack surface matches`);

    res.json({
      url,
      project_id: project.id,
      status_code: pageData.status_code,
      technologies: pageData.technologies,
      security_headers: pageData.security_headers,
      quick_findings: quickFindings,
      ai_analysis: aiResult.raw_text,
      attack_surface_matches: matchedTech,
      forms_count: pageData.forms.length,
      scripts_count: pageData.scripts.length,
      comments_count: pageData.comments.length,
      errors: pageData.errors,
    });
  } catch (e: any) {
    console.error('[Server] URL analysis error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Extension Page Analysis (UNIFIED pipeline — same quality as URL scan) ───
app.post('/api/analyze-page', async (req, res) => {
  const {
    url = 'unknown',
    html = '',
    headers = {},
    cookies = [],
    screenshot,
    scripts: extScripts,
    forms: extForms,
    links: extLinks,
    comments: extComments,
    storage,
    discoveredEndpoints,
    detectedTechnologies: extTech,
    meta: extMeta,
    cspMeta,
  } = req.body;

  const keyErr = checkApiKey();
  if (keyErr) return res.status(503).json({ error: keyErr });

  try {
    let hostname = url;
    try { hostname = new URL(url).hostname; } catch (_) {}

    // Screenshot-only path
    if (screenshot && !html) {
      const matchedTech = matchAttackSurface(extTech?.map((t: string) => ({ name: t })) || []);
      const result = await analyzePageWithVision(
        screenshot, undefined, url, 'gpt-4o',
        matchedTech, attackSurfaceDb?.common_vulnerability_patterns,
      );
      const project = {
        id: generateProjectId(),
        name: hostname + ' — Screenshot',
        url,
        source: 'extension',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        findings: { quick_findings: [], ai_analysis: result.raw_text, attack_surface_matches: matchedTech },
        metadata: { analysis_type: 'vision' },
        notes: '',
      };
      saveProject(project);
      latestExtensionProjectId = project.id;
      console.log(`[Server] Saved extension screenshot project ${project.id}`);
      return res.json({ url, project_id: project.id, ai_analysis: result.raw_text, analysis_type: 'vision' });
    }

    // ── FULL ANALYSIS PIPELINE (same quality as URL scan) ──

    // Build technologies list: merge extension client-side detection + server-side fingerprinting
    const serverTechs = detectTechnologies(headers, html);
    const clientTechNames = new Set(serverTechs.map(t => t.name));
    const allTechnologies = [...serverTechs];

    // Merge any extra techs from extension's client-side detection
    if (extTech?.length) {
      for (const t of extTech) {
        const name = typeof t === 'string' ? t : t.name;
        if (name && !clientTechNames.has(name)) {
          allTechnologies.push({ name, source: 'extension-client', category: 'detected' });
          clientTechNames.add(name);
        }
      }
    }

    // Build proper PageData from extension capture
    const pageData = {
      url,
      html,
      headers,
      cookies: cookies.map((c: any) => ({
        name: c.name || '',
        value: c.value || '',
        domain: '',
        path: '/',
        secure: false,
        httponly: false,
      })),
      scripts: extScripts || [],
      forms: extForms || [],
      links: (extLinks || []).map((l: any) => typeof l === 'string' ? l : l.href).filter(Boolean),
      comments: extComments || [],
      technologies: allTechnologies,
      security_headers: checkSecurityHeadersFromRaw(headers),
      status_code: null,
      errors: [] as string[],
    };

    // Phase 2: Full automated vulnerability checks
    const quickFindings = quickVulnCheck(pageData);

    // Add storage-based findings
    if (storage) {
      const lsKeys = Object.keys(storage.localStorage || {});
      const ssKeys = Object.keys(storage.sessionStorage || {});
      const sensitiveStoragePatterns = /token|session|auth|key|secret|password|jwt|credential|api/i;

      for (const key of [...lsKeys, ...ssKeys]) {
        if (sensitiveStoragePatterns.test(key)) {
          const isLS = lsKeys.includes(key);
          const value = isLS
            ? (storage.localStorage || {})[key]
            : (storage.sessionStorage || {})[key];
          quickFindings.push({
            type: 'sensitive_storage',
            severity: 'Medium',
            title: `Sensitive data in ${isLS ? 'localStorage' : 'sessionStorage'}: ${key}`,
            description: `Key "${key}" with value "${(value || '').substring(0, 50)}..." found in browser storage. XSS can exfiltrate this data.`,
          });
        }
      }

      if (lsKeys.length > 0 || ssKeys.length > 0) {
        quickFindings.push({
          type: 'storage_info',
          severity: 'Info',
          title: `Browser storage: ${lsKeys.length} localStorage + ${ssKeys.length} sessionStorage keys`,
          description: `localStorage keys: ${lsKeys.slice(0, 10).join(', ')}. sessionStorage keys: ${ssKeys.slice(0, 10).join(', ')}.`,
        });
      }
    }

    // Add CSP meta tag finding
    if (cspMeta) {
      if (cspMeta.includes("'unsafe-inline'") || cspMeta.includes("'unsafe-eval'")) {
        quickFindings.push({
          type: 'weak_csp',
          severity: 'Medium',
          title: 'Weak CSP in meta tag',
          description: `CSP delivered via meta tag contains unsafe directives: ${cspMeta.substring(0, 200)}`,
        });
      }
    }

    // Phase 3: Match against Jhaddix attack surface DB
    const matchedTech = matchAttackSurface(allTechnologies);

    // Phase 4: AI analysis with FULL Jhaddix context
    const aiResult = await analyzeUrlContent(
      url,
      headers,
      html,
      pageData.scripts,
      pageData.forms,
      cookies,
      'gpt-4o',
      matchedTech,
      attackSurfaceDb?.common_vulnerability_patterns,
      quickFindings,
      allTechnologies,
      discoveredEndpoints,
    );

    const project = {
      id: generateProjectId(),
      name: hostname + ' — Page Analysis',
      url,
      source: 'extension',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      findings: {
        quick_findings: quickFindings,
        ai_analysis: aiResult.raw_text,
        attack_surface_matches: matchedTech,
        technologies: allTechnologies,
      },
      metadata: {
        analysis_type: 'content',
        forms_count: pageData.forms.length,
        scripts_count: pageData.scripts.length,
        comments_count: pageData.comments.length,
        links_count: pageData.links.length,
        finding_count: quickFindings.length,
        storage_keys: storage ? Object.keys(storage.localStorage || {}).length + Object.keys(storage.sessionStorage || {}).length : 0,
        discovered_endpoints: discoveredEndpoints?.length || 0,
      },
      notes: '',
    };
    saveProject(project);
    latestExtensionProjectId = project.id;
    console.log(`[Server] Saved extension project ${project.id} — ${quickFindings.length} automated findings, ${matchedTech.length} attack surface matches, ${allTechnologies.length} techs`);

    res.json({
      url,
      project_id: project.id,
      quick_findings: quickFindings,
      ai_analysis: aiResult.raw_text,
      attack_surface_matches: matchedTech,
      technologies: allTechnologies,
      analysis_type: 'content',
    });
  } catch (e: any) {
    console.error('[Server] Page analysis error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/screenshot', async (req, res) => {
  const { screenshot, url = '' } = req.body;
  if (!screenshot) return res.status(400).json({ error: "Missing 'screenshot' field" });

  const keyErr = checkApiKey();
  if (keyErr) return res.status(503).json({ error: keyErr });

  try {
    const result = await analyzePageWithVision(screenshot, undefined, url);
    res.json({ ai_analysis: result.raw_text, tokens: result.tokens_estimated });
  } catch (e: any) {
    console.error('[Server] Screenshot error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/knowledge-base', (_req, res) => {
  const category = _req.query.category as string;
  if (category && attackSurfaceDb?.categories?.[category]) {
    return res.json(attackSurfaceDb.categories[category]);
  }
  res.json({
    categories: Object.keys(attackSurfaceDb?.categories || {}),
    default_credential_categories: Object.keys(attackSurfaceDb?.default_credentials || {}),
  });
});

// ─── Projects CRUD ───

app.get('/api/projects', (_req, res) => {
  res.json(listProjects());
});

app.get('/api/projects/:id', (req, res) => {
  const project = loadProject(req.params.id);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  res.json(project);
});

app.delete('/api/projects/:id', (req, res) => {
  if (deleteProject(req.params.id)) {
    res.json({ status: 'deleted' });
  } else {
    res.status(404).json({ error: 'Project not found' });
  }
});

app.patch('/api/projects/:id', (req, res) => {
  const project = loadProject(req.params.id);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  const { name, notes } = req.body;
  if (name !== undefined) project.name = name;
  if (notes !== undefined) project.notes = notes;
  project.updated_at = new Date().toISOString();
  saveProject(project);
  res.json(project);
});

app.post('/api/extension/dismiss', (_req, res) => {
  latestExtensionProjectId = null;
  res.json({ status: 'ok' });
});

app.get('/api/extension/download', (_req, res) => {
  const xpiPath = path.join(__dirname, '..', 'extension', 'hackagent.xpi');
  if (!fs.existsSync(xpiPath)) {
    return res.status(404).json({
      error: 'Extension not built. Run: npm run build:extension',
    });
  }
  res.download(xpiPath, 'hackagent.xpi');
});

app.get('/api/default-creds', (req, res) => {
  const query = ((req.query.q as string) || '').toLowerCase();
  const results: Record<string, any> = {};

  // Search in default_credentials
  for (const [, services] of Object.entries(attackSurfaceDb?.default_credentials || {})) {
    for (const [service, creds] of Object.entries(services as any)) {
      if (service.toLowerCase().includes(query)) {
        results[service] = creds;
      }
    }
  }

  // Also search in categories for tools with default_creds
  for (const [, catData] of Object.entries(attackSurfaceDb?.categories || {})) {
    for (const [toolName, toolData] of Object.entries((catData as any)?.tools || {})) {
      if (toolName.toLowerCase().includes(query) && (toolData as any).default_creds?.length) {
        if (!results[toolName]) {
          results[toolName] = (toolData as any).default_creds;
        }
      }
    }
  }

  res.json(results);
});

// ─── Helper: Build security headers from raw headers (for extension data) ───
function checkSecurityHeadersFromRaw(headers: Record<string, string>): Record<string, any> {
  const checks: Record<string, any> = {};
  const lh: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers || {})) {
    lh[k.toLowerCase()] = v;
  }

  const secHeaders: Record<string, string> = {
    'strict-transport-security': 'hsts',
    'content-security-policy': 'csp',
    'x-frame-options': 'x_frame_options',
    'x-content-type-options': 'x_content_type',
    'x-xss-protection': 'x_xss_protection',
    'referrer-policy': 'referrer_policy',
    'permissions-policy': 'permissions_policy',
  };

  for (const [header, key] of Object.entries(secHeaders)) {
    const value = lh[header] ?? null;
    checks[key] = {
      present: value !== null,
      value,
      severity: value === null ? 'Medium' : 'Info',
    };
  }

  if (!checks['hsts']?.present) checks['hsts'].severity = 'High';
  if (!checks['csp']?.present) checks['csp'].severity = 'High';

  return checks;
}

// ─── Start ───
app.listen(PORT, () => {
  console.log(`[Server] HackAgent v2 backend running on http://localhost:${PORT}`);
  console.log(`[Server] Attack surface DB: ${Object.keys(attackSurfaceDb?.categories || {}).length} categories loaded`);
  console.log(`[Server] Vulnerability patterns: ${attackSurfaceDb?.common_vulnerability_patterns?.owasp_top_10?.length || 0} OWASP checks`);
});

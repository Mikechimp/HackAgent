/**
 * HackAgent — Express Backend Server
 * TypeScript port of web/app.py (Flask → Express)
 * Runs as a child process managed by Electron's BackendManager.
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
import { fetchPage, quickVulnCheck } from './services/page-analyzer';

const app = express();
const PORT = parseInt(process.env.HACKAGENT_PORT || '5175', 10);

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ─── In-memory conversation storage ───
const conversations: Record<string, { role: string; content: string }[]> = {};

// ─── Load attack surface knowledge base ───
let attackSurfaceDb: any = {};
const dataPath = path.join(__dirname, '..', '..', 'data', 'attack_surface.json');
if (fs.existsSync(dataPath)) {
  attackSurfaceDb = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
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

// ─── Routes ───

app.get('/api/status', (_req, res) => {
  res.json({
    status: 'online',
    api_configured: isApiConfigured(),
    version: '1.0.0',
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

app.post('/api/analyze-url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing 'url' field" });

  const keyErr = checkApiKey();
  if (keyErr) return res.status(503).json({ error: keyErr });

  console.log(`[Server] Analyzing URL: ${url}`);

  try {
    const pageData = await fetchPage(url);
    const quickFindings = quickVulnCheck(pageData);
    const aiResult = await analyzeUrlContent(
      url,
      pageData.headers,
      pageData.html,
      pageData.scripts,
      pageData.forms,
      pageData.cookies,
    );

    const matchedTech = matchAttackSurface(pageData.technologies);

    res.json({
      url,
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

app.post('/api/analyze-page', async (req, res) => {
  const { url = 'unknown', html = '', headers = {}, cookies = [], screenshot } = req.body;

  const keyErr = checkApiKey();
  if (keyErr) return res.status(503).json({ error: keyErr });

  try {
    if (screenshot) {
      const result = await analyzePageWithVision(screenshot, html, url);
      return res.json({ url, ai_analysis: result.raw_text, analysis_type: 'vision' });
    }

    const pageData = {
      url, html, headers, cookies,
      scripts: [] as any[], forms: [] as any[], links: [] as string[],
      comments: [] as string[], technologies: [] as any[],
      security_headers: {} as any, status_code: null, errors: [] as string[],
    };

    const quickFindings = quickVulnCheck(pageData);
    const aiResult = await analyzeUrlContent(url, headers, html, [], [], cookies);

    res.json({ url, quick_findings: quickFindings, ai_analysis: aiResult.raw_text, analysis_type: 'content' });
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

app.get('/api/default-creds', (req, res) => {
  const query = ((req.query.q as string) || '').toLowerCase();
  const results: Record<string, any> = {};
  for (const [, services] of Object.entries(attackSurfaceDb?.default_credentials || {})) {
    for (const [service, creds] of Object.entries(services as any)) {
      if (service.toLowerCase().includes(query)) {
        results[service] = creds;
      }
    }
  }
  res.json(results);
});

function matchAttackSurface(technologies: any[]): any[] {
  const matches: any[] = [];
  const categories = attackSurfaceDb?.categories || {};
  const techNames = new Set(technologies.map((t: any) => (t.name || '').toLowerCase()));

  for (const [catName, catData] of Object.entries(categories)) {
    for (const [toolName, toolData] of Object.entries((catData as any)?.tools || {})) {
      const lower = toolName.toLowerCase();
      if (techNames.has(lower) || [...techNames].some(t => t.includes(lower))) {
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
  return matches;
}

// ─── Start ───
app.listen(PORT, () => {
  console.log(`[Server] HackAgent backend running on http://localhost:${PORT}`);
});

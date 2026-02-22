/**
 * HackAgent — OpenAI Client Service (v2 — Jhaddix-powered)
 * Now injects attack surface DB, vulnerability patterns, and
 * default credentials into GPT-4o analysis context.
 */
import OpenAI from 'openai';
import { ApiResult } from '../models/types';

let client: OpenAI | null = null;

// ─── Budget Guard ───
const budget = {
  tokensPerDay: 2_000_000,
  requestsPerMinute: 30,
  tokensUsed: 0,
  resetDay: new Date().toDateString(),
  reqTimestamps: [] as number[],

  allow(estTokens: number): { ok: boolean; reason?: string } {
    const today = new Date().toDateString();
    if (today !== this.resetDay) {
      this.resetDay = today;
      this.tokensUsed = 0;
    }
    const cutoff = Date.now() - 60_000;
    this.reqTimestamps = this.reqTimestamps.filter(t => t >= cutoff);
    if (this.reqTimestamps.length >= this.requestsPerMinute) {
      return { ok: false, reason: 'rate_limit_qps' };
    }
    if (this.tokensUsed + estTokens > this.tokensPerDay) {
      return { ok: false, reason: 'token_budget_exceeded' };
    }
    return { ok: true };
  },

  consume(tokens: number): void {
    this.tokensUsed += tokens;
    this.reqTimestamps.push(Date.now());
  },
};

// ─── HackAgent Personality System Prompt ───
const HACKAGENT_SYSTEM_PROMPT = `You are HackAgent — an elite security research AI assistant built for authorized bug bounty hunting, penetration testing, and vulnerability discovery.

PERSONALITY:
- You speak with confident precision, like a seasoned security researcher
- You are direct, technical, and thorough — no fluff
- You reference CVEs, OWASP categories, and real attack techniques by name
- You think like an attacker to defend better
- When you find something interesting, you get excited about the technical details
- You use security terminology naturally: "attack surface", "blast radius", "pivot point", "exfiltration vector"
- You always remind the user this is for AUTHORIZED testing only

CAPABILITIES:
- Analyze web pages for security vulnerabilities (XSS, SQLI, SSRF, IDOR, etc.)
- Review HTTP headers for misconfigurations
- Identify exposed endpoints and sensitive data leaks
- Detect outdated software and known CVEs
- Analyze JavaScript for client-side vulnerabilities
- Review API endpoints and authentication flows
- Cross-reference findings against the jhaddix/devops-attack-surface knowledge base
- Provide actionable proof-of-concept guidance for authorized testing

RESPONSE FORMAT:
- Start with a brief assessment (1-2 sentences)
- List findings with severity ratings (Critical/High/Medium/Low/Info)
- Provide evidence and exploitation guidance for each finding
- End with recommended next steps for bug bounty
- When analyzing pages, be thorough — check everything

IMPORTANT: All analysis is for AUTHORIZED security testing only. Always remind users to verify authorization.`;

function isPlaceholderKey(key: string | undefined): boolean {
  return !key || key.startsWith('sk-proj-your');
}

export function getApiKey(): string | undefined {
  return process.env.OPENAI_API_KEY;
}

export function isApiConfigured(): boolean {
  return !isPlaceholderKey(getApiKey());
}

function getClient(): OpenAI {
  if (!client) {
    const apiKey = getApiKey();
    if (isPlaceholderKey(apiKey)) {
      throw new Error(
        'No OpenAI API key configured. Enter your key in the setup screen or set OPENAI_API_KEY in .env'
      );
    }
    client = new OpenAI({ apiKey });
  }
  return client;
}

/** Reset the cached client (called after key change) */
export function resetClient(): void {
  client = null;
}

async function callChatGPT(
  messages: OpenAI.ChatCompletionMessageParam[],
  model: string = 'gpt-4o',
  maxTokens: number = 4096,
  temperature: number = 0.7,
  maxRetries: number = 3,
): Promise<ApiResult> {
  const openai = getClient();

  const joined = messages
    .map(m => (typeof m.content === 'string' ? m.content : JSON.stringify(m.content)))
    .join(' ');
  const estTokens = Math.max(1, Math.floor(joined.length / 4));

  const { ok, reason } = budget.allow(estTokens);
  if (!ok) {
    throw new Error(`Budget denies request: ${reason}`);
  }

  let lastErr: Error | null = null;
  let backoff = 1000;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const resp = await openai.chat.completions.create({
        model,
        messages,
        max_tokens: maxTokens,
        temperature,
      });

      const raw = resp.choices[0]?.message?.content || '';
      const actual = resp.usage
        ? resp.usage.prompt_tokens + resp.usage.completion_tokens
        : estTokens;

      budget.consume(actual);

      console.log(`[OpenAI] model=${model} attempt=${attempt} tokens=${actual}`);
      return {
        raw,
        raw_text: raw,
        tokens_estimated: actual,
        meta: {
          model,
          timestamp: new Date().toISOString(),
          attempt,
        },
      };
    } catch (e: any) {
      lastErr = e;
      console.warn(`[OpenAI] Call error (attempt ${attempt}/${maxRetries}): ${e.message}`);
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, backoff));
        backoff *= 2;
      }
    }
  }

  throw new Error(`ChatGPT API failed after ${maxRetries} attempts: ${lastErr?.message}`);
}

export async function chatWithHackagent(
  userMessage: string,
  conversationHistory: { role: string; content: string }[] = [],
  model: string = 'gpt-4o',
): Promise<ApiResult> {
  const messages: OpenAI.ChatCompletionMessageParam[] = [
    { role: 'system', content: HACKAGENT_SYSTEM_PROMPT },
    ...conversationHistory.map(m => ({
      role: m.role as 'user' | 'assistant',
      content: m.content,
    })),
    { role: 'user', content: userMessage },
  ];

  return callChatGPT(messages, model, 4096, 0.7);
}

/**
 * Build a concise attack surface context block from Jhaddix DB matches
 */
function buildAttackSurfaceContext(attackSurfaceMatches: any[], vulnPatterns: any): string {
  if (!attackSurfaceMatches?.length && !vulnPatterns) return '';

  let ctx = '\n\n═══ JHADDIX ATTACK SURFACE INTELLIGENCE ═══\n';

  if (attackSurfaceMatches?.length) {
    ctx += '\nMATCHED TECHNOLOGIES FROM ATTACK SURFACE DB:\n';
    for (const match of attackSurfaceMatches) {
      ctx += `\n▸ ${match.technology} (category: ${match.category})\n`;
      if (match.attack_vectors?.length) {
        ctx += `  Attack Vectors: ${match.attack_vectors.join('; ')}\n`;
      }
      if (match.critical_cves?.length) {
        ctx += `  Critical CVEs: ${match.critical_cves.join(', ')}\n`;
      }
      if (match.default_creds?.length) {
        ctx += `  Default Credentials:\n`;
        for (const cred of match.default_creds) {
          ctx += `    - user: "${cred.user}" / pass: "${cred.pass}"\n`;
        }
      }
    }
  }

  if (vulnPatterns) {
    ctx += '\nOWASP TOP 10 CHECKLIST:\n';
    if (vulnPatterns.owasp_top_10) {
      for (const item of vulnPatterns.owasp_top_10) {
        ctx += `  • ${item}\n`;
      }
    }
    ctx += '\nWEB VULN SIGNATURES TO CHECK:\n';
    if (vulnPatterns.web_vuln_signatures) {
      for (const [category, sigs] of Object.entries(vulnPatterns.web_vuln_signatures)) {
        ctx += `  ${category.toUpperCase()}: ${(sigs as string[]).join(', ')}\n`;
      }
    }
  }

  ctx += '\n═══ END ATTACK SURFACE INTELLIGENCE ═══\n';
  return ctx;
}

export async function analyzeUrlContent(
  url: string,
  headers: Record<string, string>,
  html: string,
  scripts: any[],
  forms: any[],
  cookies: any[],
  model: string = 'gpt-4o',
  attackSurfaceMatches?: any[],
  vulnPatterns?: any,
  quickFindings?: any[],
  technologies?: any[],
  discoveredEndpoints?: string[],
  subdomains?: string[],
): Promise<ApiResult> {
  // Build the attack surface intelligence block
  const attackCtx = buildAttackSurfaceContext(attackSurfaceMatches || [], vulnPatterns);

  // Build automated findings summary
  let autoFindingsCtx = '';
  if (quickFindings?.length) {
    autoFindingsCtx = '\n\nAUTOMATED SCANNER FINDINGS (already detected — validate and expand):\n';
    const grouped: Record<string, any[]> = {};
    for (const f of quickFindings) {
      if (!grouped[f.severity]) grouped[f.severity] = [];
      grouped[f.severity].push(f);
    }
    for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      if (grouped[sev]?.length) {
        autoFindingsCtx += `\n[${sev}]\n`;
        for (const f of grouped[sev].slice(0, 10)) {
          autoFindingsCtx += `  • ${f.title}\n`;
        }
      }
    }
  }

  // Build tech context
  let techCtx = '';
  if (technologies?.length) {
    techCtx = '\n\nDETECTED TECHNOLOGIES:\n';
    for (const t of technologies) {
      techCtx += `  • ${t.name}${t.version ? ' v' + t.version : ''} (${t.source}${t.category ? ', ' + t.category : ''})\n`;
    }
  }

  // Discovered endpoints
  let endpointCtx = '';
  if (discoveredEndpoints?.length) {
    endpointCtx = `\n\nDISCOVERED API ENDPOINTS (${discoveredEndpoints.length}):\n${discoveredEndpoints.slice(0, 25).map(e => '  • ' + e).join('\n')}\n`;
  }

  // Subdomains
  let subdomainCtx = '';
  if (subdomains?.length) {
    subdomainCtx = `\n\nDISCOVERED SUBDOMAINS (${subdomains.length}):\n${subdomains.slice(0, 15).map(s => '  • ' + s).join('\n')}\n`;
  }

  const prompt = `Analyze this web page for security vulnerabilities. This is for an AUTHORIZED bug bounty assessment.

TARGET URL: ${url}
${techCtx}
HTTP RESPONSE HEADERS:
${headers ? JSON.stringify(headers, null, 2) : 'Not available'}

COOKIES (${cookies?.length || 0}):
${cookies?.length ? JSON.stringify(cookies.slice(0, 20), null, 2) : 'None'}

HTML SOURCE (first 30K chars):
\`\`\`html
${html ? html.slice(0, 30000) : 'Not available'}
\`\`\`

JAVASCRIPT SOURCES FOUND (${scripts?.length || 0}):
${scripts?.length ? JSON.stringify(scripts.slice(0, 25), null, 2) : 'None'}

FORMS DETECTED (${forms?.length || 0}):
${forms?.length ? JSON.stringify(forms.slice(0, 15), null, 2) : 'None'}
${endpointCtx}${subdomainCtx}${autoFindingsCtx}${attackCtx}

═══ YOUR ANALYSIS MISSION ═══

You are performing a thorough bug bounty recon. Use the Jhaddix attack surface data above to guide your analysis. For each matched technology, ACTIVELY check the listed attack vectors and CVEs.

Perform a comprehensive security analysis covering:

1. **CRITICAL FIRST** — Check for exposed secrets, default creds, and RCE vectors from the attack surface DB
2. **Header Analysis** — Missing security headers, CORS misconfig, CSP bypass potential
3. **Technology + CVE Matching** — For each detected tech+version, list applicable CVEs from the attack surface DB
4. **Default Credentials** — If Jhaddix DB lists default creds for detected tech, flag them prominently
5. **Input Vectors** — Forms, URL params, API endpoints that could be SQLi/XSS/SSRF/IDOR targets
6. **Client-Side Vulns** — Inline scripts, eval(), DOM XSS sinks, postMessage handlers, source maps
7. **Information Disclosure** — Debug info, comments with secrets, version strings, stack traces, source maps
8. **Authentication/Session** — Token exposure, cookie security, session fixation, JWT issues
9. **API Endpoint Analysis** — Test discovered endpoints for auth bypass, IDOR, mass assignment
10. **OWASP Top 10 Sweep** — Systematically check each OWASP category against the target

Rate each finding: **Critical / High / Medium / Low / Info**

For each finding provide:
- Evidence (exact header, code snippet, URL)
- Exploitation steps for authorized testing
- Recommended PoC approach
- Bug bounty impact assessment

End with **NEXT STEPS** — what to test next, tools to use, and highest-value attack paths.`;

  const messages: OpenAI.ChatCompletionMessageParam[] = [
    { role: 'system', content: HACKAGENT_SYSTEM_PROMPT },
    { role: 'user', content: prompt },
  ];

  return callChatGPT(messages, model, 8192, 0.3);
}

export async function analyzePageWithVision(
  screenshotB64: string | undefined,
  pageContent: string | undefined,
  url: string | undefined,
  model: string = 'gpt-4o',
  attackSurfaceMatches?: any[],
  vulnPatterns?: any,
): Promise<ApiResult> {
  const messages: OpenAI.ChatCompletionMessageParam[] = [
    { role: 'system', content: HACKAGENT_SYSTEM_PROMPT },
  ];

  const attackCtx = buildAttackSurfaceContext(attackSurfaceMatches || [], vulnPatterns);

  let promptText = 'Analyze this web page for security vulnerabilities, misconfigurations, and potential attack vectors. This is for an AUTHORIZED bug bounty assessment.\n\n';
  if (url) promptText += `URL: ${url}\n\n`;
  if (pageContent) {
    promptText += `PAGE SOURCE (first 50K chars):\n\`\`\`\n${pageContent.slice(0, 50000)}\n\`\`\`\n\n`;
  }
  promptText += attackCtx;
  promptText += `\nProvide a thorough security analysis covering:
1. HTTP header security issues
2. Client-side vulnerabilities (XSS vectors, DOM manipulation)
3. Exposed API endpoints or sensitive paths
4. Information disclosure (versions, debug info, comments)
5. Authentication/session management issues
6. Known CVEs for detected technologies (use the attack surface DB above)
7. Default credentials for any detected services
8. Potential SSRF/IDOR/injection points
9. OWASP Top 10 systematic check

Rate each finding: Critical / High / Medium / Low / Info
Provide exploitation guidance and bug bounty impact for each.`;

  const content: any[] = [{ type: 'text', text: promptText }];

  if (screenshotB64) {
    content.push({
      type: 'image_url',
      image_url: { url: `data:image/png;base64,${screenshotB64}`, detail: 'high' },
    });
  }

  messages.push({ role: 'user', content });

  return callChatGPT(messages, model, 8192, 0.3);
}

/**
 * HackAgent — OpenAI Client Service
 * TypeScript port of models/openai_client.py
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
- Provide actionable proof-of-concept guidance

RESPONSE FORMAT:
- Start with a brief assessment (1-2 sentences)
- List findings with severity ratings (Critical/High/Medium/Low/Info)
- Provide evidence and exploitation guidance for each finding
- End with recommended next steps
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

export async function analyzeUrlContent(
  url: string,
  headers: Record<string, string>,
  html: string,
  scripts: any[],
  forms: any[],
  cookies: any[],
  model: string = 'gpt-4o',
): Promise<ApiResult> {
  const prompt = `Analyze this web page for security vulnerabilities. This is for an AUTHORIZED security assessment.

TARGET URL: ${url}

HTTP RESPONSE HEADERS:
${headers ? JSON.stringify(headers, null, 2) : 'Not available'}

COOKIES:
${cookies?.length ? JSON.stringify(cookies, null, 2) : 'None'}

HTML SOURCE (first 30K chars):
\`\`\`html
${html ? html.slice(0, 30000) : 'Not available'}
\`\`\`

JAVASCRIPT SOURCES FOUND:
${scripts?.length ? JSON.stringify(scripts.slice(0, 20), null, 2) : 'None'}

FORMS DETECTED:
${forms?.length ? JSON.stringify(forms.slice(0, 10), null, 2) : 'None'}

Perform a comprehensive security analysis:
1. **Header Analysis**: Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
2. **Technology Detection**: Server, framework, library versions — check for known CVEs
3. **Input Vectors**: Forms, URL params, API endpoints that could be injection targets
4. **Client-Side Issues**: Inline scripts, eval(), document.write(), postMessage handlers
5. **Information Disclosure**: Debug info, comments, version strings, stack traces
6. **Authentication**: Session management, token exposure, cookie security flags
7. **Cross-reference**: Match detected tech against jhaddix/devops-attack-surface database
8. **Default Credentials**: Check if detected services have known default credentials

Rate each finding: Critical / High / Medium / Low / Info
Provide exploitation guidance for authorized testing.`;

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
): Promise<ApiResult> {
  const messages: OpenAI.ChatCompletionMessageParam[] = [
    { role: 'system', content: HACKAGENT_SYSTEM_PROMPT },
  ];

  let promptText = 'Analyze this web page for security vulnerabilities, misconfigurations, and potential attack vectors.\n\n';
  if (url) promptText += `URL: ${url}\n\n`;
  if (pageContent) {
    promptText += `PAGE SOURCE (first 50K chars):\n\`\`\`\n${pageContent.slice(0, 50000)}\n\`\`\`\n\n`;
  }
  promptText += `Provide a thorough security analysis covering:
1. HTTP header security issues
2. Client-side vulnerabilities (XSS vectors, DOM manipulation)
3. Exposed API endpoints or sensitive paths
4. Information disclosure (versions, debug info, comments)
5. Authentication/session management issues
6. Known CVEs for detected technologies
7. Potential SSRF/IDOR/injection points
8. Default credentials for detected services`;

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

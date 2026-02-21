/**
 * HackAgent — Page Analyzer Service
 * TypeScript port of core/page_analyzer.py
 * Fetches URLs, extracts security-relevant data.
 */
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { PageData, Finding } from '../models/types';

export async function fetchPage(targetUrl: string, timeout: number = 15000): Promise<PageData> {
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const result: PageData = {
    url: targetUrl,
    status_code: null,
    headers: {},
    cookies: [],
    html: '',
    scripts: [],
    forms: [],
    links: [],
    comments: [],
    technologies: [],
    security_headers: {},
    errors: [],
  };

  try {
    const { statusCode, headers, body } = await httpGet(targetUrl, timeout);
    result.status_code = statusCode;
    result.headers = headers;
    result.html = body.slice(0, 100000);

    result.security_headers = checkSecurityHeaders(headers);
    result.scripts = extractScripts(body, targetUrl);
    result.forms = extractForms(body, targetUrl);
    result.links = extractLinks(body, targetUrl);
    result.comments = extractComments(body);
    result.technologies = detectTechnologies(headers, body);
  } catch (e: any) {
    result.errors.push(`Error: ${e.message}`);
  }

  return result;
}

function httpGet(
  url: string,
  timeout: number,
): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;

    const req = mod.get(
      url,
      {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        timeout,
      },
      (res) => {
        // Follow redirects
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, url).toString();
          httpGet(redirectUrl, timeout).then(resolve).catch(reject);
          return;
        }

        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (body.length < 200000) body += chunk;
        });
        res.on('end', () => {
          const flatHeaders: Record<string, string> = {};
          for (const [key, val] of Object.entries(res.headers)) {
            flatHeaders[key] = Array.isArray(val) ? val.join(', ') : val || '';
          }
          resolve({
            statusCode: res.statusCode || 0,
            headers: flatHeaders,
            body,
          });
        });
      },
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout after ${timeout}ms`));
    });
  });
}

function checkSecurityHeaders(headers: Record<string, string>): Record<string, any> {
  const checks: Record<string, any> = {};
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  const securityHeaders: Record<string, string> = {
    'strict-transport-security': 'hsts',
    'content-security-policy': 'csp',
    'x-frame-options': 'x_frame_options',
    'x-content-type-options': 'x_content_type',
    'x-xss-protection': 'x_xss_protection',
    'referrer-policy': 'referrer_policy',
    'permissions-policy': 'permissions_policy',
  };

  for (const [header, key] of Object.entries(securityHeaders)) {
    const value = lowerHeaders[header] ?? null;
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

function extractScripts(html: string, baseUrl: string): any[] {
  const scripts: any[] = [];
  const srcRe = /<script[^>]+src=["']([^"']+)["']/gi;
  let match;
  while ((match = srcRe.exec(html)) !== null) {
    try {
      scripts.push({ type: 'external', src: new URL(match[1], baseUrl).toString() });
    } catch {
      scripts.push({ type: 'external', src: match[1] });
    }
  }

  const inlineRe = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  while ((match = inlineRe.exec(html)) !== null) {
    const content = match[1].trim();
    if (content) {
      scripts.push({ type: 'inline', preview: content.slice(0, 500), length: content.length });
    }
  }

  return scripts.slice(0, 30);
}

function extractForms(html: string, baseUrl: string): any[] {
  const forms: any[] = [];
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formRe.exec(html)) !== null) {
    const formTag = match[0];
    const formBody = match[1];
    const actionMatch = /action=["']([^"']*)["']/i.exec(formTag);
    const methodMatch = /method=["']([^"']*)["']/i.exec(formTag);

    let action = baseUrl;
    try {
      action = actionMatch ? new URL(actionMatch[1], baseUrl).toString() : baseUrl;
    } catch { /* keep baseUrl */ }

    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
    const inputs: { name: string; type: string }[] = [];

    const inputRe = /<(?:input|textarea|select)[^>]*(?:name=["']([^"']*)["'])?[^>]*(?:type=["']([^"']*)["'])?/gi;
    let inp;
    while ((inp = inputRe.exec(formBody)) !== null) {
      inputs.push({ name: inp[1] || 'unnamed', type: inp[2] || 'text' });
    }

    forms.push({ action, method, inputs });
  }

  return forms.slice(0, 10);
}

function extractLinks(html: string, baseUrl: string): string[] {
  const links: string[] = [];
  const seen = new Set<string>();
  const re = /<a[^>]+href=["']([^"'#]+)["']/gi;
  let match;
  while ((match = re.exec(html)) !== null) {
    try {
      const full = new URL(match[1], baseUrl).toString();
      if (!seen.has(full)) {
        seen.add(full);
        links.push(full);
      }
    } catch { /* skip malformed */ }
  }
  return links.slice(0, 50);
}

function extractComments(html: string): string[] {
  const comments: string[] = [];
  const re = /<!--([\s\S]*?)-->/g;
  let match;
  while ((match = re.exec(html)) !== null) {
    const c = match[1].trim();
    if (c.length > 5) comments.push(c.slice(0, 500));
  }
  return comments.slice(0, 20);
}

function detectTechnologies(headers: Record<string, string>, html: string): any[] {
  const techs: any[] = [];
  const lh: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lh[k.toLowerCase()] = v;
  }

  if (lh['server']) techs.push({ name: 'Server', value: lh['server'], source: 'header' });
  if (lh['x-powered-by']) techs.push({ name: 'X-Powered-By', value: lh['x-powered-by'], source: 'header' });

  const patterns: Record<string, RegExp[]> = {
    WordPress: [/wp-content\//i, /wp-includes\//i],
    React: [/react\./i, /__NEXT_DATA__/i, /_next\//i],
    Angular: [/ng-app/i, /angular\./i],
    'Vue.js': [/vue\./i, /v-bind/i, /__vue__/i],
    jQuery: [/jquery[.\-]/i],
    PHP: [/\.php/i, /PHPSESSID/i],
    'ASP.NET': [/__VIEWSTATE/i, /\.aspx/i],
    Django: [/csrfmiddlewaretoken/i],
    Jenkins: [/jenkins/i],
    Cloudflare: [/cloudflare/i, /cf-ray/i],
  };

  const htmlLower = html.toLowerCase();
  const headersStr = JSON.stringify(headers).toLowerCase();

  for (const [tech, regexes] of Object.entries(patterns)) {
    for (const re of regexes) {
      if (re.test(htmlLower) || re.test(headersStr)) {
        techs.push({ name: tech, source: 'fingerprint' });
        break;
      }
    }
  }

  return techs;
}

export function quickVulnCheck(pageData: PageData): Finding[] {
  const findings: Finding[] = [];

  // Check security headers
  for (const [key, info] of Object.entries(pageData.security_headers)) {
    if (!info.present) {
      findings.push({
        type: 'missing_header',
        severity: info.severity || 'Medium',
        title: `Missing ${key.toUpperCase().replace(/_/g, '-')} header`,
        description: 'The security header is not set.',
      });
    }
  }

  // Check cookies
  for (const cookie of pageData.cookies) {
    if (!cookie.secure) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'Medium',
        title: `Cookie '${cookie.name}' missing Secure flag`,
        description: 'Cookie transmitted over unencrypted connections.',
      });
    }
    if (!cookie.httponly) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'Medium',
        title: `Cookie '${cookie.name}' missing HttpOnly flag`,
        description: 'Cookie accessible to JavaScript (XSS risk).',
      });
    }
  }

  // Check dangerous JS patterns
  for (const script of pageData.scripts) {
    const preview = script.preview || '';
    const dangerous = ['eval(', 'document.write(', 'innerHTML', '.innerHTML='];
    for (const pattern of dangerous) {
      if (preview.includes(pattern)) {
        findings.push({
          type: 'dangerous_js',
          severity: 'Medium',
          title: `Potentially dangerous JS: ${pattern}`,
          description: `Found '${pattern}' in inline script.`,
        });
      }
    }
  }

  return findings;
}

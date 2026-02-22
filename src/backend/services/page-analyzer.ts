/**
 * HackAgent — Page Analyzer Service (v2 — Bug Bounty Grade)
 * Comprehensive passive reconnaissance + vulnerability detection engine.
 * Powered by Jhaddix attack surface methodology.
 */
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { PageData, Finding } from '../models/types';

// ─── Secret Patterns (regex + label) ───
const SECRET_PATTERNS: { name: string; re: RegExp; severity: string }[] = [
  { name: 'AWS Access Key', re: /AKIA[0-9A-Z]{16}/g, severity: 'Critical' },
  { name: 'AWS Secret Key', re: /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'Critical' },
  { name: 'Google API Key', re: /AIza[0-9A-Za-z_-]{35}/g, severity: 'High' },
  { name: 'Google OAuth Token', re: /ya29\.[0-9A-Za-z_-]+/g, severity: 'High' },
  { name: 'GitHub Token (classic)', re: /ghp_[0-9A-Za-z]{36}/g, severity: 'Critical' },
  { name: 'GitHub Token (fine-grained)', re: /github_pat_[0-9A-Za-z_]{22,}/g, severity: 'Critical' },
  { name: 'GitHub OAuth', re: /gho_[0-9A-Za-z]{36}/g, severity: 'Critical' },
  { name: 'Slack Token', re: /xox[bpoas]-[0-9A-Za-z-]{10,}/g, severity: 'Critical' },
  { name: 'Slack Webhook', re: /hooks\.slack\.com\/services\/T[0-9A-Za-z]+\/B[0-9A-Za-z]+\/[0-9A-Za-z]+/g, severity: 'High' },
  { name: 'Stripe Secret Key', re: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'Critical' },
  { name: 'Stripe Publishable Key', re: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'Medium' },
  { name: 'Twilio API Key', re: /SK[0-9a-fA-F]{32}/g, severity: 'High' },
  { name: 'Mailgun API Key', re: /key-[0-9a-zA-Z]{32}/g, severity: 'High' },
  { name: 'SendGrid API Key', re: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, severity: 'High' },
  { name: 'Firebase URL', re: /[a-z0-9-]+\.firebaseio\.com/g, severity: 'Medium' },
  { name: 'Firebase API Key', re: /AIza[0-9A-Za-z_-]{35}/g, severity: 'Medium' },
  { name: 'Heroku API Key', re: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, severity: 'Medium' },
  { name: 'JWT Token', re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'High' },
  { name: 'Private Key', re: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'Critical' },
  { name: 'Basic Auth in URL', re: /https?:\/\/[^:]+:[^@]+@/g, severity: 'Critical' },
  { name: 'Bearer Token', re: /[Bb]earer\s+[A-Za-z0-9_-]{20,}/g, severity: 'High' },
  { name: 'Authorization Header', re: /[Aa]uthorization['":\s]+(?:Basic|Bearer|Token)\s+[A-Za-z0-9+/=_-]{10,}/g, severity: 'High' },
  { name: 'Generic API Key', re: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_-]{16,})['"]?/gi, severity: 'High' },
  { name: 'Generic Secret', re: /(?:secret|password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]?/gi, severity: 'High' },
  { name: 'Database Connection String', re: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"<>]+/gi, severity: 'Critical' },
  { name: 'S3 Bucket URL', re: /(?:https?:\/\/)?[a-z0-9.-]+\.s3[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d\.amazonaws\.com/gi, severity: 'Medium' },
  { name: 'S3 Bucket Path', re: /s3:\/\/[a-z0-9.-]+/gi, severity: 'Medium' },
  { name: 'Internal IP Address', re: /(?:^|[^0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)/g, severity: 'Medium' },
];

// ─── Sensitive Paths ───
const SENSITIVE_PATHS = [
  { path: '/.git/', name: 'Exposed .git directory', severity: 'Critical' },
  { path: '/.git/config', name: 'Git config exposed', severity: 'Critical' },
  { path: '/.env', name: 'Environment file exposed', severity: 'Critical' },
  { path: '/.svn/', name: 'SVN directory exposed', severity: 'High' },
  { path: '/.DS_Store', name: 'DS_Store file exposed', severity: 'Medium' },
  { path: '/wp-admin/', name: 'WordPress admin panel', severity: 'Medium' },
  { path: '/wp-login.php', name: 'WordPress login page', severity: 'Medium' },
  { path: '/administrator/', name: 'Joomla admin panel', severity: 'Medium' },
  { path: '/phpmyadmin/', name: 'phpMyAdmin exposed', severity: 'High' },
  { path: '/adminer', name: 'Adminer DB tool exposed', severity: 'High' },
  { path: '/server-status', name: 'Apache server-status', severity: 'High' },
  { path: '/server-info', name: 'Apache server-info', severity: 'High' },
  { path: '/elmah.axd', name: 'ELMAH error log exposed', severity: 'High' },
  { path: '/trace.axd', name: 'ASP.NET trace exposed', severity: 'High' },
  { path: '/debug/', name: 'Debug endpoint exposed', severity: 'High' },
  { path: '/console', name: 'Console endpoint (Werkzeug/Rails)', severity: 'Critical' },
  { path: '/_debug', name: 'Debug panel exposed', severity: 'High' },
  { path: '/api/swagger', name: 'Swagger API docs exposed', severity: 'Medium' },
  { path: '/swagger-ui', name: 'Swagger UI exposed', severity: 'Medium' },
  { path: '/api-docs', name: 'API documentation exposed', severity: 'Medium' },
  { path: '/graphql', name: 'GraphQL endpoint', severity: 'Medium' },
  { path: '/graphiql', name: 'GraphiQL IDE exposed', severity: 'High' },
  { path: '/actuator', name: 'Spring Boot Actuator', severity: 'High' },
  { path: '/actuator/env', name: 'Spring Actuator env', severity: 'Critical' },
  { path: '/metrics', name: 'Metrics endpoint', severity: 'Medium' },
  { path: '/health', name: 'Health check endpoint', severity: 'Info' },
  { path: '/info', name: 'Info endpoint', severity: 'Medium' },
  { path: '/jenkins/', name: 'Jenkins dashboard', severity: 'High' },
  { path: '/manager/html', name: 'Tomcat Manager', severity: 'Critical' },
  { path: '/jmx-console/', name: 'JBoss JMX Console', severity: 'Critical' },
  { path: '/web-console/', name: 'JBoss Web Console', severity: 'Critical' },
  { path: '/solr/', name: 'Apache Solr exposed', severity: 'High' },
  { path: '/_cat/', name: 'Elasticsearch _cat API', severity: 'High' },
  { path: '/kibana/', name: 'Kibana dashboard', severity: 'High' },
  { path: '/phpinfo', name: 'PHP info page', severity: 'High' },
  { path: '/robots.txt', name: 'robots.txt file', severity: 'Info' },
  { path: '/sitemap.xml', name: 'Sitemap XML', severity: 'Info' },
  { path: '/crossdomain.xml', name: 'Flash crossdomain policy', severity: 'Medium' },
  { path: '/clientaccesspolicy.xml', name: 'Silverlight access policy', severity: 'Medium' },
  { path: '/backup', name: 'Backup directory', severity: 'High' },
  { path: '/old/', name: 'Old directory exposed', severity: 'Medium' },
  { path: '/test/', name: 'Test directory exposed', severity: 'Medium' },
  { path: '/temp/', name: 'Temp directory exposed', severity: 'Medium' },
  { path: '/.htaccess', name: 'htaccess file exposed', severity: 'High' },
  { path: '/.htpasswd', name: 'htpasswd file exposed', severity: 'Critical' },
  { path: '/config.', name: 'Config file exposed', severity: 'High' },
  { path: '/web.config', name: 'ASP.NET web.config', severity: 'High' },
  { path: '/wp-config.php', name: 'WordPress config', severity: 'Critical' },
  { path: '/composer.json', name: 'Composer manifest', severity: 'Medium' },
  { path: '/package.json', name: 'NPM package manifest', severity: 'Medium' },
  { path: '/Dockerfile', name: 'Dockerfile exposed', severity: 'Medium' },
  { path: '/docker-compose', name: 'Docker Compose file', severity: 'Medium' },
  { path: '/.dockerenv', name: 'Docker environment marker', severity: 'Medium' },
  { path: '/terraform.tfstate', name: 'Terraform state file', severity: 'Critical' },
];

// ─── Open Redirect Patterns ───
const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'redirectUrl', 'return', 'returnTo',
  'return_to', 'returnUrl', 'return_url', 'next', 'url', 'target', 'rurl', 'dest',
  'destination', 'redir', 'redirect_to', 'out', 'view', 'to', 'ref', 'continue',
  'go', 'goto', 'link', 'forward', 'callback', 'callback_url',
];

// ─── Expanded Technology Fingerprints ───
const TECH_FINGERPRINTS: { name: string; patterns: RegExp[]; category: string; versionRe?: RegExp }[] = [
  // CMS
  { name: 'WordPress', patterns: [/wp-content\//i, /wp-includes\//i, /wp-json\//i], category: 'cms', versionRe: /content="WordPress\s+([\d.]+)"/i },
  { name: 'Joomla', patterns: [/\/media\/jui\//i, /\/administrator\//i, /com_content/i], category: 'cms', versionRe: /joomla!\s*([\d.]+)/i },
  { name: 'Drupal', patterns: [/\/sites\/default\//i, /Drupal\.settings/i, /drupal\.js/i], category: 'cms', versionRe: /Drupal\s+([\d.]+)/i },
  { name: 'Magento', patterns: [/\/skin\/frontend\//i, /mage\/cookies/i, /Mage\.Cookies/i], category: 'cms' },
  { name: 'Shopify', patterns: [/cdn\.shopify\.com/i, /myshopify\.com/i], category: 'cms' },
  { name: 'Squarespace', patterns: [/squarespace\.com/i, /sqsp/i], category: 'cms' },
  { name: 'Wix', patterns: [/wix\.com/i, /wixsite\.com/i, /parastorage\.com/i], category: 'cms' },
  { name: 'Ghost', patterns: [/ghost\//i, /ghost-url/i], category: 'cms' },
  { name: 'Hugo', patterns: [/powered by Hugo/i], category: 'cms' },

  // JS Frameworks
  { name: 'React', patterns: [/react\./i, /__NEXT_DATA__/i, /_next\//i, /react-dom/i, /data-reactroot/i], category: 'framework', versionRe: /react[.-]v?([\d.]+)/i },
  { name: 'Next.js', patterns: [/__NEXT_DATA__/i, /_next\/static/i, /next\/dist/i], category: 'framework' },
  { name: 'Angular', patterns: [/ng-app/i, /angular\./i, /ng-version/i, /\[\(ngModel\)\]/i], category: 'framework', versionRe: /ng-version="([\d.]+)"/i },
  { name: 'Vue.js', patterns: [/vue\./i, /v-bind/i, /__vue__/i, /vue-router/i, /v-cloak/i], category: 'framework', versionRe: /vue(?:\.min)?\.js\/([\d.]+)/i },
  { name: 'Nuxt.js', patterns: [/__nuxt/i, /_nuxt\//i, /nuxtjs/i], category: 'framework' },
  { name: 'Svelte', patterns: [/svelte/i, /__svelte/i], category: 'framework' },
  { name: 'Ember.js', patterns: [/ember\./i, /ember-cli/i, /data-ember/i], category: 'framework' },
  { name: 'Backbone.js', patterns: [/backbone\./i, /Backbone\.Model/i], category: 'framework' },

  // JS Libraries
  { name: 'jQuery', patterns: [/jquery[.\-]/i, /jquery\.min/i], category: 'library', versionRe: /jquery[.-]v?([\d.]+)/i },
  { name: 'Lodash', patterns: [/lodash/i, /_\.VERSION/i], category: 'library' },
  { name: 'Bootstrap', patterns: [/bootstrap\./i, /bootstrap\.min/i], category: 'library', versionRe: /bootstrap[.-]v?([\d.]+)/i },
  { name: 'Tailwind CSS', patterns: [/tailwindcss/i], category: 'library' },
  { name: 'Moment.js', patterns: [/moment\.min/i, /moment\.js/i], category: 'library' },
  { name: 'Axios', patterns: [/axios\.min/i, /axios/i], category: 'library' },
  { name: 'Socket.io', patterns: [/socket\.io/i], category: 'library' },
  { name: 'D3.js', patterns: [/d3\.min/i, /d3\.js/i], category: 'library' },

  // Server-side
  { name: 'PHP', patterns: [/\.php/i, /PHPSESSID/i, /X-Powered-By:\s*PHP/i], category: 'language', versionRe: /PHP\/([\d.]+)/i },
  { name: 'ASP.NET', patterns: [/__VIEWSTATE/i, /\.aspx/i, /X-AspNet-Version/i, /ASP\.NET/i], category: 'language', versionRe: /X-AspNet-Version:\s*([\d.]+)/i },
  { name: 'Java', patterns: [/\.jsp/i, /jsessionid/i, /X-Powered-By:\s*JSP/i], category: 'language' },
  { name: 'Python', patterns: [/wsgiref/i, /X-Powered-By:\s*Python/i], category: 'language' },
  { name: 'Ruby on Rails', patterns: [/X-Powered-By:\s*Phusion/i, /_rails/i, /csrf-token/i, /authenticity_token/i], category: 'framework' },
  { name: 'Django', patterns: [/csrfmiddlewaretoken/i, /django/i, /__admin__/i], category: 'framework' },
  { name: 'Flask', patterns: [/werkzeug/i], category: 'framework' },
  { name: 'Express.js', patterns: [/X-Powered-By:\s*Express/i], category: 'framework' },
  { name: 'Laravel', patterns: [/laravel/i, /laravel_session/i, /XSRF-TOKEN/i], category: 'framework' },
  { name: 'Spring', patterns: [/spring/i, /jsessionid/i], category: 'framework' },

  // DevOps / Infrastructure (Jhaddix targets)
  { name: 'Jenkins', patterns: [/jenkins/i, /hudson/i, /X-Jenkins/i], category: 'devops', versionRe: /Jenkins\s*ver[.:]?\s*([\d.]+)/i },
  { name: 'GitLab', patterns: [/gitlab/i, /gl-/i], category: 'devops', versionRe: /gitlab[- ](?:ce|ee)[- ]([\d.]+)/i },
  { name: 'Jira', patterns: [/jira/i, /atlassian/i], category: 'devops', versionRe: /jira[- ]v?([\d.]+)/i },
  { name: 'Confluence', patterns: [/confluence/i], category: 'devops', versionRe: /confluence[- ]v?([\d.]+)/i },
  { name: 'Bitbucket', patterns: [/bitbucket/i], category: 'devops' },
  { name: 'Grafana', patterns: [/grafana/i], category: 'devops', versionRe: /grafana[- ]v?([\d.]+)/i },
  { name: 'Kibana', patterns: [/kibana/i], category: 'devops', versionRe: /kibana[- ]v?([\d.]+)/i },
  { name: 'SonarQube', patterns: [/sonarqube/i, /sonar/i], category: 'devops' },
  { name: 'Artifactory', patterns: [/artifactory/i, /jfrog/i], category: 'devops' },
  { name: 'Nexus', patterns: [/nexus/i, /sonatype/i], category: 'devops' },
  { name: 'TeamCity', patterns: [/teamcity/i], category: 'devops' },
  { name: 'Bamboo', patterns: [/bamboo/i], category: 'devops' },
  { name: 'Ansible Tower', patterns: [/ansible/i, /awx/i], category: 'devops' },
  { name: 'HashiCorp Vault', patterns: [/vault/i, /hashicorp/i], category: 'devops' },
  { name: 'Consul', patterns: [/consul/i], category: 'devops' },
  { name: 'Prometheus', patterns: [/prometheus/i], category: 'devops' },
  { name: 'Splunk', patterns: [/splunk/i], category: 'devops' },

  // Web servers / CDN / WAF
  { name: 'Nginx', patterns: [/nginx/i], category: 'server', versionRe: /nginx\/([\d.]+)/i },
  { name: 'Apache', patterns: [/apache/i], category: 'server', versionRe: /Apache\/([\d.]+)/i },
  { name: 'IIS', patterns: [/microsoft-iis/i], category: 'server', versionRe: /IIS\/([\d.]+)/i },
  { name: 'LiteSpeed', patterns: [/litespeed/i], category: 'server' },
  { name: 'Cloudflare', patterns: [/cloudflare/i, /cf-ray/i, /cf-cache-status/i], category: 'cdn' },
  { name: 'AWS CloudFront', patterns: [/cloudfront/i, /x-amz-cf/i], category: 'cdn' },
  { name: 'Akamai', patterns: [/akamai/i, /x-akamai/i], category: 'cdn' },
  { name: 'Fastly', patterns: [/fastly/i, /x-fastly/i], category: 'cdn' },
  { name: 'Varnish', patterns: [/varnish/i, /x-varnish/i], category: 'cdn' },
  { name: 'Sucuri WAF', patterns: [/sucuri/i], category: 'waf' },
  { name: 'Imperva/Incapsula', patterns: [/incapsula/i, /imperva/i, /visid_incap/i], category: 'waf' },
  { name: 'ModSecurity', patterns: [/mod_security/i], category: 'waf' },
  { name: 'AWS WAF', patterns: [/awswaf/i, /x-amzn-waf/i], category: 'waf' },
  { name: 'F5 BIG-IP', patterns: [/big-?ip/i, /BIGipServer/i], category: 'waf' },

  // Analytics / Tracking
  { name: 'Google Analytics', patterns: [/google-analytics\.com/i, /gtag\//i, /ga\.js/i, /gtm\.js/i], category: 'analytics' },
  { name: 'Google Tag Manager', patterns: [/googletagmanager\.com/i, /gtm\.js/i], category: 'analytics' },
  { name: 'Facebook Pixel', patterns: [/fbevents\.js/i, /facebook\.net/i], category: 'analytics' },
  { name: 'Hotjar', patterns: [/hotjar\.com/i, /hjid/i], category: 'analytics' },
  { name: 'Sentry', patterns: [/sentry\.io/i, /browser\.sentry-cdn/i, /Sentry\.init/i], category: 'analytics' },

  // E-commerce / Payment
  { name: 'Stripe', patterns: [/js\.stripe\.com/i, /Stripe\(/i], category: 'payment' },
  { name: 'PayPal', patterns: [/paypal\.com\/sdk/i], category: 'payment' },
  { name: 'Braintree', patterns: [/braintree/i], category: 'payment' },
];

// ─── Fetch Page ───

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
  depth: number = 0,
): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    if (depth > 5) {
      reject(new Error('Too many redirects'));
      return;
    }
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
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, url).toString();
          httpGet(redirectUrl, timeout, depth + 1).then(resolve).catch(reject);
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

// ─── Security Header Analysis ───

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

// ─── Extraction Helpers ───

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
      scripts.push({ type: 'inline', preview: content.slice(0, 2000), length: content.length });
    }
  }

  return scripts.slice(0, 50);
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
    const enctypeMatch = /enctype=["']([^"']*)["']/i.exec(formTag);

    let action = baseUrl;
    try {
      action = actionMatch ? new URL(actionMatch[1], baseUrl).toString() : baseUrl;
    } catch { /* keep baseUrl */ }

    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
    const enctype = enctypeMatch ? enctypeMatch[1] : '';
    const inputs: { name: string; type: string; value?: string }[] = [];

    const inputRe = /<(?:input|textarea|select)[^>]*/gi;
    let inp;
    while ((inp = inputRe.exec(formBody)) !== null) {
      const tag = inp[0];
      const nameMatch = /name=["']([^"']*)["']/i.exec(tag);
      const typeMatch = /type=["']([^"']*)["']/i.exec(tag);
      const valueMatch = /value=["']([^"']*)["']/i.exec(tag);
      inputs.push({
        name: nameMatch?.[1] || 'unnamed',
        type: typeMatch?.[1] || 'text',
        value: typeMatch?.[1] === 'hidden' ? valueMatch?.[1] : undefined,
      });
    }

    forms.push({ action, method, enctype, inputs });
  }

  return forms.slice(0, 20);
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
  return links.slice(0, 100);
}

function extractComments(html: string): string[] {
  const comments: string[] = [];
  const re = /<!--([\s\S]*?)-->/g;
  let match;
  while ((match = re.exec(html)) !== null) {
    const c = match[1].trim();
    if (c.length > 5) comments.push(c.slice(0, 500));
  }
  return comments.slice(0, 30);
}

// ─── Technology Detection (v2 — 70+ fingerprints with version extraction) ───

export function detectTechnologies(headers: Record<string, string>, html: string): any[] {
  const techs: any[] = [];
  const seen = new Set<string>();
  const lh: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lh[k.toLowerCase()] = v;
  }

  // Header-based detection
  if (lh['server']) techs.push({ name: 'Server', value: lh['server'], source: 'header' });
  if (lh['x-powered-by']) techs.push({ name: 'X-Powered-By', value: lh['x-powered-by'], source: 'header' });
  if (lh['x-aspnet-version']) techs.push({ name: 'ASP.NET Version', value: lh['x-aspnet-version'], source: 'header' });
  if (lh['x-generator']) techs.push({ name: 'Generator', value: lh['x-generator'], source: 'header' });

  // Meta generator tag
  const generatorMatch = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(html);
  if (generatorMatch) {
    techs.push({ name: 'Generator', value: generatorMatch[1], source: 'meta' });
  }

  const fullText = html + '\n' + JSON.stringify(headers);

  for (const fp of TECH_FINGERPRINTS) {
    if (seen.has(fp.name)) continue;
    for (const re of fp.patterns) {
      if (re.test(fullText)) {
        let version: string | undefined;
        if (fp.versionRe) {
          const vm = fp.versionRe.exec(fullText);
          if (vm) version = vm[1];
        }
        techs.push({
          name: fp.name,
          version,
          category: fp.category,
          source: 'fingerprint',
        });
        seen.add(fp.name);
        break;
      }
    }
  }

  return techs;
}

// ─── API Endpoint Discovery ───

function discoverEndpoints(html: string, scripts: any[]): string[] {
  const endpoints = new Set<string>();
  const allCode = html + '\n' + scripts.map(s => s.preview || '').join('\n');

  // REST API patterns
  const apiPatterns = [
    /["'`](\/api\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/v[0-9]+\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/rest\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/graphql[a-zA-Z0-9_/.-]*)["'`]/g,
    /["'`](\/ws\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/auth\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/oauth\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/admin\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /["'`](\/internal\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /fetch\s*\(\s*["'`](\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /\.(?:get|post|put|patch|delete)\s*\(\s*["'`](\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /xhr\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`](\/[a-zA-Z0-9_/.-]+)["'`]/g,
    /url:\s*["'`](\/[a-zA-Z0-9_/.-]+)["'`]/g,
  ];

  for (const re of apiPatterns) {
    let m;
    while ((m = re.exec(allCode)) !== null) {
      const ep = m[1];
      if (ep.length > 3 && ep.length < 200) {
        endpoints.add(ep);
      }
    }
  }

  return [...endpoints].slice(0, 50);
}

// ─── Subdomain Discovery from Links ───

function discoverSubdomains(links: string[], baseUrl: string): string[] {
  const subdomains = new Set<string>();
  let baseDomain = '';
  try {
    const parsed = new URL(baseUrl);
    const parts = parsed.hostname.split('.');
    baseDomain = parts.slice(-2).join('.');
  } catch { return []; }

  for (const link of links) {
    try {
      const parsed = new URL(link);
      if (parsed.hostname.endsWith(baseDomain) && parsed.hostname !== baseDomain) {
        subdomains.add(parsed.hostname);
      }
    } catch { /* skip */ }
  }

  return [...subdomains].slice(0, 30);
}

// ─── The Main Vulnerability Check Engine (v2) ───

export function quickVulnCheck(pageData: PageData): Finding[] {
  const findings: Finding[] = [];
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(pageData.headers || {})) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  // ── 1. Security Headers ──
  for (const [key, info] of Object.entries(pageData.security_headers || {})) {
    if (!info.present) {
      findings.push({
        type: 'missing_header',
        severity: info.severity || 'Medium',
        title: `Missing ${key.toUpperCase().replace(/_/g, '-')} header`,
        description: 'This security header is not set, reducing defense-in-depth.',
      });
    }
  }

  // ── 2. CORS Misconfiguration ──
  const acao = lowerHeaders['access-control-allow-origin'];
  if (acao) {
    if (acao === '*') {
      findings.push({
        type: 'cors_misconfig',
        severity: 'High',
        title: 'CORS: Wildcard Access-Control-Allow-Origin',
        description: 'Server allows any origin to make cross-origin requests. If combined with Access-Control-Allow-Credentials, this is critical — enables credential theft from any domain.',
      });
    }
    const acac = lowerHeaders['access-control-allow-credentials'];
    if (acac === 'true' && acao !== '*') {
      findings.push({
        type: 'cors_misconfig',
        severity: 'Medium',
        title: 'CORS: Credentials allowed with specific origin',
        description: `Origin "${acao}" is trusted with credentials. Test if the server reflects arbitrary Origin headers — if it does, this becomes Critical (CVE pattern for CORS bypass).`,
      });
    }
  }

  // ── 3. Cookie Analysis ──
  for (const cookie of (pageData.cookies || [])) {
    if (!cookie.secure) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'Medium',
        title: `Cookie '${cookie.name}' missing Secure flag`,
        description: 'Cookie transmitted over unencrypted connections. Can be intercepted via MITM.',
      });
    }
    if (!cookie.httponly) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'Medium',
        title: `Cookie '${cookie.name}' missing HttpOnly flag`,
        description: 'Cookie accessible to JavaScript — XSS can steal it via document.cookie.',
      });
    }
    const lcName = cookie.name.toLowerCase();
    if ((lcName.includes('session') || lcName.includes('token') || lcName.includes('auth')) && !cookie.secure) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'High',
        title: `Session/auth cookie '${cookie.name}' transmitted insecurely`,
        description: 'A session or authentication cookie lacks Secure flag. High risk of session hijacking via MITM.',
      });
    }
  }

  // ── 4. JavaScript Secret Scanning ──
  const allInlineCode = (pageData.scripts || [])
    .filter(s => s.preview)
    .map(s => s.preview!)
    .join('\n');
  const fullScanText = pageData.html + '\n' + allInlineCode;

  for (const sp of SECRET_PATTERNS) {
    const re = new RegExp(sp.re.source, sp.re.flags);
    const matches: string[] = [];
    let m;
    while ((m = re.exec(fullScanText)) !== null && matches.length < 3) {
      const match = m[0].slice(0, 80);
      if (!matches.includes(match)) matches.push(match);
    }
    if (matches.length > 0) {
      findings.push({
        type: 'exposed_secret',
        severity: sp.severity,
        title: `${sp.name} found in page source`,
        description: `Detected ${matches.length} instance(s) of ${sp.name}. Sample: "${matches[0]}..."  This could allow account takeover, unauthorized API access, or lateral movement.`,
      });
    }
  }

  // ── 5. Dangerous JS Patterns (expanded) ──
  const dangerousPatterns = [
    { pattern: 'eval(', desc: 'eval() — direct code execution, potential XSS sink' },
    { pattern: 'document.write(', desc: 'document.write() — DOM XSS sink' },
    { pattern: '.innerHTML=', desc: 'innerHTML assignment — DOM XSS sink' },
    { pattern: '.innerHTML =', desc: 'innerHTML assignment — DOM XSS sink' },
    { pattern: '.outerHTML=', desc: 'outerHTML assignment — DOM XSS sink' },
    { pattern: '.outerHTML =', desc: 'outerHTML assignment — DOM XSS sink' },
    { pattern: 'document.domain', desc: 'document.domain manipulation — can relax same-origin policy' },
    { pattern: 'location.href=', desc: 'location.href assignment — potential open redirect' },
    { pattern: 'location.replace(', desc: 'location.replace() — potential open redirect' },
    { pattern: 'window.open(', desc: 'window.open() — potential phishing vector' },
    { pattern: 'postMessage(', desc: 'postMessage() — cross-origin messaging, verify origin checking' },
    { pattern: 'addEventListener("message"', desc: 'message event listener — verify origin validation in handler' },
    { pattern: "addEventListener('message'", desc: 'message event listener — verify origin validation in handler' },
    { pattern: 'DOMParser', desc: 'DOMParser — could parse untrusted HTML' },
    { pattern: 'createContextualFragment', desc: 'createContextualFragment — DOM XSS via Range API' },
    { pattern: 'setTimeout(', desc: 'setTimeout with string — potential eval-like execution' },
    { pattern: 'setInterval(', desc: 'setInterval with string — potential eval-like execution' },
    { pattern: 'Function(', desc: 'Function constructor — dynamic code execution' },
  ];

  const seenDangerous = new Set<string>();
  for (const script of (pageData.scripts || [])) {
    const preview = script.preview || '';
    for (const dp of dangerousPatterns) {
      if (preview.includes(dp.pattern) && !seenDangerous.has(dp.pattern)) {
        seenDangerous.add(dp.pattern);
        findings.push({
          type: 'dangerous_js',
          severity: 'Medium',
          title: `Dangerous JS pattern: ${dp.pattern.trim()}`,
          description: dp.desc,
        });
      }
    }
  }

  // ── 6. Sensitive Path/Endpoint Detection ──
  const allLinks = (pageData.links || []).join('\n').toLowerCase();
  const htmlLower = pageData.html.toLowerCase();
  const combinedPaths = allLinks + '\n' + htmlLower;

  for (const sp of SENSITIVE_PATHS) {
    if (combinedPaths.includes(sp.path.toLowerCase())) {
      findings.push({
        type: 'sensitive_path',
        severity: sp.severity,
        title: `Sensitive path detected: ${sp.path}`,
        description: `${sp.name}. This may expose sensitive information, admin interfaces, or configuration files. Verify if accessible.`,
      });
    }
  }

  // ── 7. Open Redirect Detection ──
  const pageUrl = pageData.url || '';
  try {
    const parsedUrl = new URL(pageUrl);
    for (const param of REDIRECT_PARAMS) {
      if (parsedUrl.searchParams.has(param)) {
        findings.push({
          type: 'open_redirect',
          severity: 'Medium',
          title: `Potential open redirect parameter: ${param}`,
          description: `URL contains redirect parameter "${param}=${parsedUrl.searchParams.get(param)}". Test with external URLs to confirm open redirect vulnerability.`,
        });
      }
    }
  } catch { /* invalid URL */ }

  // Check forms for redirect params
  for (const form of (pageData.forms || [])) {
    for (const input of form.inputs) {
      if (REDIRECT_PARAMS.includes(input.name.toLowerCase())) {
        findings.push({
          type: 'open_redirect',
          severity: 'Medium',
          title: `Form contains redirect parameter: ${input.name}`,
          description: `Form at ${form.action} contains input "${input.name}" which may enable open redirect. Test by injecting external URL.`,
        });
      }
    }
  }

  // ── 8. Server Information Disclosure ──
  if (lowerHeaders['server']) {
    const serverVal = lowerHeaders['server'];
    const versionMatch = /[\d]+\.[\d]+/.exec(serverVal);
    if (versionMatch) {
      findings.push({
        type: 'info_disclosure',
        severity: 'Low',
        title: `Server version disclosed: ${serverVal}`,
        description: `Server header reveals version information (${serverVal}). This helps attackers identify known CVEs for this specific version.`,
      });
    }
  }
  if (lowerHeaders['x-powered-by']) {
    findings.push({
      type: 'info_disclosure',
      severity: 'Low',
      title: `X-Powered-By header: ${lowerHeaders['x-powered-by']}`,
      description: 'Technology stack disclosed via X-Powered-By header. Aids targeted exploitation.',
    });
  }
  if (lowerHeaders['x-aspnet-version']) {
    findings.push({
      type: 'info_disclosure',
      severity: 'Medium',
      title: `ASP.NET version disclosed: ${lowerHeaders['x-aspnet-version']}`,
      description: 'Exact ASP.NET version revealed. Cross-reference with known CVEs.',
    });
  }

  // ── 9. Source Map Detection ──
  const sourceMapPatterns = [/\/\/# sourceMappingURL=([^\s]+\.map)/g, /\/\*# sourceMappingURL=([^\s]+\.map)/g];
  for (const re of sourceMapPatterns) {
    let m;
    while ((m = re.exec(fullScanText)) !== null) {
      findings.push({
        type: 'source_map',
        severity: 'Medium',
        title: `JavaScript source map exposed: ${m[1]}`,
        description: 'Source maps expose original source code including comments, variable names, and logic. Can reveal internal API endpoints, secrets, and business logic.',
      });
      break;
    }
  }

  // ── 10. Comment Analysis for Sensitive Info ──
  const sensitiveCommentPatterns = [
    { re: /todo|fixme|hack|bug|xxx/i, label: 'Developer TODO/FIXME note', severity: 'Low' as string },
    { re: /password|passwd|pwd|secret|credential/i, label: 'Password/credential reference in comment', severity: 'Medium' as string },
    { re: /admin|root|superuser/i, label: 'Admin/root reference in comment', severity: 'Low' as string },
    { re: /internal|private|confidential/i, label: 'Internal/confidential reference in comment', severity: 'Medium' as string },
    { re: /debug|staging|dev|test/i, label: 'Debug/staging environment reference', severity: 'Low' as string },
    { re: /api[_-]?key|token|auth/i, label: 'API key/token reference in comment', severity: 'Medium' as string },
    { re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/, label: 'Internal IP in comment', severity: 'Medium' as string },
    { re: /https?:\/\/(?:localhost|127\.0\.0\.1)/, label: 'Localhost URL in comment', severity: 'Low' as string },
  ];

  for (const comment of (pageData.comments || [])) {
    for (const sp of sensitiveCommentPatterns) {
      if (sp.re.test(comment)) {
        findings.push({
          type: 'sensitive_comment',
          severity: sp.severity,
          title: sp.label,
          description: `HTML comment: "${comment.slice(0, 120)}..."`,
        });
        break;
      }
    }
  }

  // ── 11. Form Security Analysis ──
  for (const form of (pageData.forms || [])) {
    // File upload forms
    const hasFileInput = form.inputs.some((i: any) => i.type === 'file');
    if (hasFileInput) {
      findings.push({
        type: 'file_upload',
        severity: 'Medium',
        title: `File upload form detected`,
        description: `Form at ${form.action} accepts file uploads. Test for unrestricted file upload (shell upload, path traversal in filename, content-type bypass).`,
      });
    }

    // Forms without CSRF tokens
    const hasCsrf = form.inputs.some((i: any) =>
      /csrf|token|nonce|authenticity/i.test(i.name)
    );
    if (form.method === 'POST' && !hasCsrf) {
      findings.push({
        type: 'missing_csrf',
        severity: 'Medium',
        title: 'POST form without CSRF protection',
        description: `Form at ${form.action} (method ${form.method}) has no apparent CSRF token input. May be vulnerable to cross-site request forgery.`,
      });
    }

    // Password form with autocomplete
    const hasPassword = form.inputs.some((i: any) => i.type === 'password');
    if (hasPassword && form.action.startsWith('http://')) {
      findings.push({
        type: 'insecure_form',
        severity: 'High',
        title: 'Login form submits over HTTP',
        description: `Form at ${form.action} contains password field but submits over unencrypted HTTP. Credentials can be intercepted.`,
      });
    }

    // Hidden field analysis
    const hiddenFields = form.inputs.filter((i: any) => i.type === 'hidden' && i.value);
    for (const hf of hiddenFields) {
      if (/id|user|role|admin|price|discount|level/i.test(hf.name)) {
        findings.push({
          type: 'idor_candidate',
          severity: 'Medium',
          title: `Hidden field may be IDOR target: ${hf.name}=${hf.value}`,
          description: `Hidden input "${hf.name}" with value "${hf.value}" may be an Insecure Direct Object Reference. Try modifying this value to access other users' data.`,
        });
      }
    }
  }

  // ── 12. Mixed Content Detection ──
  if (pageData.url.startsWith('https://')) {
    const httpRefs = fullScanText.match(/http:\/\/[^\s"'<>]+/g) || [];
    const externalHttp = httpRefs.filter(ref =>
      !ref.includes('localhost') && !ref.includes('127.0.0.1') && !ref.includes('://http')
    );
    if (externalHttp.length > 0) {
      findings.push({
        type: 'mixed_content',
        severity: 'Medium',
        title: `Mixed content: ${externalHttp.length} HTTP resource(s) on HTTPS page`,
        description: `Found HTTP references on HTTPS page. Example: ${externalHttp[0].slice(0, 100)}. Mixed content can be MITM'd to inject malicious scripts.`,
      });
    }
  }

  // ── 13. API Endpoint Discovery ──
  const discoveredEndpoints = discoverEndpoints(pageData.html, pageData.scripts || []);
  if (discoveredEndpoints.length > 0) {
    findings.push({
      type: 'api_endpoints',
      severity: 'Info',
      title: `${discoveredEndpoints.length} API endpoint(s) discovered in source`,
      description: `Endpoints found: ${discoveredEndpoints.slice(0, 15).join(', ')}. Test each for authentication bypass, IDOR, and injection.`,
    });
  }

  // ── 14. Subdomain Discovery ──
  const subdomains = discoverSubdomains(pageData.links || [], pageData.url);
  if (subdomains.length > 0) {
    findings.push({
      type: 'subdomains',
      severity: 'Info',
      title: `${subdomains.length} subdomain(s) discovered`,
      description: `Subdomains: ${subdomains.slice(0, 15).join(', ')}. Each is a potential attack surface — scan for exposed services.`,
    });
  }

  // ── 15. Technology-based Vulnerability Hints ──
  for (const tech of (pageData.technologies || [])) {
    if (tech.version) {
      findings.push({
        type: 'version_detected',
        severity: 'Info',
        title: `${tech.name} version ${tech.version} detected`,
        description: `Version-specific detection. Cross-reference with CVE databases for known vulnerabilities in ${tech.name} ${tech.version}.`,
      });
    }
  }

  // ── 16. CSP Analysis (if present) ──
  const cspHeader = lowerHeaders['content-security-policy'];
  if (cspHeader) {
    if (cspHeader.includes("'unsafe-inline'")) {
      findings.push({
        type: 'weak_csp',
        severity: 'Medium',
        title: 'CSP allows unsafe-inline',
        description: "Content Security Policy includes 'unsafe-inline' which allows inline script execution, weakening XSS protection.",
      });
    }
    if (cspHeader.includes("'unsafe-eval'")) {
      findings.push({
        type: 'weak_csp',
        severity: 'Medium',
        title: 'CSP allows unsafe-eval',
        description: "Content Security Policy includes 'unsafe-eval' which allows eval() and similar dynamic code execution.",
      });
    }
    if (cspHeader.includes('*') && !cspHeader.includes('*.')) {
      findings.push({
        type: 'weak_csp',
        severity: 'High',
        title: 'CSP contains wildcard source',
        description: 'Content Security Policy contains a wildcard (*) source directive, significantly weakening the policy.',
      });
    }
    if (cspHeader.includes('data:')) {
      findings.push({
        type: 'weak_csp',
        severity: 'Medium',
        title: 'CSP allows data: URIs',
        description: "CSP allows data: URIs which can be used to bypass script restrictions via data:text/html payloads.",
      });
    }
  }

  // ── 17. WAF Detection ──
  const wafIndicators = [
    { header: 'cf-ray', name: 'Cloudflare' },
    { header: 'x-sucuri-id', name: 'Sucuri' },
    { header: 'x-cdn', name: 'CDN detected' },
    { header: 'x-iinfo', name: 'Incapsula/Imperva' },
    { header: 'x-fw-protection', name: 'Firewall protection' },
  ];
  for (const waf of wafIndicators) {
    if (lowerHeaders[waf.header]) {
      findings.push({
        type: 'waf_detected',
        severity: 'Info',
        title: `WAF/CDN detected: ${waf.name}`,
        description: `${waf.name} detected via "${waf.header}" header. May filter payloads — use WAF bypass techniques for testing.`,
      });
    }
  }

  // ── 18. Email Address Disclosure ──
  const emailRe = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = new Set<string>();
  let em;
  while ((em = emailRe.exec(pageData.html)) !== null && emails.size < 5) {
    const email = em[0];
    if (!email.includes('example.com') && !email.includes('placeholder')) {
      emails.add(email);
    }
  }
  if (emails.size > 0) {
    findings.push({
      type: 'email_disclosure',
      severity: 'Low',
      title: `${emails.size} email address(es) exposed`,
      description: `Found: ${[...emails].join(', ')}. Can be used for phishing, social engineering, or credential stuffing.`,
    });
  }

  // ── 19. JSONP Endpoint Detection ──
  const jsonpRe = /(?:callback|jsonp|cb)\s*=\s*[a-zA-Z_]/gi;
  if (jsonpRe.test(fullScanText)) {
    findings.push({
      type: 'jsonp_endpoint',
      severity: 'Medium',
      title: 'JSONP callback parameter detected',
      description: 'JSONP endpoints can leak data cross-origin. If the endpoint returns sensitive data, this is a data exfiltration vector.',
    });
  }

  // ── 20. Unencrypted Form Actions ──
  if (pageData.url.startsWith('https://')) {
    for (const form of (pageData.forms || [])) {
      if (form.action.startsWith('http://')) {
        findings.push({
          type: 'insecure_form',
          severity: 'High',
          title: `Form submits to HTTP: ${form.action}`,
          description: 'Form on HTTPS page submits data over unencrypted HTTP. Data can be intercepted.',
        });
      }
    }
  }

  return findings;
}

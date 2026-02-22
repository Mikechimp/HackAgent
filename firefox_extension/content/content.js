/**
 * HackAgent Content Script (v2 — Deep Page Capture)
 *
 * Captures comprehensive security-relevant page data:
 * - Full HTML + inline script contents
 * - localStorage / sessionStorage keys
 * - All forms with hidden field values
 * - External + inline scripts
 * - Links, meta tags, comments
 * - Cookies (client-visible)
 * - Detected technologies (quick client-side check)
 * - API endpoints discovered in JS
 * - Response headers (from performance API)
 */

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getPageData') {
        try {
            const data = capturePageData();
            sendResponse(data);
        } catch (err) {
            sendResponse({
                html: document.documentElement.outerHTML.substring(0, 100000),
                url: window.location.href,
                title: document.title,
                error: err.message,
            });
        }
    }
    return true;
});

function capturePageData() {
    const html = document.documentElement.outerHTML.substring(0, 150000);

    // ── Cookies ──
    const cookies = document.cookie ? document.cookie.split(';').map(c => {
        const [name, ...rest] = c.trim().split('=');
        return { name: name.trim(), value: rest.join('=').substring(0, 100) };
    }) : [];

    // ── Forms (with hidden field values for IDOR detection) ──
    const forms = Array.from(document.forms).slice(0, 20).map(form => ({
        action: form.action,
        method: form.method,
        enctype: form.enctype || '',
        inputs: Array.from(form.elements).slice(0, 30).map(el => ({
            name: el.name,
            type: el.type,
            id: el.id,
            value: el.type === 'hidden' ? el.value.substring(0, 200) : undefined,
            autocomplete: el.getAttribute('autocomplete'),
        })),
    }));

    // ── Scripts (external + inline contents for secret scanning) ──
    const scripts = Array.from(document.scripts).slice(0, 50).map(s => {
        if (s.src) {
            return {
                type: 'external',
                src: s.src,
                crossOrigin: s.crossOrigin,
                integrity: s.integrity || null,
                async: s.async,
                defer: s.defer,
            };
        } else {
            const content = s.textContent || '';
            return {
                type: 'inline',
                preview: content.substring(0, 3000),
                length: content.length,
            };
        }
    });

    // ── Links ──
    const links = Array.from(document.links).slice(0, 100).map(a => ({
        href: a.href,
        text: a.textContent.trim().substring(0, 100),
        rel: a.rel || null,
        target: a.target || null,
    }));

    // ── Meta tags ──
    const meta = Array.from(document.querySelectorAll('meta')).map(m => ({
        name: m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv'),
        content: (m.getAttribute('content') || '').substring(0, 300),
    })).filter(m => m.name);

    // ── HTML Comments ──
    const comments = [];
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node = walker.nextNode()) && comments.length < 30) {
        const text = node.textContent.trim();
        if (text.length > 5) {
            comments.push(text.substring(0, 500));
        }
    }

    // ── localStorage / sessionStorage keys ──
    let storageData = { localStorage: {}, sessionStorage: {} };
    try {
        const lsKeys = Object.keys(localStorage).slice(0, 30);
        for (const key of lsKeys) {
            try {
                storageData.localStorage[key] = localStorage.getItem(key).substring(0, 200);
            } catch (e) { /* skip */ }
        }
    } catch (e) { /* blocked */ }

    try {
        const ssKeys = Object.keys(sessionStorage).slice(0, 30);
        for (const key of ssKeys) {
            try {
                storageData.sessionStorage[key] = sessionStorage.getItem(key).substring(0, 200);
            } catch (e) { /* skip */ }
        }
    } catch (e) { /* blocked */ }

    // ── API Endpoints discovered in inline scripts ──
    const endpoints = new Set();
    const allInlineCode = scripts
        .filter(s => s.type === 'inline' && s.preview)
        .map(s => s.preview)
        .join('\n');

    const endpointPatterns = [
        /["'`](\/api\/[a-zA-Z0-9_/.-]+)["'`]/g,
        /["'`](\/v[0-9]+\/[a-zA-Z0-9_/.-]+)["'`]/g,
        /["'`](\/rest\/[a-zA-Z0-9_/.-]+)["'`]/g,
        /["'`](\/graphql[a-zA-Z0-9_/.-]*)["'`]/g,
        /["'`](\/auth\/[a-zA-Z0-9_/.-]+)["'`]/g,
        /["'`](\/admin\/[a-zA-Z0-9_/.-]+)["'`]/g,
        /fetch\s*\(\s*["'`](\/[a-zA-Z0-9_/.-]+)["'`]/g,
        /\.(?:get|post|put|patch|delete)\s*\(\s*["'`](\/[a-zA-Z0-9_/.-]+)["'`]/g,
    ];

    for (const re of endpointPatterns) {
        let m;
        while ((m = re.exec(allInlineCode)) !== null && endpoints.size < 50) {
            if (m[1].length > 3) endpoints.add(m[1]);
        }
    }

    // ── Quick client-side tech detection ──
    const detectedTech = [];
    const htmlLower = html.toLowerCase();
    const techChecks = [
        { name: 'WordPress', test: () => htmlLower.includes('wp-content/') || htmlLower.includes('wp-includes/') },
        { name: 'React', test: () => htmlLower.includes('react') || htmlLower.includes('__next_data__') || htmlLower.includes('data-reactroot') },
        { name: 'Angular', test: () => htmlLower.includes('ng-app') || htmlLower.includes('ng-version') },
        { name: 'Vue.js', test: () => htmlLower.includes('__vue__') || htmlLower.includes('v-bind') || htmlLower.includes('v-cloak') },
        { name: 'jQuery', test: () => !!window.jQuery },
        { name: 'Next.js', test: () => htmlLower.includes('__next_data__') || htmlLower.includes('_next/static') },
        { name: 'Nuxt.js', test: () => htmlLower.includes('__nuxt') || htmlLower.includes('_nuxt/') },
        { name: 'Bootstrap', test: () => htmlLower.includes('bootstrap.min') || htmlLower.includes('bootstrap.css') },
        { name: 'Tailwind CSS', test: () => htmlLower.includes('tailwindcss') },
        { name: 'Google Analytics', test: () => htmlLower.includes('google-analytics.com') || htmlLower.includes('gtag/') },
        { name: 'Google Tag Manager', test: () => htmlLower.includes('googletagmanager.com') },
        { name: 'Sentry', test: () => htmlLower.includes('sentry.io') || htmlLower.includes('sentry-cdn') },
        { name: 'Stripe', test: () => htmlLower.includes('js.stripe.com') },
        { name: 'Cloudflare', test: () => htmlLower.includes('cloudflare') || htmlLower.includes('cf-ray') },
        { name: 'Laravel', test: () => htmlLower.includes('laravel_session') || htmlLower.includes('xsrf-token') },
        { name: 'Django', test: () => htmlLower.includes('csrfmiddlewaretoken') },
        { name: 'Ruby on Rails', test: () => htmlLower.includes('authenticity_token') || htmlLower.includes('csrf-token') },
        { name: 'ASP.NET', test: () => htmlLower.includes('__viewstate') || htmlLower.includes('.aspx') },
        { name: 'Jenkins', test: () => htmlLower.includes('jenkins') || htmlLower.includes('hudson') },
        { name: 'GitLab', test: () => htmlLower.includes('gitlab') },
        { name: 'Jira', test: () => htmlLower.includes('jira') || htmlLower.includes('atlassian') },
        { name: 'Grafana', test: () => htmlLower.includes('grafana') },
        { name: 'Socket.io', test: () => htmlLower.includes('socket.io') },
    ];

    for (const check of techChecks) {
        try {
            if (check.test()) detectedTech.push(check.name);
        } catch (e) { /* skip */ }
    }

    // ── Service Worker detection ──
    let serviceWorker = null;
    try {
        if (navigator.serviceWorker && navigator.serviceWorker.controller) {
            serviceWorker = navigator.serviceWorker.controller.scriptURL;
        }
    } catch (e) { /* blocked */ }

    // ── Response headers from Performance API ──
    let perfHeaders = {};
    try {
        const entries = performance.getEntriesByType('navigation');
        if (entries.length > 0 && entries[0].serverTiming) {
            perfHeaders.serverTiming = entries[0].serverTiming.map(t => ({
                name: t.name,
                description: t.description,
                duration: t.duration,
            }));
        }
    } catch (e) { /* not available */ }

    // ── CSP from meta tags ──
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const cspContent = cspMeta ? cspMeta.getAttribute('content') : null;

    return {
        html,
        url: window.location.href,
        title: document.title,
        cookies,
        forms,
        scripts,
        links,
        meta,
        comments,
        storage: storageData,
        discoveredEndpoints: [...endpoints],
        detectedTechnologies: detectedTech,
        serviceWorker,
        perfHeaders,
        cspMeta: cspContent,
        capturedAt: new Date().toISOString(),
    };
}

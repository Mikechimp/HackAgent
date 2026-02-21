/**
 * HackAgent Firefox Extension — Popup Controller
 */

const BACKEND_URL = 'http://localhost:5000';

const statusDot = document.querySelector('.status-dot');
const statusText = document.getElementById('status-text');
const btnAnalyze = document.getElementById('btn-analyze');
const btnScreenshot = document.getElementById('btn-screenshot');
const resultsDiv = document.getElementById('results');
const resultsContent = document.getElementById('results-content');
const loadingDiv = document.getElementById('loading');
const btnOpenFull = document.getElementById('btn-open-full');

// Check backend status
async function checkBackend() {
    try {
        const resp = await fetch(BACKEND_URL + '/api/status', { method: 'GET' });
        const data = await resp.json();

        if (data.status === 'online') {
            statusDot.classList.add('online');
            statusDot.classList.remove('offline');
            statusText.textContent = data.api_configured
                ? 'Connected — API Ready'
                : 'Connected — No API Key';
            btnAnalyze.disabled = false;
            btnScreenshot.disabled = false;
            return true;
        }
    } catch (e) {
        statusDot.classList.add('offline');
        statusDot.classList.remove('online');
        statusText.textContent = 'Backend offline';
        btnAnalyze.disabled = true;
        btnScreenshot.disabled = true;
        return false;
    }
}

checkBackend();

// Analyze current page content
btnAnalyze.addEventListener('click', async () => {
    btnAnalyze.disabled = true;
    loadingDiv.style.display = 'block';
    resultsDiv.style.display = 'none';

    try {
        // Get the active tab
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];

        // Execute content script to get page data
        const results = await browser.tabs.sendMessage(tab.id, { action: 'getPageData' });

        // Send to backend for analysis
        const resp = await fetch(BACKEND_URL + '/api/analyze-page', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: tab.url,
                html: results.html,
                cookies: results.cookies || [],
            }),
        });

        const data = await resp.json();

        loadingDiv.style.display = 'none';
        resultsDiv.style.display = 'block';

        if (data.error) {
            resultsContent.textContent = 'Error: ' + data.error;
        } else {
            let text = '';

            if (data.quick_findings && data.quick_findings.length > 0) {
                text += '=== AUTOMATED FINDINGS ===\n\n';
                data.quick_findings.forEach(f => {
                    text += `[${f.severity}] ${f.title}\n  ${f.description}\n\n`;
                });
            }

            if (data.ai_analysis) {
                text += '=== AI ANALYSIS ===\n\n';
                text += data.ai_analysis;
            }

            resultsContent.textContent = text || 'No significant findings.';
        }

    } catch (e) {
        loadingDiv.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsContent.textContent = 'Error: ' + e.message +
            '\n\nMake sure the content script is loaded. Try refreshing the page.';
    }

    btnAnalyze.disabled = false;
});

// Capture screenshot and analyze
btnScreenshot.addEventListener('click', async () => {
    btnScreenshot.disabled = true;
    loadingDiv.style.display = 'block';
    resultsDiv.style.display = 'none';

    try {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];

        // Capture visible tab as screenshot
        const screenshot = await browser.tabs.captureVisibleTab(null, {
            format: 'png',
            quality: 80,
        });

        // Remove the data URL prefix to get pure base64
        const b64 = screenshot.replace(/^data:image\/png;base64,/, '');

        // Send to backend
        const resp = await fetch(BACKEND_URL + '/api/analyze-page', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: tab.url,
                screenshot: b64,
            }),
        });

        const data = await resp.json();

        loadingDiv.style.display = 'none';
        resultsDiv.style.display = 'block';

        resultsContent.textContent = data.ai_analysis || data.error || 'No analysis returned.';

    } catch (e) {
        loadingDiv.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsContent.textContent = 'Error: ' + e.message;
    }

    btnScreenshot.disabled = false;
});

// Open full HackAgent UI
btnOpenFull.addEventListener('click', () => {
    browser.tabs.create({ url: BACKEND_URL });
});

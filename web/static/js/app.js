/**
 * HackAgent Frontend — Chat, URL Analysis, and Extension Integration
 */

const API_BASE = window.location.origin;
let sessionId = 'session-' + Date.now();

// ─── DOM Elements ───
const setupOverlay = document.getElementById('setup-overlay');
const appContainer = document.getElementById('app-container');
const chatMessages = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
const chatSend = document.getElementById('chat-send');
const urlInput = document.getElementById('url-input');
const urlAnalyzeBtn = document.getElementById('url-analyze-btn');
const analysisResults = document.getElementById('analysis-results');
const analysisPlaceholder = document.getElementById('analysis-placeholder');
const kbSearch = document.getElementById('kb-search');

// ─── Navigation ───
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        // Update active nav
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');

        // Show corresponding panel
        const panelId = 'panel-' + item.dataset.panel;
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.getElementById(panelId).classList.add('active');
    });
});

// ─── Status Check & Setup Screen ───
let apiConfigured = false;

function showSetup() {
    setupOverlay.style.display = 'flex';
    appContainer.style.display = 'none';
}

function showApp() {
    setupOverlay.style.display = 'none';
    appContainer.style.display = '';
}

async function checkStatus() {
    const dot = document.querySelector('.status-dot');
    const text = document.querySelector('.status-text');
    const extStatus = document.getElementById('extension-status');

    try {
        const resp = await fetch(API_BASE + '/api/status');
        const data = await resp.json();

        if (data.status === 'online') {
            apiConfigured = data.api_configured;

            // Show setup screen or the main app
            if (!data.api_configured) {
                showSetup();
            } else {
                showApp();
            }

            dot.classList.add('online');
            text.textContent = data.api_configured ? 'Online — API Connected' : 'Online — No API Key';
            text.style.color = data.api_configured ? '#4dd88a' : '#d4a853';

            if (extStatus) {
                extStatus.className = 'extension-status online';
                extStatus.innerHTML = `
                    <p style="color: #4dd88a; font-weight: 600;">Backend Online</p>
                    <p>API: ${data.api_configured ? 'Configured' : 'Not configured'}</p>
                    <p>Extension endpoint: <code style="color: #3dd8c5;">${API_BASE}/api/analyze-page</code></p>
                `;
            }
        }
    } catch (e) {
        dot.classList.remove('online');
        text.textContent = 'Offline';
        text.style.color = '#e85d5d';

        if (extStatus) {
            extStatus.className = 'extension-status offline';
            extStatus.innerHTML = '<p style="color: #e85d5d;">Backend offline — start with: python run_web.py</p>';
        }
    }
}

checkStatus();
setInterval(checkStatus, 30000);

// ─── Setup Form ───
const setupKeyInput = document.getElementById('setup-api-key');
const setupSubmitBtn = document.getElementById('setup-submit');
const setupError = document.getElementById('setup-error');

setupKeyInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitApiKey();
});

setupSubmitBtn.addEventListener('click', submitApiKey);

async function submitApiKey() {
    const key = setupKeyInput.value.trim();
    setupError.style.display = 'none';

    if (!key) {
        setupError.textContent = 'Please enter your API key.';
        setupError.style.display = 'block';
        return;
    }

    if (!key.startsWith('sk-')) {
        setupError.textContent = 'Invalid key format. OpenAI keys start with "sk-".';
        setupError.style.display = 'block';
        return;
    }

    // Show loading state
    setupSubmitBtn.disabled = true;
    setupSubmitBtn.querySelector('.setup-btn-text').style.display = 'none';
    setupSubmitBtn.querySelector('.setup-btn-loading').style.display = 'inline-flex';

    try {
        const resp = await fetch(API_BASE + '/api/setup-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: key }),
        });

        const data = await resp.json();

        if (data.error) {
            setupError.textContent = data.error;
            setupError.style.display = 'block';
        } else {
            // Key saved — switch to the main app
            apiConfigured = true;
            showApp();
        }
    } catch (e) {
        setupError.textContent = 'Connection error: ' + e.message;
        setupError.style.display = 'block';
    }

    // Reset button
    setupSubmitBtn.disabled = false;
    setupSubmitBtn.querySelector('.setup-btn-text').style.display = 'inline';
    setupSubmitBtn.querySelector('.setup-btn-loading').style.display = 'none';
}

// ─── Chat ───
chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
});

chatSend.addEventListener('click', sendMessage);

async function sendMessage() {
    const message = chatInput.value.trim();
    if (!message) return;

    // Add user message to chat
    appendMessage('user', message);
    chatInput.value = '';
    chatInput.style.height = 'auto';

    // Show typing indicator
    const typingEl = appendTyping();

    try {
        const resp = await fetch(API_BASE + '/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: message,
                session_id: sessionId,
            }),
        });

        const data = await resp.json();
        typingEl.remove();

        if (data.error) {
            appendMessage('assistant', `Error: ${data.error}`);
        } else {
            appendMessage('assistant', data.response);
        }
    } catch (e) {
        typingEl.remove();
        appendMessage('assistant', `Connection error: ${e.message}. Make sure the backend is running.`);
    }
}

function appendMessage(role, content) {
    const div = document.createElement('div');
    div.className = `message ${role}`;

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.innerHTML = `<span>${role === 'assistant' ? 'HA' : 'You'}</span>`;

    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';

    const header = document.createElement('div');
    header.className = 'message-header';
    header.innerHTML = `<span class="message-sender">${role === 'assistant' ? 'HackAgent' : 'You'}</span>`;

    const body = document.createElement('div');
    body.className = 'message-body';
    body.innerHTML = formatMessage(content);

    contentDiv.appendChild(header);
    contentDiv.appendChild(body);
    div.appendChild(avatar);
    div.appendChild(contentDiv);

    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function appendTyping() {
    const div = document.createElement('div');
    div.className = 'message assistant';
    div.innerHTML = `
        <div class="message-avatar"><span>HA</span></div>
        <div class="message-content">
            <div class="message-header"><span class="message-sender">HackAgent</span></div>
            <div class="message-body">
                <div class="typing-indicator">
                    <span></span><span></span><span></span>
                </div>
            </div>
        </div>
    `;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return div;
}

function formatMessage(text) {
    if (!text) return '';

    // Escape HTML first
    let formatted = text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    // Code blocks
    formatted = formatted.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
        return `<pre><code>${code.trim()}</code></pre>`;
    });

    // Inline code
    formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold
    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Italic
    formatted = formatted.replace(/\*([^*]+)\*/g, '<em>$1</em>');

    // Lists
    formatted = formatted.replace(/^[-•] (.+)$/gm, '<li>$1</li>');
    formatted = formatted.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

    // Numbered lists
    formatted = formatted.replace(/^\d+\.\s(.+)$/gm, '<li>$1</li>');

    // Line breaks
    formatted = formatted.replace(/\n\n/g, '</p><p>');
    formatted = formatted.replace(/\n/g, '<br>');

    // Wrap in paragraphs
    if (!formatted.startsWith('<')) {
        formatted = '<p>' + formatted + '</p>';
    }

    return formatted;
}

// ─── URL Analysis ───
urlAnalyzeBtn.addEventListener('click', analyzeUrl);

urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') analyzeUrl();
});

async function analyzeUrl() {
    let url = urlInput.value.trim();
    if (!url) return;

    // Prepend https:// if not present
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    // Show loading state
    urlAnalyzeBtn.disabled = true;
    urlAnalyzeBtn.querySelector('.btn-text').style.display = 'none';
    urlAnalyzeBtn.querySelector('.btn-loading').style.display = 'inline-flex';

    analysisPlaceholder.style.display = 'none';
    analysisResults.style.display = 'flex';
    analysisResults.innerHTML = '<div class="result-section"><div class="result-section-body"><div class="typing-indicator"><span></span><span></span><span></span></div><p style="color: var(--text-muted); margin-top: 8px;">Analyzing target... fetching page, checking headers, scanning for vulnerabilities</p></div></div>';

    try {
        const resp = await fetch(API_BASE + '/api/analyze-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });

        const data = await resp.json();

        if (data.error) {
            analysisResults.innerHTML = `<div class="result-section"><div class="result-section-body" style="color: var(--severity-high);">Error: ${escapeHtml(data.error)}</div></div>`;
        } else {
            renderAnalysisResults(data);
        }
    } catch (e) {
        analysisResults.innerHTML = `<div class="result-section"><div class="result-section-body" style="color: var(--severity-high);">Connection error: ${escapeHtml(e.message)}</div></div>`;
    }

    // Reset button
    urlAnalyzeBtn.disabled = false;
    urlAnalyzeBtn.querySelector('.btn-text').style.display = 'inline';
    urlAnalyzeBtn.querySelector('.btn-loading').style.display = 'none';
}

function renderAnalysisResults(data) {
    let html = '';

    // Overview section
    html += `
        <div class="result-section">
            <div class="result-section-header">
                <h3>Overview</h3>
                <span style="color: var(--text-muted); font-size: 12px;">Status: ${data.status_code || 'N/A'}</span>
            </div>
            <div class="result-section-body">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px;">
                    <div style="text-align: center; padding: 12px; background: var(--bg-input); border-radius: var(--radius-sm);">
                        <div style="font-size: 24px; font-weight: 700; color: var(--accent-gold);">${data.technologies ? data.technologies.length : 0}</div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Technologies</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: var(--bg-input); border-radius: var(--radius-sm);">
                        <div style="font-size: 24px; font-weight: 700; color: var(--accent-gold);">${data.quick_findings ? data.quick_findings.length : 0}</div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Quick Findings</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: var(--bg-input); border-radius: var(--radius-sm);">
                        <div style="font-size: 24px; font-weight: 700; color: var(--accent-gold);">${data.forms_count || 0}</div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Forms</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: var(--bg-input); border-radius: var(--radius-sm);">
                        <div style="font-size: 24px; font-weight: 700; color: var(--accent-gold);">${data.scripts_count || 0}</div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Scripts</div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Quick findings
    if (data.quick_findings && data.quick_findings.length > 0) {
        html += `
            <div class="result-section">
                <div class="result-section-header">
                    <h3>Automated Findings</h3>
                    <span style="color: var(--text-muted); font-size: 12px;">${data.quick_findings.length} issues</span>
                </div>
                <div class="result-section-body">
                    ${data.quick_findings.map(f => `
                        <div class="finding-item">
                            <span class="severity-badge ${(f.severity || 'info').toLowerCase()}">${f.severity || 'Info'}</span>
                            <div class="finding-detail">
                                <h4>${escapeHtml(f.title)}</h4>
                                <p>${escapeHtml(f.description)}</p>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // Attack surface matches
    if (data.attack_surface_matches && data.attack_surface_matches.length > 0) {
        html += `
            <div class="result-section">
                <div class="result-section-header">
                    <h3>Attack Surface Matches (jhaddix DB)</h3>
                </div>
                <div class="result-section-body">
                    ${data.attack_surface_matches.map(m => `
                        <div class="finding-item">
                            <span class="severity-badge high">Match</span>
                            <div class="finding-detail">
                                <h4>${escapeHtml(m.technology)}</h4>
                                <p><strong>Attack vectors:</strong> ${m.attack_vectors.map(v => escapeHtml(v)).join(', ')}</p>
                                ${m.critical_cves.length ? `<p><strong>Critical CVEs:</strong> ${m.critical_cves.join(', ')}</p>` : ''}
                                ${m.default_creds.length ? `<p><strong>Default creds:</strong> ${m.default_creds.map(c => `${c.user}:${c.pass}`).join(', ')}</p>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // AI Analysis
    if (data.ai_analysis) {
        html += `
            <div class="result-section">
                <div class="result-section-header">
                    <h3>AI Deep Analysis</h3>
                    <span style="color: var(--text-muted); font-size: 12px;">GPT-4o</span>
                </div>
                <div class="result-section-body">
                    <div class="ai-analysis-text">${formatMessage(data.ai_analysis)}</div>
                </div>
            </div>
        `;
    }

    // Errors
    if (data.errors && data.errors.length > 0) {
        html += `
            <div class="result-section">
                <div class="result-section-header">
                    <h3>Errors</h3>
                </div>
                <div class="result-section-body">
                    ${data.errors.map(e => `<p style="color: var(--severity-high);">${escapeHtml(e)}</p>`).join('')}
                </div>
            </div>
        `;
    }

    analysisResults.innerHTML = html;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Knowledge Base Search ───
if (kbSearch) {
    kbSearch.addEventListener('input', () => {
        const query = kbSearch.value.toLowerCase();
        document.querySelectorAll('.kb-category').forEach(cat => {
            const text = cat.textContent.toLowerCase();
            cat.style.display = text.includes(query) ? 'block' : 'none';
        });
    });
}

// ─── Keyboard shortcuts ───
document.addEventListener('keydown', (e) => {
    // Ctrl+K to focus chat input
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        chatInput.focus();
        // Switch to chat panel
        document.querySelector('[data-panel="chat"]').click();
    }
});

/**
 * HackAgent Frontend — Chat, URL Analysis, and Extension Integration
 * Electron renderer — uses preload bridge for API base URL.
 */

const API_BASE = (window.hackagent && window.hackagent.getApiBase())
    || 'http://localhost:5175';
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

            // Check for new extension results
            checkExtensionResults(data);
        }
    } catch (e) {
        dot.classList.remove('online');
        text.textContent = 'Offline';
        text.style.color = '#e85d5d';

        if (extStatus) {
            extStatus.className = 'extension-status offline';
            extStatus.innerHTML = '<p style="color: #e85d5d;">Backend offline — restarting...</p>';
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

// ─── Projects ───
const projectsList = document.getElementById('projects-list');
const projectsEmpty = document.getElementById('projects-empty');
const projectDetail = document.getElementById('project-detail');
const projectMeta = document.getElementById('project-meta');
const projectResults = document.getElementById('project-results');
const projectNotes = document.getElementById('project-notes');
const projectsBadge = document.getElementById('projects-badge');
const projectsSearch = document.getElementById('projects-search');

let currentProjects = [];
let currentProjectId = null;

async function loadProjects() {
    try {
        const resp = await fetch(API_BASE + '/api/projects');
        currentProjects = await resp.json();
        renderProjectsList(currentProjects);
    } catch (e) {
        console.error('Failed to load projects:', e);
    }
}

function renderProjectsList(projects) {
    const query = (projectsSearch?.value || '').toLowerCase();
    const filtered = query
        ? projects.filter(p => (p.name + ' ' + p.url + ' ' + p.notes).toLowerCase().includes(query))
        : projects;

    if (filtered.length === 0) {
        projectsList.style.display = 'none';
        projectsEmpty.style.display = 'block';
        projectDetail.style.display = 'none';
        return;
    }

    projectsEmpty.style.display = 'none';
    projectDetail.style.display = 'none';
    projectsList.style.display = 'flex';

    projectsList.innerHTML = filtered.map(p => {
        const date = new Date(p.created_at);
        const timeStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const sourceIcon = p.source === 'extension' ? '&#129418;' : '&#128269;';
        const sourceLabel = p.source === 'extension' ? 'Extension' : 'URL Scan';
        return `
            <div class="project-card" data-id="${escapeHtml(p.id)}">
                <div class="project-card-header">
                    <span class="project-source">${sourceIcon} ${sourceLabel}</span>
                    <span class="project-date">${timeStr}</span>
                </div>
                <h4 class="project-card-title">${escapeHtml(p.name)}</h4>
                <p class="project-card-url">${escapeHtml(p.url)}</p>
                <div class="project-card-footer">
                    <span class="project-finding-count">${p.finding_count} finding${p.finding_count !== 1 ? 's' : ''}${p.has_ai ? ' + AI analysis' : ''}</span>
                    ${p.notes ? '<span class="project-has-notes">&#128221; Notes</span>' : ''}
                </div>
            </div>
        `;
    }).join('');

    projectsList.querySelectorAll('.project-card').forEach(card => {
        card.addEventListener('click', () => openProject(card.dataset.id));
    });
}

async function openProject(id) {
    try {
        const resp = await fetch(API_BASE + '/api/projects/' + id);
        if (!resp.ok) return;
        const project = await resp.json();
        currentProjectId = id;

        projectsList.style.display = 'none';
        projectsEmpty.style.display = 'none';
        projectDetail.style.display = 'block';

        const date = new Date(project.created_at);
        projectMeta.innerHTML = `
            <h3 class="project-detail-title">${escapeHtml(project.name)}</h3>
            <p class="project-detail-url">${escapeHtml(project.url)}</p>
            <p class="project-detail-date">${project.source === 'extension' ? '&#129418; Extension' : '&#128269; URL Scan'} &middot; ${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
        `;

        projectNotes.value = project.notes || '';

        // Render findings using the shared renderer
        renderProjectFindings(project);
    } catch (e) {
        console.error('Failed to open project:', e);
    }
}

function renderProjectFindings(project) {
    const f = project.findings || {};
    const m = project.metadata || {};
    let html = '';

    // Overview (if URL scan)
    if (m.status_code !== undefined) {
        html += `
            <div class="result-section">
                <div class="result-section-header"><h3>Overview</h3><span style="color:var(--text-muted);font-size:12px;">Status: ${m.status_code || 'N/A'}</span></div>
                <div class="result-section-body">
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;">
                        <div style="text-align:center;padding:12px;background:var(--bg-input);border-radius:var(--radius-sm);"><div style="font-size:24px;font-weight:700;color:var(--accent-gold);">${f.technologies ? f.technologies.length : 0}</div><div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Technologies</div></div>
                        <div style="text-align:center;padding:12px;background:var(--bg-input);border-radius:var(--radius-sm);"><div style="font-size:24px;font-weight:700;color:var(--accent-gold);">${f.quick_findings ? f.quick_findings.length : 0}</div><div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Findings</div></div>
                        <div style="text-align:center;padding:12px;background:var(--bg-input);border-radius:var(--radius-sm);"><div style="font-size:24px;font-weight:700;color:var(--accent-gold);">${m.forms_count || 0}</div><div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Forms</div></div>
                        <div style="text-align:center;padding:12px;background:var(--bg-input);border-radius:var(--radius-sm);"><div style="font-size:24px;font-weight:700;color:var(--accent-gold);">${m.scripts_count || 0}</div><div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Scripts</div></div>
                    </div>
                </div>
            </div>
        `;
    }

    // Quick findings
    if (f.quick_findings && f.quick_findings.length > 0) {
        html += `
            <div class="result-section">
                <div class="result-section-header"><h3>Automated Findings</h3><span style="color:var(--text-muted);font-size:12px;">${f.quick_findings.length} issues</span></div>
                <div class="result-section-body">
                    ${f.quick_findings.map(item => `
                        <div class="finding-item">
                            <span class="severity-badge ${(item.severity || 'info').toLowerCase()}">${item.severity || 'Info'}</span>
                            <div class="finding-detail"><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.description)}</p></div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // Attack surface matches
    if (f.attack_surface_matches && f.attack_surface_matches.length > 0) {
        html += `
            <div class="result-section">
                <div class="result-section-header"><h3>Attack Surface Matches</h3></div>
                <div class="result-section-body">
                    ${f.attack_surface_matches.map(match => `
                        <div class="finding-item">
                            <span class="severity-badge high">Match</span>
                            <div class="finding-detail">
                                <h4>${escapeHtml(match.technology)}</h4>
                                <p><strong>Vectors:</strong> ${match.attack_vectors.map(v => escapeHtml(v)).join(', ')}</p>
                                ${match.critical_cves?.length ? `<p><strong>CVEs:</strong> ${match.critical_cves.join(', ')}</p>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // AI Analysis
    if (f.ai_analysis) {
        html += `
            <div class="result-section">
                <div class="result-section-header"><h3>AI Deep Analysis</h3><span style="color:var(--text-muted);font-size:12px;">GPT-4o</span></div>
                <div class="result-section-body"><div class="ai-analysis-text">${formatMessage(f.ai_analysis)}</div></div>
            </div>
        `;
    }

    if (!html) {
        html = '<div class="result-section"><div class="result-section-body"><p style="color:var(--text-muted);">No findings recorded for this project.</p></div></div>';
    }

    projectResults.innerHTML = html;
}

// Project detail actions
document.getElementById('project-back')?.addEventListener('click', () => {
    currentProjectId = null;
    renderProjectsList(currentProjects);
});

document.getElementById('project-delete')?.addEventListener('click', async () => {
    if (!currentProjectId) return;
    if (!confirm('Delete this project?')) return;
    try {
        await fetch(API_BASE + '/api/projects/' + currentProjectId, { method: 'DELETE' });
        currentProjectId = null;
        await loadProjects();
    } catch (e) {
        alert('Failed to delete: ' + e.message);
    }
});

document.getElementById('project-save-notes')?.addEventListener('click', async () => {
    if (!currentProjectId) return;
    const btn = document.getElementById('project-save-notes');
    try {
        await fetch(API_BASE + '/api/projects/' + currentProjectId, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: projectNotes.value }),
        });
        btn.textContent = 'Saved!';
        setTimeout(() => { btn.textContent = 'Save Notes'; }, 2000);
    } catch (e) {
        alert('Failed to save notes: ' + e.message);
    }
});

document.getElementById('projects-refresh')?.addEventListener('click', loadProjects);

if (projectsSearch) {
    projectsSearch.addEventListener('input', () => renderProjectsList(currentProjects));
}

// Load projects on startup
loadProjects();

// Check for new extension results during status polling
function checkExtensionResults(data) {
    if (data.pending_extension_result) {
        // Show badge
        if (projectsBadge) {
            projectsBadge.style.display = 'inline-block';
            projectsBadge.textContent = 'NEW';
        }
    }
}

// Clear badge when switching to projects panel
const origNavClick = document.querySelectorAll('.nav-item');
origNavClick.forEach(item => {
    item.addEventListener('click', () => {
        if (item.dataset.panel === 'projects') {
            if (projectsBadge) projectsBadge.style.display = 'none';
            // Dismiss on backend
            fetch(API_BASE + '/api/extension/dismiss', { method: 'POST' }).catch(() => {});
            loadProjects();
        }
    });
});

// ─── Extension Wizard ───

// Tab switching
document.querySelectorAll('.ext-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.ext-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.ext-method').forEach(m => m.classList.remove('active'));
        tab.classList.add('active');
        const method = document.getElementById('ext-method-' + tab.dataset.method);
        if (method) method.classList.add('active');
    });
});

// Copy-to-clipboard buttons
document.querySelectorAll('.ext-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const text = btn.dataset.copy;
        navigator.clipboard.writeText(text).then(() => {
            btn.classList.add('copied');
            const origTitle = btn.title;
            btn.title = 'Copied!';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.title = origTitle;
            }, 2000);
        });
    });
});

// Download extension .xpi
const extDownloadBtn = document.getElementById('ext-download-btn');
if (extDownloadBtn) {
    extDownloadBtn.addEventListener('click', async () => {
        extDownloadBtn.disabled = true;
        const origHTML = extDownloadBtn.innerHTML;
        extDownloadBtn.innerHTML = '<span class="spinner"></span> Downloading...';

        try {
            const resp = await fetch(API_BASE + '/api/extension/download');
            if (!resp.ok) {
                let errMsg = 'Download failed';
                try {
                    const err = await resp.json();
                    errMsg = err.error || errMsg;
                } catch (_) {}
                extDownloadBtn.innerHTML = origHTML;
                extDownloadBtn.disabled = false;
                alert(errMsg);
                return;
            }
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'hackagent.xpi';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            extDownloadBtn.innerHTML = '&#10003; Downloaded!';
            setTimeout(() => {
                extDownloadBtn.innerHTML = origHTML;
                extDownloadBtn.disabled = false;
            }, 3000);
        } catch (e) {
            extDownloadBtn.innerHTML = origHTML;
            extDownloadBtn.disabled = false;
            alert('Download failed: ' + e.message);
        }
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

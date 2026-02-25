/**
 * Settings View
 *
 * Application settings, backend status, and TTS voice diagnostics.
 */

import { View } from '../services/router';
import { ApiClient } from '../services/api-client';
import { getTTSService } from '../services/tts-service';

export class SettingsView implements View {
  private tts = getTTSService();
  private unsubVoiceChanged: (() => void) | null = null;
  private containerRef: HTMLElement | null = null;

  constructor(private api: ApiClient) {}

  render(): HTMLElement {
    const container = document.createElement('div');
    this.containerRef = container;
    container.innerHTML = `
      <div class="view-header">
        <h2>Settings</h2>
        <p>Configure your learning experience</p>
      </div>

      <div class="settings-section">
        <h3>Text-to-Speech Diagnostics</h3>
        <div class="card" id="tts-diagnostics">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
            <span class="status-dot" id="tts-status-dot"></span>
            <span id="tts-status-text" style="font-weight: 600;">Checking TTS...</span>
          </div>
          <div id="tts-details" style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.8;"></div>

          <div style="margin-top: 16px; display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-secondary" id="tts-refresh-btn">Refresh Voices</button>
            <button class="btn btn-secondary" id="tts-test-btn">Test Arabic TTS</button>
            <button class="btn btn-secondary" id="tts-sapi-btn">Query Windows Voices</button>
            <button class="btn btn-secondary" id="tts-caps-btn">Check Language Packs</button>
            <button class="btn btn-secondary" id="tts-reset-sapi-btn">Reset SAPI Fallback</button>
          </div>

          <div id="tts-test-result" style="margin-top: 12px; display: none;"></div>

          <div id="tts-voice-list" style="margin-top: 16px;"></div>
          <div id="tts-sapi-result" style="margin-top: 16px;"></div>
          <div id="tts-caps-result" style="margin-top: 16px;"></div>
        </div>
      </div>

      <div class="settings-section">
        <h3>Backend Status</h3>
        <div class="card" id="backend-info">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <span class="status-dot" id="settings-status-dot"></span>
            <span id="settings-status-text" style="font-weight: 600;">Checking...</span>
          </div>
          <div id="settings-status-details" style="color: var(--text-secondary); font-size: 0.9rem;"></div>
        </div>
      </div>

      <div class="settings-section">
        <h3>Application Architecture</h3>
        <div class="card">
          <p style="color: var(--text-secondary); line-height: 1.8; font-size: 0.9rem;">
            This application uses a <strong style="color: var(--text-primary);">multi-process architecture</strong>:
          </p>
          <ul style="color: var(--text-secondary); margin: 16px 0 0 20px; line-height: 2; font-size: 0.9rem;">
            <li><strong style="color: var(--accent-primary);">Main Process</strong> (Electron/TypeScript) &mdash; Window management, system integration, IPC</li>
            <li><strong style="color: var(--accent-info);">Renderer Process</strong> (TypeScript/HTML/CSS) &mdash; User interface, sandboxed browser context</li>
            <li><strong style="color: var(--accent-success);">Backend Service</strong> (C# .NET / Embedded TS) &mdash; API, business logic, data persistence</li>
            <li><strong style="color: var(--accent-warning);">Preload Bridge</strong> (TypeScript) &mdash; Secure IPC between renderer and main process</li>
          </ul>
        </div>
      </div>

      <div class="settings-section">
        <h3>About</h3>
        <div class="card">
          <div style="display: flex; justify-content: space-between; padding: 4px 0;">
            <span style="color: var(--text-secondary);">Version</span>
            <span id="app-version">--</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;">
            <span style="color: var(--text-secondary);">Electron</span>
            <span id="info-electron">--</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;">
            <span style="color: var(--text-secondary);">Chrome</span>
            <span id="info-chrome">--</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;">
            <span style="color: var(--text-secondary);">Node.js</span>
            <span id="info-node">--</span>
          </div>
        </div>
      </div>
    `;

    this.loadStatus(container);
    this.loadTTSDiagnostics(container);
    this.attachTTSHandlers(container);

    // Auto-refresh diagnostics when voices change
    this.unsubVoiceChanged = this.tts.onVoiceChanged(() => {
      this.loadTTSDiagnostics(container);
    });

    return container;
  }

  destroy(): void {
    this.tts.stop();
    if (this.unsubVoiceChanged) {
      this.unsubVoiceChanged();
      this.unsubVoiceChanged = null;
    }
    this.containerRef = null;
  }

  private loadTTSDiagnostics(container: HTMLElement): void {
    const diag = this.tts.getDiagnostics();

    const dot = container.querySelector('#tts-status-dot') as HTMLElement;
    const text = container.querySelector('#tts-status-text') as HTMLElement;
    const details = container.querySelector('#tts-details') as HTMLElement;
    if (!dot || !text || !details) return;

    // Remove any existing classes
    dot.classList.remove('connected', 'error', 'warning');

    if (diag.usingSapiFallback) {
      dot.classList.add('connected');
      text.textContent = 'Using Windows SAPI (Fallback)';
      text.style.color = 'var(--accent-info, var(--accent-success))';
    } else if (diag.selectedArabicVoice) {
      dot.classList.add('connected');
      text.textContent = 'Arabic Voice Available';
      text.style.color = 'var(--accent-success)';
    } else if (diag.totalVoices > 0) {
      dot.classList.add('warning');
      text.textContent = 'No Arabic Voice Found';
      text.style.color = 'var(--accent-warning)';
    } else if (!diag.available) {
      dot.classList.add('error');
      text.textContent = 'TTS Not Available';
      text.style.color = 'var(--accent-primary)';
    } else {
      dot.classList.add('error');
      text.textContent = 'No Voices Loaded';
      text.style.color = 'var(--accent-primary)';
    }

    const selectedName = diag.selectedArabicVoice
      ? `<strong style="color: var(--accent-success);">${diag.selectedArabicVoice.name}</strong> (${diag.selectedArabicVoice.lang})`
      : '<span style="color: var(--accent-primary);">None</span>';

    const fallbackName = diag.fallbackVoice
      ? `${diag.fallbackVoice.name} (${diag.fallbackVoice.lang})`
      : 'None';

    details.innerHTML = `
      <div style="display: grid; grid-template-columns: auto 1fr; gap: 4px 16px;">
        <span>Speech API:</span>
        <span>${diag.available ? 'Available' : 'Not Available'}</span>
        <span>Voices loaded:</span>
        <span>${diag.voicesLoaded ? 'Yes' : 'No'} (${diag.totalVoices} total)</span>
        <span>Arabic voices:</span>
        <span>${diag.arabicVoices.length} found</span>
        <span>Selected voice:</span>
        <span>${selectedName}</span>
        <span>Fallback voice:</span>
        <span>${fallbackName}</span>
        <span>Poll attempts:</span>
        <span>${diag.pollingAttempts}</span>
        <span>SAPI fallback:</span>
        <span>${diag.usingSapiFallback ? '<strong style="color: var(--accent-info, #4fc3f7);">Active</strong>' : 'Off'} (${diag.webSpeechFailures} Web Speech failures)</span>
      </div>
    `;

    // Show Arabic voice list if any found
    if (diag.arabicVoices.length > 0) {
      const listEl = container.querySelector('#tts-voice-list') as HTMLElement;
      if (listEl) {
        listEl.innerHTML = `
          <h4 style="margin: 0 0 8px; color: var(--text-primary); font-size: 0.85rem;">Arabic Voices Detected</h4>
          <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.8rem; line-height: 1.6;">
            ${diag.arabicVoices.map(v => `
              <div style="color: var(--accent-success);">
                ${v.name} | lang=${v.lang} | local=${v.localService} | uri=${v.voiceURI}
              </div>
            `).join('')}
          </div>
        `;
      }
    }
  }

  private attachTTSHandlers(container: HTMLElement): void {
    // Refresh voices button
    container.querySelector('#tts-refresh-btn')?.addEventListener('click', () => {
      this.tts.reloadVoices();
      // Refresh display after a short delay to let polling start
      setTimeout(() => this.loadTTSDiagnostics(container), 1000);
      setTimeout(() => this.loadTTSDiagnostics(container), 3000);
      setTimeout(() => this.loadTTSDiagnostics(container), 6000);
    });

    // Test Arabic TTS button
    container.querySelector('#tts-test-btn')?.addEventListener('click', () => {
      const resultEl = container.querySelector('#tts-test-result') as HTMLElement;
      if (!resultEl) return;

      resultEl.style.display = 'block';
      resultEl.innerHTML = '<span style="color: var(--accent-info);">Speaking test phrase...</span>';

      this.tts.speak('بِسْمِ اللَّهِ الرَّحْمَٰنِ الرَّحِيمِ', (state) => {
        if (state === 'playing') {
          resultEl.innerHTML = '<span style="color: var(--accent-success);">Playing: "Bismillah ir-Rahman ir-Raheem"</span>';
        } else if (state === 'error') {
          resultEl.innerHTML = '<span style="color: var(--accent-primary);">Error: TTS failed to play. Check the diagnostics above and ensure Arabic voice packs are installed.</span>';
        } else if (state === 'idle') {
          resultEl.innerHTML = '<span style="color: var(--accent-success);">Test completed successfully.</span>';
        }
      });
    });

    // Query Windows SAPI voices button
    container.querySelector('#tts-sapi-btn')?.addEventListener('click', async () => {
      const resultEl = container.querySelector('#tts-sapi-result') as HTMLElement;
      if (!resultEl) return;

      resultEl.innerHTML = '<span style="color: var(--text-muted);">Querying Windows SAPI voices via PowerShell...</span>';

      try {
        const result = await window.electronAPI.getSystemVoices();
        const data = result as Record<string, unknown>;

        if (data.error) {
          resultEl.innerHTML = `
            <h4 style="margin: 0 0 8px; color: var(--text-primary); font-size: 0.85rem;">Windows SAPI Voice Query</h4>
            <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.8rem; color: var(--accent-primary);">
              Error: ${data.error}
              ${data.raw ? `<br><br>Raw output: ${data.raw}` : ''}
            </div>
          `;
          return;
        }

        const voices = (data.voices || []) as Array<Record<string, string>>;
        const sapiVoices = (data.sapiVoices || []) as Array<Record<string, string>>;
        const oneCoreVoices = (data.oneCoreVoices || []) as Array<Record<string, string>>;
        const source = data.source as string;

        let voiceHtml = '';

        if (source === 'sapi' && voices.length > 0) {
          const arabicSapi = voices.filter(v => (v.Culture || '').startsWith('ar'));
          voiceHtml = `
            <div style="margin-bottom: 8px; color: var(--text-secondary);">Source: System.Speech (SAPI) &mdash; ${voices.length} voice(s), ${arabicSapi.length} Arabic</div>
            ${voices.map(v => {
              const isArabic = (v.Culture || '').startsWith('ar');
              return `<div style="color: ${isArabic ? 'var(--accent-success)' : 'var(--text-muted)'};">
                ${isArabic ? '>> ' : '   '}${v.Name} | ${v.Culture} | ${v.Gender} | ${v.Age}
                ${v.Description ? ` | ${v.Description}` : ''}
              </div>`;
            }).join('')}
          `;
        } else if (source === 'onecore-fallback') {
          voiceHtml = `
            <div style="margin-bottom: 8px; color: var(--text-secondary);">Source: OneCore Registry + SAPI COM</div>
            ${sapiVoices.length > 0 ? `
              <div style="margin-top: 8px; color: var(--accent-info);">SAPI COM Voices (${sapiVoices.length}):</div>
              ${(sapiVoices as Array<Record<string, string>>).map(v => `<div style="color: var(--text-muted);">   ${v.Name}</div>`).join('')}
            ` : '<div style="color: var(--text-muted);">No SAPI COM voices found</div>'}
            ${oneCoreVoices.length > 0 ? `
              <div style="margin-top: 8px; color: var(--accent-info);">OneCore Registry Voices (${oneCoreVoices.length}):</div>
              ${(oneCoreVoices as Array<Record<string, string>>).map(v => `<div style="color: var(--text-muted);">   ${v.Name} | lang=${v.Lang}</div>`).join('')}
            ` : '<div style="color: var(--text-muted);">No OneCore registry voices found</div>'}
          `;
        } else {
          voiceHtml = '<div style="color: var(--text-muted);">No voices returned from query</div>';
        }

        resultEl.innerHTML = `
          <h4 style="margin: 0 0 8px; color: var(--text-primary); font-size: 0.85rem;">Windows Voice Query Results</h4>
          <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.8rem; line-height: 1.6; max-height: 300px; overflow-y: auto;">
            ${voiceHtml}
          </div>
        `;
      } catch (err) {
        resultEl.innerHTML = `
          <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; color: var(--accent-primary); font-size: 0.85rem;">
            Failed to query system voices: ${err instanceof Error ? err.message : 'Unknown error'}
          </div>
        `;
      }
    });

    // Reset SAPI fallback button
    container.querySelector('#tts-reset-sapi-btn')?.addEventListener('click', () => {
      this.tts.resetSapiFallback();
      this.loadTTSDiagnostics(container);
    });

    // Check language capabilities button
    container.querySelector('#tts-caps-btn')?.addEventListener('click', async () => {
      const resultEl = container.querySelector('#tts-caps-result') as HTMLElement;
      if (!resultEl) return;

      resultEl.innerHTML = '<span style="color: var(--text-muted);">Checking Windows language capabilities...</span>';

      try {
        const result = await window.electronAPI.checkArabicCapabilities();
        const data = result as Record<string, unknown>;

        if (data.error) {
          resultEl.innerHTML = `
            <h4 style="margin: 0 0 8px; color: var(--text-primary); font-size: 0.85rem;">Windows Language Capabilities</h4>
            <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.8rem; color: var(--accent-primary);">
              Error: ${data.error}
            </div>
          `;
          return;
        }

        const caps = (data.capabilities || []) as Array<{ Name: string; State: string }>;

        resultEl.innerHTML = `
          <h4 style="margin: 0 0 8px; color: var(--text-primary); font-size: 0.85rem;">Windows Arabic Language Capabilities</h4>
          <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.8rem; line-height: 1.6;">
            ${caps.length > 0 ? caps.map(c => {
              const installed = c.State === 'Installed';
              return `<div style="color: ${installed ? 'var(--accent-success)' : 'var(--accent-warning)'};">
                ${installed ? '[INSTALLED]' : '[MISSING]  '} ${c.Name}
              </div>`;
            }).join('') : '<div style="color: var(--accent-primary);">No Arabic capabilities found. Run these in PowerShell as Administrator:<br><br>Add-WindowsCapability -Online -Name "Language.Basic~~~ar-SA~0.0.1.0"<br>Add-WindowsCapability -Online -Name "Language.TextToSpeech~~~ar-SA~0.0.1.0"</div>'}
          </div>
        `;
      } catch (err) {
        resultEl.innerHTML = `
          <div style="background: var(--bg-tertiary); border-radius: 6px; padding: 12px; color: var(--accent-primary); font-size: 0.85rem;">
            Failed to check capabilities: ${err instanceof Error ? err.message : 'Unknown error'}
          </div>
        `;
      }
    });
  }

  private async loadStatus(container: HTMLElement): Promise<void> {
    try {
      const status = await this.api.getStatus();
      const version = await window.electronAPI.getVersion();
      const sysInfo = await window.electronAPI.getSystemInfo();

      const dot = container.querySelector('#settings-status-dot') as HTMLElement;
      const text = container.querySelector('#settings-status-text') as HTMLElement;
      const details = container.querySelector('#settings-status-details') as HTMLElement;
      const versionEl = container.querySelector('#app-version') as HTMLElement;

      if (status.running) {
        dot.classList.add('connected');
        text.textContent = 'Backend Running';
        text.style.color = 'var(--accent-success)';
      } else {
        dot.classList.add('error');
        text.textContent = 'Backend Offline';
        text.style.color = 'var(--accent-primary)';
      }

      details.innerHTML = `
        Mode: <strong>${status.mode === 'dotnet' ? 'C# .NET Backend' : 'Embedded TypeScript Service'}</strong><br>
        Port: <strong>${status.port}</strong><br>
        URL: <strong>${status.url}</strong>
      `;

      if (versionEl) versionEl.textContent = version;

      const elElectron = container.querySelector('#info-electron');
      const elChrome = container.querySelector('#info-chrome');
      const elNode = container.querySelector('#info-node');
      if (elElectron) elElectron.textContent = sysInfo.electron;
      if (elChrome) elChrome.textContent = sysInfo.chrome;
      if (elNode) elNode.textContent = sysInfo.node;
    } catch {
      console.error('Failed to load backend status');
    }
  }
}

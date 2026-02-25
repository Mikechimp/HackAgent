/**
 * Text-to-Speech Service
 *
 * Provides Arabic pronunciation audio using the Web Speech API (SpeechSynthesis).
 * Chromium (Electron's rendering engine) supports the SpeechSynthesis API natively.
 *
 * Known issues addressed:
 *   - Chromium bug: speechSynthesis can silently pause after ~15s; workaround via resume() timer
 *   - No Arabic voice: onstart never fires; workaround via timeout + error fallback
 *   - Some systems have no voices at all; detected and reported as error immediately
 *   - Windows OneCore voices may take time to register with Chromium; extended polling
 *   - Name-based matching for known Windows Arabic voices (Naayf, Hoda, etc.)
 *
 * States:
 *   - idle: No audio playing
 *   - loading: Voice is being prepared
 *   - playing: Audio is currently playing
 *   - error: TTS not available or failed
 */

export type TTSState = 'idle' | 'loading' | 'playing' | 'error';

export type TTSStateCallback = (state: TTSState) => void;

/** Callback fired when TTS reaches a new word boundary */
export type TTSWordBoundaryCallback = (charIndex: number, charLength: number) => void;

/** Diagnostic information about a single voice */
export interface VoiceDiagnostic {
  name: string;
  lang: string;
  localService: boolean;
  default: boolean;
  voiceURI: string;
}

/** Overall TTS diagnostic report */
export interface TTSDiagnostics {
  available: boolean;
  voicesLoaded: boolean;
  totalVoices: number;
  allVoices: VoiceDiagnostic[];
  arabicVoices: VoiceDiagnostic[];
  selectedArabicVoice: VoiceDiagnostic | null;
  fallbackVoice: VoiceDiagnostic | null;
  pollingAttempts: number;
  lastLoadTime: number | null;
  usingSapiFallback: boolean;
  webSpeechFailures: number;
}

/** Known Windows Arabic TTS voice name fragments */
const KNOWN_ARABIC_VOICE_NAMES = [
  'naayf',   // Microsoft Naayf - ar-SA
  'hoda',    // Microsoft Hoda - ar-EG
  'fadil',   // Microsoft Fadil - ar-SA (newer)
];

export class TTSService {
  private synth: SpeechSynthesis;
  private arabicVoice: SpeechSynthesisVoice | null = null;
  private fallbackVoice: SpeechSynthesisVoice | null = null;
  private voicesLoaded = false;
  private currentUtterance: SpeechSynthesisUtterance | null = null;
  private startTimeout: ReturnType<typeof setTimeout> | null = null;
  private resumeInterval: ReturnType<typeof setInterval> | null = null;
  private pendingSpeak: ReturnType<typeof setTimeout> | null = null;
  private pollingAttempts = 0;
  private lastLoadTime: number | null = null;
  private voiceChangedListeners: Array<() => void> = [];
  /** Whether SAPI fallback is being used because Web Speech API failed */
  private useSapiFallback = false;
  /** Track consecutive Web Speech API failures to auto-switch to SAPI */
  private webSpeechFailures = 0;

  constructor() {
    this.synth = window.speechSynthesis;
    this.loadVoices();

    // Voices may load asynchronously in Chromium
    if (this.synth.onvoiceschanged !== undefined) {
      this.synth.addEventListener('voiceschanged', () => {
        console.log('[TTS] voiceschanged event fired');
        this.loadVoices();
        this.notifyVoiceChanged();
      });
    }

    // Some Chromium builds never fire voiceschanged — poll as a fallback.
    // Extended to 40 attempts over 20 seconds for Windows OneCore voices
    // that may take longer to register.
    if (!this.voicesLoaded) {
      const poll = setInterval(() => {
        this.pollingAttempts++;
        this.loadVoices();
        if (this.voicesLoaded || this.pollingAttempts >= 40) {
          clearInterval(poll);
          if (this.voicesLoaded) {
            console.log(`[TTS] Voices discovered via polling after ${this.pollingAttempts} attempts`);
          } else {
            console.warn('[TTS] Voice polling exhausted (40 attempts / 20s) — no voices found');
          }
        }
      }, 500);
    }
  }

  private loadVoices(): void {
    const voices = this.synth.getVoices();
    if (voices.length === 0) return;

    this.voicesLoaded = true;
    this.lastLoadTime = Date.now();

    // Log all voices for diagnostics
    console.log(`[TTS] Loaded ${voices.length} voice(s):`);
    for (const v of voices) {
      const isArabic = v.lang.startsWith('ar') || this.isKnownArabicVoice(v);
      if (isArabic) {
        console.log(`[TTS]   >> ARABIC: "${v.name}" lang=${v.lang} local=${v.localService} uri=${v.voiceURI}`);
      }
    }

    // Look for Arabic voices: ar-SA, ar-EG, ar-*, or any Arabic variant
    const arabicVoices = voices.filter(v => v.lang.startsWith('ar'));

    // Also check by known voice names (catches voices with incorrect lang tags)
    const nameMatchedVoices = voices.filter(v =>
      !v.lang.startsWith('ar') && this.isKnownArabicVoice(v)
    );

    if (nameMatchedVoices.length > 0) {
      console.log(`[TTS] Found ${nameMatchedVoices.length} Arabic voice(s) by name matching that weren't tagged with ar-* lang`);
    }

    const allArabicVoices = [...arabicVoices, ...nameMatchedVoices];

    if (allArabicVoices.length > 0) {
      // Priority: ar-SA > ar-EG > any ar-* > name-matched
      this.arabicVoice =
        allArabicVoices.find(v => v.lang === 'ar-SA') ||
        allArabicVoices.find(v => v.lang === 'ar-EG') ||
        arabicVoices[0] ||
        nameMatchedVoices[0];

      console.log(`[TTS] Selected Arabic voice: "${this.arabicVoice!.name}" lang=${this.arabicVoice!.lang}`);
    } else {
      console.warn('[TTS] No Arabic voices found among', voices.length, 'voices');
    }

    // Pick a fallback voice (any voice that works) for when Arabic isn't available
    // Google voices tend to handle Arabic script better even if tagged as en-US
    if (!this.arabicVoice) {
      this.fallbackVoice =
        voices.find(v => v.name.includes('Google') && v.lang.startsWith('en')) ||
        voices.find(v => v.default) ||
        voices[0] || null;

      if (this.fallbackVoice) {
        console.log(`[TTS] Using fallback voice: "${this.fallbackVoice.name}" lang=${this.fallbackVoice.lang}`);
      }
    }
  }

  /** Check if a voice matches a known Arabic TTS voice by name */
  private isKnownArabicVoice(voice: SpeechSynthesisVoice): boolean {
    const nameLower = voice.name.toLowerCase();
    return KNOWN_ARABIC_VOICE_NAMES.some(known => nameLower.includes(known));
  }

  /** Whether TTS is available in this environment */
  get isAvailable(): boolean {
    return 'speechSynthesis' in window;
  }

  /** Whether a dedicated Arabic voice was found */
  get hasArabicVoice(): boolean {
    return this.arabicVoice !== null;
  }

  /** Force a fresh reload of voices (useful after installing language packs) */
  reloadVoices(): void {
    console.log('[TTS] Manual voice reload requested');
    this.arabicVoice = null;
    this.fallbackVoice = null;
    this.voicesLoaded = false;

    // Some Chromium builds cache getVoices() — try to bust the cache
    // by cancelling any speech and re-querying
    this.synth.cancel();

    // Attempt immediate load
    this.loadVoices();

    // If that didn't work, poll again
    if (!this.voicesLoaded) {
      let attempts = 0;
      const poll = setInterval(() => {
        attempts++;
        this.loadVoices();
        if (this.voicesLoaded || attempts >= 10) {
          clearInterval(poll);
          this.notifyVoiceChanged();
        }
      }, 500);
    } else {
      this.notifyVoiceChanged();
    }
  }

  /** Subscribe to voice availability changes */
  onVoiceChanged(callback: () => void): () => void {
    this.voiceChangedListeners.push(callback);
    return () => {
      this.voiceChangedListeners = this.voiceChangedListeners.filter(cb => cb !== callback);
    };
  }

  private notifyVoiceChanged(): void {
    for (const cb of this.voiceChangedListeners) {
      try { cb(); } catch (e) { console.error('[TTS] Voice change listener error:', e); }
    }
  }

  /** Whether TTS is using SAPI fallback instead of Web Speech API */
  get isSapiFallback(): boolean {
    return this.useSapiFallback;
  }

  /** Reset SAPI fallback state to try Web Speech API again */
  resetSapiFallback(): void {
    this.useSapiFallback = false;
    this.webSpeechFailures = 0;
    console.log('[TTS] SAPI fallback reset — will try Web Speech API again');
  }

  /** Get detailed diagnostics about TTS state */
  getDiagnostics(): TTSDiagnostics {
    const voices = this.synth.getVoices();
    const allVoices = voices.map(v => this.voiceToDiagnostic(v));
    const arabicVoices = voices
      .filter(v => v.lang.startsWith('ar') || this.isKnownArabicVoice(v))
      .map(v => this.voiceToDiagnostic(v));

    return {
      available: this.isAvailable,
      voicesLoaded: this.voicesLoaded,
      totalVoices: voices.length,
      allVoices,
      arabicVoices,
      selectedArabicVoice: this.arabicVoice ? this.voiceToDiagnostic(this.arabicVoice) : null,
      fallbackVoice: this.fallbackVoice ? this.voiceToDiagnostic(this.fallbackVoice) : null,
      pollingAttempts: this.pollingAttempts,
      lastLoadTime: this.lastLoadTime,
      usingSapiFallback: this.useSapiFallback,
      webSpeechFailures: this.webSpeechFailures,
    };
  }

  private voiceToDiagnostic(v: SpeechSynthesisVoice): VoiceDiagnostic {
    return {
      name: v.name,
      lang: v.lang,
      localService: v.localService,
      default: v.default,
      voiceURI: v.voiceURI,
    };
  }

  private clearTimers(): void {
    if (this.startTimeout) {
      clearTimeout(this.startTimeout);
      this.startTimeout = null;
    }
    if (this.resumeInterval) {
      clearInterval(this.resumeInterval);
      this.resumeInterval = null;
    }
    if (this.pendingSpeak) {
      clearTimeout(this.pendingSpeak);
      this.pendingSpeak = null;
    }
  }

  /** Stop any current playback */
  stop(): void {
    this.clearTimers();
    if (this.synth.speaking || this.synth.pending) {
      this.synth.cancel();
    }
    this.currentUtterance = null;
  }

  /**
   * Speak the given Arabic text.
   *
   * Uses Web Speech API first. If it fails (common on Windows), automatically
   * falls back to Windows SAPI via the main process IPC bridge.
   *
   * @param text Arabic text to pronounce
   * @param onStateChange Callback for state changes (loading, playing, idle, error)
   */
  speak(text: string, onStateChange?: TTSStateCallback): void {
    if (!this.isAvailable && !this.hasSapiAccess()) {
      onStateChange?.('error');
      return;
    }

    // Stop any current playback
    this.stop();
    onStateChange?.('loading');

    // If SAPI fallback is active (previous Web Speech failures), go straight to SAPI
    if (this.useSapiFallback) {
      this.speakViaSapi(text, onStateChange);
      return;
    }

    // Ensure voices are loaded
    if (!this.voicesLoaded) {
      const voices = this.synth.getVoices();
      if (voices.length > 0) {
        this.loadVoices();
      }
    }

    const voice = this.arabicVoice || this.fallbackVoice;

    // If no voices at all and we have SAPI access, go straight to SAPI
    if (!voice && this.hasSapiAccess()) {
      console.log('[TTS] No Web Speech voices available, trying SAPI fallback');
      this.speakViaSapi(text, onStateChange);
      return;
    }

    // If no voices and no SAPI, fail immediately
    if (!voice) {
      console.warn('[TTS] No voices available and no SAPI fallback');
      onStateChange?.('error');
      return;
    }

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = 'ar-SA';
    utterance.rate = 0.85;
    utterance.pitch = 1.0;
    utterance.volume = 1.0;
    utterance.voice = voice;

    utterance.onstart = () => {
      // Clear the "stuck" timeout since speech started
      if (this.startTimeout) {
        clearTimeout(this.startTimeout);
        this.startTimeout = null;
      }
      // Reset failure counter on success
      this.webSpeechFailures = 0;
      onStateChange?.('playing');

      // Chromium bug workaround: speechSynthesis can silently pause after ~15s.
      // Periodically call resume() to keep it going.
      this.resumeInterval = setInterval(() => {
        if (this.synth.speaking && !this.synth.paused) {
          this.synth.pause();
          this.synth.resume();
        }
      }, 10000);
    };

    utterance.onend = () => {
      this.clearTimers();
      this.currentUtterance = null;
      onStateChange?.('idle');
    };

    utterance.onerror = (event) => {
      this.clearTimers();
      this.currentUtterance = null;
      // 'canceled' is not a real error — it happens when we call stop()
      if (event.error === 'canceled' || event.error === 'interrupted') {
        onStateChange?.('idle');
      } else {
        console.error('[TTS] Speech error:', event.error);
        // Try SAPI fallback on error
        if (this.hasSapiAccess()) {
          console.log('[TTS] Web Speech error, trying SAPI fallback');
          this.webSpeechFailures++;
          if (this.webSpeechFailures >= 2) {
            this.useSapiFallback = true;
            console.log('[TTS] Switching to SAPI fallback permanently (2+ consecutive failures)');
          }
          this.speakViaSapi(text, onStateChange);
        } else {
          onStateChange?.('error');
        }
      }
    };

    this.currentUtterance = utterance;

    // Chromium bug workaround: calling speak() immediately after cancel() can
    // silently drop the utterance. Delay slightly to let state settle.
    this.pendingSpeak = setTimeout(() => {
      this.pendingSpeak = null;
      // Chromium sometimes gets stuck in a paused state; resume before speaking
      this.synth.resume();
      this.synth.speak(utterance);
      // Another Chromium workaround: nudge the synth to start processing
      setTimeout(() => {
        if (this.synth.paused) {
          this.synth.resume();
        }
      }, 100);
    }, 150);

    // Safety timeout: if onstart doesn't fire within 2 seconds, try SAPI fallback.
    // Reduced from 5s for faster user feedback.
    this.startTimeout = setTimeout(() => {
      if (this.currentUtterance === utterance) {
        console.warn('[TTS] Speech start timeout (2s) — trying SAPI fallback');
        this.stop();
        this.webSpeechFailures++;
        if (this.webSpeechFailures >= 2) {
          this.useSapiFallback = true;
          console.log('[TTS] Switching to SAPI fallback permanently (2+ consecutive failures)');
        }
        if (this.hasSapiAccess()) {
          this.speakViaSapi(text, onStateChange);
        } else {
          // No SAPI — try one more time with Web Speech before giving up
          this.synth.cancel();
          setTimeout(() => {
            this.synth.speak(utterance);
            this.synth.resume();
            this.currentUtterance = utterance;
            this.startTimeout = setTimeout(() => {
              if (this.currentUtterance === utterance) {
                console.warn('[TTS] Speech retry also failed, no SAPI available');
                this.stop();
                onStateChange?.('error');
              }
            }, 2000);
          }, 100);
        }
      }
    }, 2000);
  }

  /** Check if we can access Windows SAPI via the Electron IPC bridge */
  private hasSapiAccess(): boolean {
    return typeof window !== 'undefined' &&
           typeof window.electronAPI !== 'undefined' &&
           typeof window.electronAPI.speakSapi === 'function';
  }

  /**
   * Speak via Windows SAPI through the main process.
   * This bypasses Chromium's Web Speech API entirely.
   */
  private speakViaSapi(text: string, onStateChange?: TTSStateCallback): void {
    console.log('[TTS] Speaking via SAPI fallback:', text.substring(0, 40) + (text.length > 40 ? '...' : ''));
    onStateChange?.('playing');

    window.electronAPI.speakSapi(text).then((result) => {
      if (result.success) {
        console.log(`[TTS] SAPI spoke successfully via ${result.method}`);
        onStateChange?.('idle');
      } else {
        console.error('[TTS] SAPI fallback failed:', result.error);
        onStateChange?.('error');
      }
    }).catch((err) => {
      console.error('[TTS] SAPI IPC error:', err);
      onStateChange?.('error');
    });
  }

  /**
   * Speak with word boundary tracking for synchronized highlighting.
   * Uses SpeechSynthesis onboundary events when available, with a
   * timer-based fallback that estimates word timing from text length.
   *
   * @param text Arabic text to speak
   * @param rate Speech rate (0.3 - 1.0)
   * @param onWordBoundary Called when TTS advances to a new word
   * @param onStateChange Called when playback state changes
   */
  speakWithTracking(
    text: string,
    rate: number,
    onWordBoundary: TTSWordBoundaryCallback,
    onStateChange?: TTSStateCallback,
  ): void {
    if (!this.isAvailable && !this.hasSapiAccess()) {
      onStateChange?.('error');
      return;
    }

    this.stop();
    onStateChange?.('loading');

    if (!this.voicesLoaded) {
      const voices = this.synth.getVoices();
      if (voices.length > 0) {
        this.loadVoices();
      }
    }

    const voice = this.arabicVoice || this.fallbackVoice;

    // Build word offset map (needed for both Web Speech and SAPI fallback)
    const words = text.split(/\s+/);
    const wordOffsets: { start: number; length: number }[] = [];
    let cursor = 0;
    for (const w of words) {
      const idx = text.indexOf(w, cursor);
      wordOffsets.push({ start: idx, length: w.length });
      cursor = idx + w.length;
    }

    // If SAPI fallback is active or no voices available, use SAPI with estimated timing
    if (this.useSapiFallback || (!voice && this.hasSapiAccess())) {
      console.log('[TTS] Using SAPI fallback for tracked speech');
      this.speakViaSapiWithTracking(text, rate, wordOffsets, onWordBoundary, onStateChange);
      return;
    }

    if (!voice) {
      console.warn('[TTS] No voices available for tracked speech');
      onStateChange?.('error');
      return;
    }

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = 'ar-SA';
    utterance.rate = Math.max(0.1, Math.min(rate, 1.0));
    utterance.pitch = 1.0;
    utterance.volume = 1.0;
    utterance.voice = voice;

    // Track whether real boundary events fire so we can fall back to estimation
    let boundaryFired = false;
    let fallbackTimer: ReturnType<typeof setTimeout> | null = null;
    let fallbackTimers: ReturnType<typeof setTimeout>[] = [];

    // Real boundary events from the speech engine
    utterance.onboundary = (event: SpeechSynthesisEvent) => {
      if (event.name === 'word') {
        boundaryFired = true;
        // Clear fallback timers since real events are working
        for (const t of fallbackTimers) clearTimeout(t);
        fallbackTimers = [];
        onWordBoundary(event.charIndex, event.charLength || 0);
      }
    };

    utterance.onstart = () => {
      if (this.startTimeout) {
        clearTimeout(this.startTimeout);
        this.startTimeout = null;
      }
      this.webSpeechFailures = 0;
      onStateChange?.('playing');

      // Fire the first word boundary immediately
      if (wordOffsets.length > 0) {
        onWordBoundary(wordOffsets[0].start, wordOffsets[0].length);
      }

      // Start fallback timer — if no boundary event fires within 500ms,
      // schedule estimated word timings for the rest of the passage.
      fallbackTimer = setTimeout(() => {
        if (boundaryFired) return; // Real events are working, no fallback needed

        // Estimate total speech duration from text length and rate.
        // Arabic TTS speaks roughly 4-6 chars/second at rate 1.0.
        const charsPerSecond = 5 * utterance.rate;
        const totalChars = text.replace(/\s+/g, '').length;
        const estimatedDurationMs = (totalChars / charsPerSecond) * 1000;
        const msPerChar = estimatedDurationMs / totalChars;

        for (let i = 1; i < wordOffsets.length; i++) {
          // Time to reach this word = cumulative char lengths of prior words
          const prevChars = wordOffsets.slice(0, i).reduce((sum, w) => sum + w.length, 0);
          const delay = prevChars * msPerChar;
          const wo = wordOffsets[i];
          const timer = setTimeout(() => {
            if (this.currentUtterance === utterance) {
              onWordBoundary(wo.start, wo.length);
            }
          }, delay);
          fallbackTimers.push(timer);
        }
      }, 500);

      // Chromium resume workaround
      this.resumeInterval = setInterval(() => {
        if (this.synth.speaking && !this.synth.paused) {
          this.synth.pause();
          this.synth.resume();
        }
      }, 10000);
    };

    utterance.onend = () => {
      if (fallbackTimer) clearTimeout(fallbackTimer);
      for (const t of fallbackTimers) clearTimeout(t);
      fallbackTimers = [];
      this.clearTimers();
      this.currentUtterance = null;
      onStateChange?.('idle');
    };

    utterance.onerror = (event) => {
      if (fallbackTimer) clearTimeout(fallbackTimer);
      for (const t of fallbackTimers) clearTimeout(t);
      fallbackTimers = [];
      this.clearTimers();
      this.currentUtterance = null;
      if (event.error === 'canceled' || event.error === 'interrupted') {
        onStateChange?.('idle');
      } else {
        console.error('[TTS] Speech error:', event.error);
        // Try SAPI fallback for tracked speech too
        if (this.hasSapiAccess()) {
          this.webSpeechFailures++;
          if (this.webSpeechFailures >= 2) this.useSapiFallback = true;
          this.speakViaSapiWithTracking(text, rate, wordOffsets, onWordBoundary, onStateChange);
        } else {
          onStateChange?.('error');
        }
      }
    };

    this.currentUtterance = utterance;

    this.pendingSpeak = setTimeout(() => {
      this.pendingSpeak = null;
      this.synth.resume();
      this.synth.speak(utterance);
      setTimeout(() => {
        if (this.synth.paused) {
          this.synth.resume();
        }
      }, 100);
    }, 150);

    // Reduced timeout: 2s instead of 5s for faster feedback
    this.startTimeout = setTimeout(() => {
      if (this.currentUtterance === utterance) {
        console.warn('[TTS] Tracked speech start timeout (2s)');
        this.stop();
        this.webSpeechFailures++;
        if (this.webSpeechFailures >= 2) this.useSapiFallback = true;
        if (this.hasSapiAccess()) {
          this.speakViaSapiWithTracking(text, rate, wordOffsets, onWordBoundary, onStateChange);
        } else {
          // Fallback: retry Web Speech once more
          if (fallbackTimer) clearTimeout(fallbackTimer);
          for (const t of fallbackTimers) clearTimeout(t);
          fallbackTimers = [];
          this.synth.cancel();
          setTimeout(() => {
            this.synth.speak(utterance);
            this.synth.resume();
            this.currentUtterance = utterance;
            this.startTimeout = setTimeout(() => {
              if (this.currentUtterance === utterance) {
                this.stop();
                onStateChange?.('error');
              }
            }, 2000);
          }, 100);
        }
      }
    }, 2000);
  }

  /**
   * SAPI fallback for tracked speech. Uses estimated word timing since
   * SAPI speaks synchronously in the main process.
   */
  private speakViaSapiWithTracking(
    text: string,
    rate: number,
    wordOffsets: { start: number; length: number }[],
    onWordBoundary: TTSWordBoundaryCallback,
    onStateChange?: TTSStateCallback,
  ): void {
    onStateChange?.('playing');

    // Fire first word immediately
    if (wordOffsets.length > 0) {
      onWordBoundary(wordOffsets[0].start, wordOffsets[0].length);
    }

    // Estimate word timings and schedule boundary callbacks
    const charsPerSecond = 5 * Math.max(0.1, Math.min(rate, 1.0));
    const totalChars = text.replace(/\s+/g, '').length;
    const estimatedDurationMs = (totalChars / charsPerSecond) * 1000;
    const msPerChar = totalChars > 0 ? estimatedDurationMs / totalChars : 200;

    const timers: ReturnType<typeof setTimeout>[] = [];
    for (let i = 1; i < wordOffsets.length; i++) {
      const prevChars = wordOffsets.slice(0, i).reduce((sum, w) => sum + w.length, 0);
      const delay = prevChars * msPerChar;
      const wo = wordOffsets[i];
      timers.push(setTimeout(() => onWordBoundary(wo.start, wo.length), delay));
    }

    window.electronAPI.speakSapi(text).then((result) => {
      for (const t of timers) clearTimeout(t);
      if (result.success) {
        onStateChange?.('idle');
      } else {
        console.error('[TTS] SAPI tracked fallback failed:', result.error);
        onStateChange?.('error');
      }
    }).catch((err) => {
      for (const t of timers) clearTimeout(t);
      console.error('[TTS] SAPI IPC error:', err);
      onStateChange?.('error');
    });
  }
}

/** Singleton TTS instance shared across views */
let _instance: TTSService | null = null;

export function getTTSService(): TTSService {
  if (!_instance) {
    _instance = new TTSService();
  }
  return _instance;
}

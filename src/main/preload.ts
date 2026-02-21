/**
 * HackAgent — Preload Script (Secure IPC Bridge)
 * Exposes a safe API to the renderer via contextBridge.
 */
import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('hackagent', {
  /** The backend API base URL (Express server on localhost) */
  getApiBase: (): string => 'http://localhost:5175',

  /** Platform info */
  platform: process.platform,

  /** App version from package.json */
  version: '1.0.0',
});

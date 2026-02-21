/**
 * HackAgent — Backend Manager
 * Spawns and manages the Express.js backend server as a child process,
 * following the same pattern as spawning a .NET backend in VS Code-style apps.
 */
import { fork, ChildProcess } from 'child_process';
import * as path from 'path';
import * as http from 'http';

export class BackendManager {
  private process: ChildProcess | null = null;
  private port: number;
  private ready: boolean = false;

  constructor(port: number) {
    this.port = port;
  }

  async start(): Promise<void> {
    const serverPath = path.join(__dirname, '..', 'backend', 'server.js');

    console.log(`[BackendManager] Starting backend on port ${this.port}...`);

    this.process = fork(serverPath, [], {
      env: {
        ...process.env,
        HACKAGENT_PORT: String(this.port),
        NODE_ENV: 'production',
      },
      stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
    });

    this.process.stdout?.on('data', (data: Buffer) => {
      console.log(`[Backend] ${data.toString().trim()}`);
    });

    this.process.stderr?.on('data', (data: Buffer) => {
      console.error(`[Backend:err] ${data.toString().trim()}`);
    });

    this.process.on('exit', (code: number | null) => {
      console.log(`[BackendManager] Backend exited with code ${code}`);
      this.ready = false;
    });

    // Wait for the server to be ready
    await this.waitForReady();
  }

  stop(): void {
    if (this.process) {
      console.log('[BackendManager] Stopping backend...');
      this.process.kill('SIGTERM');
      this.process = null;
      this.ready = false;
    }
  }

  isReady(): boolean {
    return this.ready;
  }

  private async waitForReady(timeoutMs: number = 10000): Promise<void> {
    const start = Date.now();
    const interval = 200;

    while (Date.now() - start < timeoutMs) {
      try {
        await this.ping();
        this.ready = true;
        console.log(`[BackendManager] Backend ready on port ${this.port}`);
        return;
      } catch {
        await new Promise(resolve => setTimeout(resolve, interval));
      }
    }

    console.warn('[BackendManager] Backend did not start in time, continuing anyway');
  }

  private ping(): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = http.get(`http://localhost:${this.port}/api/status`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else {
          reject(new Error(`Status ${res.statusCode}`));
        }
        res.resume();
      });
      req.on('error', reject);
      req.setTimeout(1000, () => {
        req.destroy();
        reject(new Error('timeout'));
      });
    });
  }
}

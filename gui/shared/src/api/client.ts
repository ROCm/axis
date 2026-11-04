// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// REST + WebSocket client for the AXIS gateway.

const GATEWAY_BASE =
  (window as any).AXIS_CONFIG?.gateway_url ?? "http://127.0.0.1:18520";
const WS_BASE = GATEWAY_BASE.replace(/^http/, "ws");
// axisd rejects gateway requests without the per-user token the native shell injects.
const TOKEN: string = (window as any).AXIS_CONFIG?.token ?? "";
// Browsers cannot set headers on WebSockets, so the token rides in a subprotocol.
const WS_PROTOCOLS = ["axis.v1", `axis-token.${TOKEN}`];

// ── REST API ────────────────────────────────────────────────────────────

export interface Sandbox {
  id: string;
  status: string;
  policy_name: string;
  pid: number | null;
  workspace_dir: string;
}

export interface Agent {
  name: string;
  installed: boolean;
}

export interface HealthResponse {
  status: string;
  version: string;
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3000);

  try {
    const resp = await fetch(`${GATEWAY_BASE}${path}`, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${TOKEN}`,
      },
      signal: controller.signal,
      ...init,
    });
    clearTimeout(timeout);
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`${resp.status}: ${body}`);
    }
    return resp.json();
  } catch (e: any) {
    clearTimeout(timeout);
    if (e.name === "AbortError") {
      throw new Error("Cannot connect to AXIS daemon. Start axisd first.");
    }
    throw new Error(`Connection failed: ${e.message}`);
  }
}

export async function getHealth(): Promise<HealthResponse> {
  return fetchJson("/api/v1/health");
}

export async function listSandboxes(): Promise<Sandbox[]> {
  const data = await fetchJson<{ sandboxes: Sandbox[] }>("/api/v1/sandboxes");
  return data.sandboxes;
}

export async function createSandbox(policy: string, command: string[]): Promise<string> {
  const data = await fetchJson<{ sandbox_id: string }>("/api/v1/sandboxes", {
    method: "POST",
    body: JSON.stringify({ policy, command }),
  });
  return data.sandbox_id;
}

export async function destroySandbox(id: string): Promise<void> {
  await fetchJson(`/api/v1/sandboxes/${id}`, { method: "DELETE" });
}

export async function listAgents(): Promise<Agent[]> {
  const data = await fetchJson<{ agents: Agent[] }>("/api/v1/agents");
  return data.agents;
}

export async function runAgent(name: string): Promise<string> {
  const data = await fetchJson<{ sandbox_id: string }>(`/api/v1/agents/${name}/run`, {
    method: "POST",
  });
  return data.sandbox_id;
}

// ── WebSocket: Event Stream ─────────────────────────────────────────────

export interface AuditEvent {
  id: string;
  timestamp: string;
  category: string;
  severity: string;
  sandbox_id: string | null;
  message: string;
  details: any;
}

export type EventCallback = (event: AuditEvent) => void;

export function subscribeEvents(onEvent: EventCallback): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/v1/events`, WS_PROTOCOLS);
  ws.onmessage = (msg) => {
    try {
      const event: AuditEvent = JSON.parse(msg.data);
      onEvent(event);
    } catch {
      // Skip malformed messages.
    }
  };
  ws.onerror = () => {
    console.warn("AXIS event WebSocket error — will reconnect");
  };
  return ws;
}

// ── WebSocket: PTY Stream ───────────────────────────────────────────────

export interface PtyConnection {
  ws: WebSocket;
  send(data: string): void;
  resize(cols: number, rows: number): void;
  close(): void;
}

export function connectPty(sandboxId: string): PtyConnection {
  const ws = new WebSocket(`${WS_BASE}/ws/v1/sandboxes/${sandboxId}/pty`, WS_PROTOCOLS);
  ws.binaryType = "arraybuffer";

  return {
    ws,
    send(data: string) {
      if (ws.readyState === WebSocket.OPEN) {
        // Frame type 0x00 = data
        const encoder = new TextEncoder();
        const payload = encoder.encode(data);
        const frame = new Uint8Array(1 + payload.length);
        frame[0] = 0x00;
        frame.set(payload, 1);
        ws.send(frame.buffer);
      }
    },
    resize(cols: number, rows: number) {
      if (ws.readyState === WebSocket.OPEN) {
        // Frame type 0x01 = resize
        const frame = new Uint8Array(5);
        frame[0] = 0x01;
        frame[1] = cols & 0xff;
        frame[2] = (cols >> 8) & 0xff;
        frame[3] = rows & 0xff;
        frame[4] = (rows >> 8) & 0xff;
        ws.send(frame.buffer);
      }
    },
    close() {
      ws.close();
    },
  };
}

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface Workspace {
  id: string;
  name: string;
  owner_id: string;
  created_at: string;
  updated_at: string;
}

export type PolicyMode = "ALLOW" | "REDACT" | "BLOCK";

export interface Policy {
  workspace_id: string;
  mode: PolicyMode;
  block_injections: boolean;
  upstream_base_url: string;
  has_upstream_api_key: boolean;
  upstream_api_key_preview?: string | null;
  updated_at: string;
}

export interface PolicyUpdateRequest {
  mode?: PolicyMode;
  block_injections?: boolean;
  upstream_base_url?: string;
  upstream_api_key?: string;
}

export interface ApiKey {
  id: string;
  workspace_id: string;
  name: string;
  prefix: string;
  is_revoked: boolean;
  created_at: string;
  last_used_at?: string | null;
}

export interface ApiKeyCreateResponse {
  id: string;
  workspace_id: string;
  name: string;
  api_key: string;
  prefix: string;
  created_at: string;
  message: string;
}

export interface Finding {
  type: string;
  category: string;
  rule_name: string;
  safe_preview: string;
  start?: number;
  end?: number;
  entropy?: number | null;
  details?: string | null;
}

export interface AuditLog {
  id: string;
  workspace_id: string;
  key_id?: string | null;
  model: string;
  action: "ALLOW" | "REDACT" | "BLOCK";
  is_blocked: boolean;
  block_reason?: string | null;
  findings_count: number;
  findings: Finding[];
  inspection_ms: number;
  upstream_ms?: number | null;
  total_ms: number;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  created_at: string;
}

export interface AegisGateMeta {
  action: "ALLOW" | "REDACT" | "BLOCK";
  is_blocked: boolean;
  block_reason?: string | null;
  findings_count: number;
  findings: Finding[];
  inspection_ms: number;
  upstream_ms?: number | null;
  total_ms: number;
  policy_mode: string;
}

export interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: { role: string; content: string };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  aegisgate_meta: AegisGateMeta;
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {},
  token?: string
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg =
      data?.detail || data?.error?.message || `Request failed with status ${response.status}`;
    throw new Error(typeof errorMsg === "string" ? errorMsg : JSON.stringify(errorMsg));
  }

  return data as T;
}

export const api = {
  // Auth
  register: (email: string, password: string) =>
    request<TokenResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  login: (email: string, password: string) =>
    request<TokenResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  getMe: (token: string) => request<User>("/api/auth/me", { method: "GET" }, token),

  // Workspaces
  listWorkspaces: (token: string) =>
    request<Workspace[]>("/api/workspaces", { method: "GET" }, token),

  createWorkspace: (token: string, name: string) =>
    request<Workspace>("/api/workspaces", {
      method: "POST",
      body: JSON.stringify({ name }),
    }, token),

  getWorkspace: (token: string, wsId: string) =>
    request<Workspace>(`/api/workspaces/${wsId}`, { method: "GET" }, token),

  // Policies
  getPolicy: (token: string, wsId: string) =>
    request<Policy>(`/api/workspaces/${wsId}/policy`, { method: "GET" }, token),

  updatePolicy: (token: string, wsId: string, data: PolicyUpdateRequest) =>
    request<Policy>(`/api/workspaces/${wsId}/policy`, {
      method: "PUT",
      body: JSON.stringify(data),
    }, token),

  // API Keys
  listKeys: (token: string, wsId: string) =>
    request<ApiKey[]>(`/api/workspaces/${wsId}/keys`, { method: "GET" }, token),

  createKey: (token: string, wsId: string, name: string) =>
    request<ApiKeyCreateResponse>(`/api/workspaces/${wsId}/keys`, {
      method: "POST",
      body: JSON.stringify({ name }),
    }, token),

  revokeKey: (token: string, wsId: string, keyId: string) =>
    request<{ message: string; revoked: boolean }>(`/api/workspaces/${wsId}/keys/${keyId}`, {
      method: "DELETE",
    }, token),

  // Audit Logs
  getLogs: (token: string, wsId: string, limit = 100) =>
    request<AuditLog[]>(`/api/workspaces/${wsId}/logs?limit=${limit}`, { method: "GET" }, token),

  // Data Plane Proxy Playground
  proxyChatCompletion: async (apiKey: string, payload: unknown) => {
    const url = `${API_BASE_URL}/v1/chat/completions`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json().catch(() => ({}));

    return {
      status: response.status,
      ok: response.ok,
      data,
    };
  },
};

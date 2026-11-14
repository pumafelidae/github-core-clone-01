// MCP over streamable HTTP: initialize/discover, tools/list, tools/call.
// Supports both the modern (server/discover, 2026-07-28) and legacy (initialize) eras;
// plain JSON responses are enough — the client accepts non-SSE bodies.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Store, VIEWER_LOGIN, gitId, type Repo } from './store.ts';
import { sendJson, errMessage, readBody, parseJsonBody, isRecord, isAuthed, requestId } from './util.ts';

const PROTOCOL_VERSION = '2026-07-28';
const SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const SERVER_INFO = { name: 'github-core-clone', version: '1.0.0' };
const SESSION_ID = `sess-${Math.random().toString(36).slice(2, 12)}`;

interface ToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description: string }>;
  required: string[];
}

const TOOLS: ToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    properties: {
      name: { type: 'string', description: 'Repository name' },
      description: { type: 'string', description: 'Repository description' },
      private: { type: 'boolean', description: 'Whether the repository is private' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'Repository owner login' },
      repo: { type: 'string', description: 'Repository name' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'Repository owner login' },
      repo: { type: 'string', description: 'Repository name' },
      title: { type: 'string', description: 'Issue title' },
      body: { type: 'string', description: 'Issue body' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    properties: {
      owner: { type: 'string', description: 'Repository owner login' },
      repo: { type: 'string', description: 'Repository name' },
      state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    properties: {
      owner: { type: 'string', description: 'Repository owner login' },
      repo: { type: 'string', description: 'Repository name' },
      title: { type: 'string', description: 'Pull request title' },
      body: { type: 'string', description: 'Pull request body' },
      head: { type: 'string', description: 'Head branch name' },
      base: { type: 'string', description: 'Base branch name' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    properties: {
      owner: { type: 'string', description: 'Repository owner login' },
      repo: { type: 'string', description: 'Repository name' },
      pull_number: { type: 'integer', description: 'Pull request number' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
];

function toolJson(t: ToolDef): Record<string, unknown> {
  return {
    name: t.name,
    description: t.description,
    inputSchema: { type: 'object', properties: t.properties, required: t.required },
  };
}

function rpcResult(id: unknown, result: unknown, res: ServerResponse): void {
  sendJson(res, 200, { jsonrpc: '2.0', id, result }, { 'mcp-session-id': SESSION_ID });
}

function rpcError(id: unknown, code: number, message: string, res: ServerResponse, status = 200): void {
  sendJson(res, status, { jsonrpc: '2.0', id, error: { code, message } }, { 'mcp-session-id': SESSION_ID });
}

function toolResult(data: Record<string, unknown>): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data };
}

function toolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function resolveRepo(store: Store, owner: string, repoName: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return store.getRepo(owner, repoName) ?? null;
}

function callTool(store: Store, name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; error?: { code: number; message: string } } {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return { error: { code: -32601, message: `Unknown tool: ${name}` } };
  // Missing required arguments -> invalid params.
  for (const req of tool.required) {
    if (args[req] === undefined || args[req] === null || args[req] === '') {
      return { error: { code: -32602, message: `Missing required argument: ${req}` } };
    }
  }
  const owner = String(args.owner ?? VIEWER_LOGIN);
  const repoName = String(args.repo ?? '');

  if (name === 'create_repo') {
    const repoNameArg = String(args.name ?? '');
    if (store.getRepo(VIEWER_LOGIN, repoNameArg)) {
      return { result: toolError(`Repository ${VIEWER_LOGIN}/${repoNameArg} already exists`) };
    }
    const repo = store.createRepo(repoNameArg, args.private === true, typeof args.description === 'string' ? args.description : '');
    return { result: toolResult({ id: repo.dbId, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.private, description: repo.description, default_branch: repo.defaultBranch }) };
  }

  const repo = resolveRepo(store, owner, repoName);
  if (!repo && name !== 'create_repo') {
    return { result: toolError(`Repository ${owner}/${repoName} not found`) };
  }

  if (name === 'get_repo') {
    return { result: toolResult({ id: repo!.dbId, name: repo!.name, full_name: `${repo!.owner}/${repo!.name}`, private: repo!.private, description: repo!.description, default_branch: repo!.defaultBranch, owner: { login: repo!.owner } }) };
  }

  if (name === 'create_issue') {
    const number = store.nextNumber(repo!);
    const issue = {
      number,
      id: gitId('Issue', repo!.dbId, String(number)),
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open' as const,
      labels: [] as string[],
      comments: [],
      seq: repo!.counter,
    };
    repo!.issues.push(issue);
    return { result: toolResult({ id: repo!.dbId * 100000 + number, number, title: issue.title, body: issue.body, state: 'open', full_name: `${repo!.owner}/${repo!.name}` }) };
  }

  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = repo!.issues.slice();
    if (state !== 'all') list = list.filter((i) => i.state === state);
    const items = list.map((i) => ({ id: repo!.dbId * 100000 + i.number, number: i.number, title: i.title, body: i.body, state: i.state }));
    return { result: toolResult({ issues: items, total_count: items.length }) };
  }

  if (name === 'create_pull_request') {
    const head = String(args.head);
    const baseRef = String(args.base);
    const headSha = repo!.branches.get(head);
    const baseSha = repo!.branches.get(baseRef);
    if (!headSha || !baseSha) {
      return { result: toolError(`Head or base branch does not exist: ${head} / ${baseRef}`) };
    }
    const files = store.diffFiles(store.filesOfCommit(baseSha), store.filesOfCommit(headSha));
    const number = store.nextNumber(repo!);
    const pr = {
      number,
      id: gitId('PullRequest', repo!.dbId, String(number)),
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open' as const,
      merged: false,
      merged_at: null as string | null,
      merge_commit_sha: null as string | null,
      head: { ref: head, sha: headSha },
      base: { ref: baseRef, sha: baseSha },
      baseSha,
      files,
      seq: repo!.counter,
    };
    repo!.prs.push(pr);
    return { result: toolResult({ id: repo!.dbId * 100000 + number, number, title: pr.title, state: 'open', head: { ref: head, sha: headSha }, base: { ref: baseRef, sha: baseSha } }) };
  }

  if (name === 'merge_pull_request') {
    const number = Number(args.pull_number);
    const pr = repo!.prs.find((p) => p.number === number);
    if (!pr) return { result: toolError(`Pull request #${number} not found`) };
    if (pr.merged || pr.state === 'closed') {
      return { result: toolError(`Pull request #${number} is already merged or closed`) };
    }
    const baseTip = repo!.branches.get(pr.base.ref);
    if (!baseTip) return { result: toolError('Base branch not found') };
    if (baseTip !== pr.baseSha) {
      const prBaseFiles = store.filesOfCommit(pr.baseSha);
      const baseNowFiles = store.filesOfCommit(baseTip);
      const baseChanged = new Set(store.diffFiles(prBaseFiles, baseNowFiles).map((f) => f.filename));
      if (pr.files.some((f) => baseChanged.has(f.filename))) {
        return { result: toolError('Merge conflict') };
      }
    }
    const mergedFiles = store.filesOfCommit(baseTip);
    const headFiles = store.filesOfCommit(pr.head.sha);
    for (const f of pr.files) {
      if (f.status === 'removed') mergedFiles.delete(f.filename);
      else {
        const c = headFiles.get(f.filename);
        if (c !== undefined) mergedFiles.set(f.filename, c);
      }
    }
    const mergeSha = store.createCommit(repo!, pr.base.ref, mergedFiles, `${pr.title} (#${pr.number})`, [baseTip]);
    pr.merged = true;
    pr.state = 'closed';
    pr.merged_at = new Date().toISOString();
    pr.merge_commit_sha = mergeSha;
    return { result: toolResult({ merged: true, number: pr.number, state: 'closed', sha: mergeSha }) };
  }

  return { error: { code: -32601, message: `Unknown tool: ${name}` } };
}

export async function handleMcp(req: IncomingMessage, res: ServerResponse, store: Store): Promise<boolean> {
  const method = req.method ?? 'GET';

  if (method === 'DELETE') {
    // Session close: best-effort, always fine.
    res.writeHead(204, { 'x-github-request-id': requestId() });
    res.end();
    return true;
  }
  if (method !== 'POST') return false;

  if (!isAuthed(req)) {
    errMessage(res, 401, 'Requires authentication');
    return true;
  }

  const buf = await readBody(req);
  if (buf === null) {
    rpcError(null, -32700, 'Parse error', res, 400);
    return true;
  }
  const text = buf.toString('utf8');
  const { value, error } = parseJsonBody(buf);
  if (error || !isRecord(value)) {
    // Malformed JSON body -> JSON-RPC parse error, HTTP 400.
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: ${text.slice(0, 80)}` } }, { 'mcp-session-id': SESSION_ID });
    return true;
  }

  const id = value.id ?? null;
  const rpcMethod = typeof value.method === 'string' ? value.method : '';
  const params = isRecord(value.params) ? value.params : {};

  // Notifications (no id): accept silently.
  if (value.id === undefined) {
    res.writeHead(202, { 'x-github-request-id': requestId(), 'mcp-session-id': SESSION_ID });
    res.end();
    return true;
  }

  if (rpcMethod === 'server/discover') {
    rpcResult(id, {
      supportedVersions: SUPPORTED_VERSIONS,
      serverInfo: SERVER_INFO,
      capabilities: { tools: {} },
      _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO },
    }, res);
    return true;
  }

  if (rpcMethod === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : PROTOCOL_VERSION;
    const negotiated = SUPPORTED_VERSIONS.includes(offered) ? offered : PROTOCOL_VERSION;
    rpcResult(id, { protocolVersion: negotiated, serverInfo: SERVER_INFO, capabilities: { tools: {} } }, res);
    return true;
  }

  if (rpcMethod === 'tools/list') {
    rpcResult(id, { tools: TOOLS.map(toolJson) }, res);
    return true;
  }

  if (rpcMethod === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const outcome = callTool(store, toolName, args);
    if (outcome.error) {
      rpcError(id, outcome.error.code, outcome.error.message, res);
      return true;
    }
    rpcResult(id, outcome.result, res);
    return true;
  }

  if (rpcMethod === 'ping') {
    rpcResult(id, {}, res);
    return true;
  }

  rpcError(id, -32601, `Method not found: ${rpcMethod}`, res);
  return true;
}

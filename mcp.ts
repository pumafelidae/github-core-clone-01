// The Model Context Protocol surface: MCP over streamable HTTP (JSON-RPC 2.0) at POST /mcp.
//
// Written fresh for this entry from the kit's conformance contract
// (sdk/conformance/checks-mcp.ts + mcp-client.ts). The entry speaks both protocol eras the
// rules accept:
//
//   modern  2026-07-28: `server/discover` answers identity, capabilities and
//           supportedVersions in one request; no handshake, no session.
//   legacy  2025-11-25 and earlier: `initialize` (echoing the client's revision) +
//           `notifications/initialized`; stateless, no Mcp-Session-Id is issued.
//
// Every tool reads and writes the same Forge store as REST, so a tool-created repository,
// issue or pull request is visible over GET /api/v3/... immediately. Tool results are
// deterministic: ids come from the Forge's sequential numbers, never from a clock or
// Math.random.
//
// Auth: every POST /mcp requires a valid Bearer token (isAuthorized); anything else gets
// HTTP 401 {"message":"Bad credentials"} — including initialize and server/discover, since
// the suite always presents its token when it connects (checks-mcp.ts never calls
// initialize/discover without auth; only tools/call is probed unauthenticated, in
// check id mcp/auth-required).

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Forge, Issue, PullRequest, RepoRecord } from './store.ts';
import { isAuthorized, isRecord, pathOf, readBody, sendBytes, sendJson, sendUnauthorized } from './util.ts';

/** The server identity every era reports. */
export const MCP_SERVER_NAME = 'github-core-clone';
export const MCP_SERVER_VERSION = '0.0.0';

/** The current protocol revision (2026-07-28). */
export const MCP_PREFERRED_VERSION = '2026-07-28';

/** The protocol revisions this server negotiates, newest first. */
export const MCP_SUPPORTED_VERSIONS: readonly string[] = Object.freeze([
  MCP_PREFERRED_VERSION,
  '2025-11-25',
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
]);

/** JSON-RPC error codes. */
const JSON_RPC_PARSE_ERROR = -32700;
const JSON_RPC_INVALID_REQUEST = -32600;
const JSON_RPC_METHOD_NOT_FOUND = -32601;
const JSON_RPC_INVALID_PARAMS = -32602;

// ---------------------------------------------------------------- tool definitions

/** One tool as tools/list answers it. */
interface McpToolDef {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Record<string, Record<string, unknown>>;
    readonly required: readonly string[];
  };
}

/** Build one tool definition (the tools array is built once, at module load). */
function toolDef(
  name: string,
  description: string,
  properties: Record<string, Record<string, unknown>>,
  required: readonly string[],
): McpToolDef {
  return { name, description, inputSchema: { type: 'object', properties, required } };
}

const STRING = { type: 'string' };
const BOOLEAN = { type: 'boolean' };
const INTEGER = { type: 'integer' };
const STATE = { type: 'string', enum: ['open', 'closed', 'all'] };
const LABELS = { type: 'array', items: { type: 'string' } };

/**
 * The tools. Canonical names first (create_repo, get_repo, ... — the names
 * checks-mcp.ts's MCP_REQUIRED_TOOLS requires), then the create_repository /
 * get_repository aliases the brief names; the suite matches either by exact name or by
 * normalized suffix, and dispatch normalizes the name the same way, so both spellings
 * run the same handler. Every tool has a non-empty description and an object
 * inputSchema (check id mcp/tool-schemas), and every required property is one the suite
 * can fill from its documented arguments (check id mcp/tools-list and the mapping in
 * checks-mcp.ts's mapArguments): create_repo {name, description?, private?} plus an
 * optional owner; get_repo {owner, repo}; create_issue {owner, repo, title, body?};
 * list_issues {owner, repo, state?}; create_pull_request {owner, repo, title, head,
 * base, body?}; merge_pull_request {owner, repo, pull_number}.
 */
export const MCP_TOOLS: readonly McpToolDef[] = Object.freeze([
  toolDef('create_repo', 'Create a repository owned by the given owner (default: the authenticated user).', {
    owner: STRING, name: STRING, description: STRING, private: BOOLEAN,
  }, ['name']),
  toolDef('create_repository', 'Create a repository owned by the given owner (default: the authenticated user).', {
    owner: STRING, name: STRING, description: STRING, private: BOOLEAN,
  }, ['name']),
  toolDef('get_repo', 'Get a repository by owner and name.', {
    owner: STRING, repo: STRING,
  }, ['owner', 'repo']),
  toolDef('get_repository', 'Get a repository by owner and name.', {
    owner: STRING, repo: STRING,
  }, ['owner', 'repo']),
  toolDef('create_issue', 'Create an issue in a repository.', {
    owner: STRING, repo: STRING, title: STRING, body: STRING, labels: LABELS,
  }, ['owner', 'repo', 'title']),
  toolDef('list_issues', 'List issues in a repository, optionally filtered by state.', {
    owner: STRING, repo: STRING, state: STATE,
  }, ['owner', 'repo']),
  toolDef('get_issue', 'Get one issue in a repository by its number.', {
    owner: STRING, repo: STRING, issue_number: INTEGER,
  }, ['owner', 'repo', 'issue_number']),
  toolDef('create_pull_request', 'Open a pull request from a head branch into a base branch.', {
    owner: STRING, repo: STRING, title: STRING, body: STRING, head: STRING, base: STRING,
  }, ['owner', 'repo', 'title', 'head', 'base']),
  toolDef('list_pull_requests', 'List pull requests in a repository, optionally filtered by state.', {
    owner: STRING, repo: STRING, state: STATE,
  }, ['owner', 'repo']),
  toolDef('get_pull_request', 'Get one pull request in a repository by its number.', {
    owner: STRING, repo: STRING, pull_number: INTEGER,
  }, ['owner', 'repo', 'pull_number']),
  toolDef('merge_pull_request', 'Merge an open pull request into its base branch.', {
    owner: STRING, repo: STRING, pull_number: INTEGER,
  }, ['owner', 'repo', 'pull_number']),
  toolDef('list_repositories', 'List repositories, optionally filtered to one owner.', {
    owner: STRING,
  }, []),
]);

/** The normalized tool names tools/call accepts. */
const KNOWN_TOOL_NAMES: ReadonlySet<string> = new Set(
  MCP_TOOLS.map((tool) => normalizeToolName(tool.name)),
);

/** A tool name normalized for matching: lowercase, every non-alphanumeric removed. */
function normalizeToolName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

// ---------------------------------------------------------------- result shapes (REST-like, same objects REST reads)

/** A repository as the tools return it (id/name/full_name are what the checks read). */
function repoJson(repo: RepoRecord): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: repo.fullName,
    owner: { login: repo.owner },
    description: repo.description,
    private: repo.private,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.pushedAt,
  };
}

/** An issue as the tools return it. */
function issueJson(issue: Issue): Record<string, unknown> {
  return {
    id: issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: [...issue.labels],
    user: { login: issue.user.login },
    assignees: [...issue.assignees],
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    comments: issue.comments.size,
  };
}

/** A pull request as the tools return it (head/base as {ref, label, sha} objects). */
function pullJson(repo: RepoRecord, pull: PullRequest): Record<string, unknown> {
  return {
    id: pull.number,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.head, label: `${repo.owner}:${pull.head}`, sha: pull.headSha },
    base: { ref: pull.base, label: `${repo.owner}:${pull.base}`, sha: pull.baseSha },
    merged: pull.merged,
    mergeable: pull.mergeable,
    user: { login: pull.user.login },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    merged_at: pull.mergedAt,
    merged_by: pull.mergedBy,
  };
}

// ---------------------------------------------------------------- argument helpers

/** The first present string argument under any of `keys` (trimmed, non-empty), else null. */
function stringArg(args: Record<string, unknown>, keys: readonly string[]): string | null {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
  }
  return null;
}

/** The first present string argument under any of `keys`, else `fallback`. */
function optionalStringArg(args: Record<string, unknown>, keys: readonly string[], fallback = ''): string {
  return stringArg(args, keys) ?? fallback;
}

/** The first present integer argument under any of `keys` (a number, or a digit string), else null. */
function integerArg(args: Record<string, unknown>, keys: readonly string[]): number | null {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'number' && Number.isInteger(value)) return value;
    if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim());
  }
  return null;
}

/** A boolean argument, else `fallback`. */
function booleanArg(args: Record<string, unknown>, key: string, fallback = false): boolean {
  const value = args[key];
  return typeof value === 'boolean' ? value : fallback;
}

/** The labels argument: an array of strings, a single string, or none. */
function labelsArg(args: Record<string, unknown>): string[] {
  const value = args.labels;
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === 'string');
  if (typeof value === 'string' && value !== '') return [value];
  return [];
}

// ---------------------------------------------------------------- tool dispatch

/** A tool's outcome: a value to JSON-encode, or a tool execution error. */
type ToolOutcome = { ok: true; value: unknown } | { ok: false; message: string };

/** Resolve the owner/repo pair a tool names (owner defaults to the viewer). */
function resolveRepo(
  forge: Forge,
  args: Record<string, unknown>,
): { repo: RepoRecord; owner: string; name: string } | { error: string } {
  const owner = stringArg(args, ['owner', 'owner_login', 'login']) ?? forge.viewer.login;
  const name = stringArg(args, ['repo', 'repository', 'repo_name', 'repository_name', 'name']);
  if (name === null) return { error: 'Missing required argument: repo' };
  const repo = forge.getRepo(owner, name);
  if (repo === undefined) return { error: `Repository not found: ${owner}/${name}` };
  return { repo, owner, name };
}

/** A state argument: open/closed/all, defaulting to open; null when unrecognized. */
function stateArg(args: Record<string, unknown>): 'open' | 'closed' | 'all' | null {
  const state = optionalStringArg(args, ['state', 'status'], 'open');
  if (state === 'open' || state === 'closed' || state === 'all') return state;
  return null;
}

function createRepoTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const name = stringArg(args, ['name', 'repo', 'repository', 'repo_name', 'repository_name']);
  if (name === null) return { ok: false, message: 'Missing required argument: name' };
  if (name.includes('/')) return { ok: false, message: `Invalid repository name: ${name}` };
  const owner = stringArg(args, ['owner', 'owner_login', 'login']) ?? forge.viewer.login;
  if (forge.getRepo(owner, name) !== undefined) return { ok: false, message: `Repository already exists: ${owner}/${name}` };
  const repo = forge.createRepo(owner, name, optionalStringArg(args, ['description']), booleanArg(args, 'private', false));
  return { ok: true, value: repoJson(repo) };
}

function getRepoTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  return { ok: true, value: repoJson(resolved.repo) };
}

function createIssueTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const title = stringArg(args, ['title', 'issue_title', 'subject']);
  if (title === null) return { ok: false, message: 'Missing required argument: title' };
  const body = optionalStringArg(args, ['body', 'issue_body', 'description', 'content', 'text']);
  const issue = forge.createIssue(resolved.repo, title, body, labelsArg(args), forge.viewer);
  return { ok: true, value: issueJson(issue) };
}

function listIssuesTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const state = stateArg(args);
  if (state === null) return { ok: false, message: `Invalid state: ${optionalStringArg(args, ['state', 'status'])}` };
  return { ok: true, value: forge.listIssues(resolved.repo, state).map(issueJson) };
}

function getIssueTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const number = integerArg(args, ['issue_number', 'number']);
  if (number === null) return { ok: false, message: 'Missing required argument: issue_number' };
  const issue = forge.getIssue(resolved.repo, number);
  if (issue === undefined) return { ok: false, message: `Issue not found: #${number}` };
  return { ok: true, value: issueJson(issue) };
}

function createPullTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const title = stringArg(args, ['title', 'pr_title', 'pull_request_title', 'subject']);
  if (title === null) return { ok: false, message: 'Missing required argument: title' };
  const head = stringArg(args, ['head', 'head_ref', 'head_branch', 'source', 'source_branch', 'from_branch', 'branch']);
  if (head === null) return { ok: false, message: 'Missing required argument: head' };
  const base = stringArg(args, ['base', 'base_ref', 'base_branch', 'target', 'target_ref', 'target_branch', 'into_branch']);
  if (base === null) return { ok: false, message: 'Missing required argument: base' };
  const body = optionalStringArg(args, ['body', 'description', 'content', 'text']);
  const pull = forge.createPull(resolved.repo, title, body, head, base, forge.viewer);
  return { ok: true, value: pullJson(resolved.repo, pull) };
}

function listPullsTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const state = stateArg(args);
  if (state === null) return { ok: false, message: `Invalid state: ${optionalStringArg(args, ['state', 'status'])}` };
  return { ok: true, value: forge.listPulls(resolved.repo, state).map((pull) => pullJson(resolved.repo, pull)) };
}

function getPullTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const number = integerArg(args, ['pull_number', 'pull_request_number', 'pr_number', 'number']);
  if (number === null) return { ok: false, message: 'Missing required argument: pull_number' };
  const pull = forge.getPull(resolved.repo, number);
  if (pull === undefined) return { ok: false, message: `Pull request not found: #${number}` };
  return { ok: true, value: pullJson(resolved.repo, pull) };
}

function mergePullTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const resolved = resolveRepo(forge, args);
  if ('error' in resolved) return { ok: false, message: resolved.error };
  const number = integerArg(args, ['pull_number', 'pull_request_number', 'pr_number', 'number']);
  if (number === null) return { ok: false, message: 'Missing required argument: pull_number' };
  const pull = forge.getPull(resolved.repo, number);
  if (pull === undefined) return { ok: false, message: `Pull request not found: #${number}` };
  const mergeSha = forge.mergePull(resolved.repo, pull, forge.viewer);
  if (mergeSha === null) return { ok: false, message: `Pull request #${number} cannot be merged` };
  return { ok: true, value: { ...pullJson(resolved.repo, pull), merge_commit_sha: mergeSha } };
}

function listReposTool(forge: Forge, args: Record<string, unknown>): ToolOutcome {
  const owner = stringArg(args, ['owner', 'owner_login', 'login']);
  const repos = owner === null ? forge.listRepos() : forge.listRepos(owner);
  return { ok: true, value: repos.map(repoJson) };
}

/** Dispatch a tools/call to its handler (the caller has already rejected unknown names). */
function callTool(forge: Forge, name: string, args: Record<string, unknown>): ToolOutcome {
  switch (normalizeToolName(name)) {
    case 'createrepo':
    case 'createrepository':
      return createRepoTool(forge, args);
    case 'getrepo':
    case 'getrepository':
      return getRepoTool(forge, args);
    case 'createissue':
      return createIssueTool(forge, args);
    case 'listissues':
      return listIssuesTool(forge, args);
    case 'getissue':
      return getIssueTool(forge, args);
    case 'createpullrequest':
      return createPullTool(forge, args);
    case 'listpullrequests':
      return listPullsTool(forge, args);
    case 'getpullrequest':
      return getPullTool(forge, args);
    case 'mergepullrequest':
      return mergePullTool(forge, args);
    case 'listrepositories':
      return listReposTool(forge, args);
    default:
      return { ok: false, message: `Unknown tool: ${name}` };
  }
}

// ---------------------------------------------------------------- JSON-RPC plumbing

/** One JSON-RPC reply: its HTTP status and body. Null means "no reply" (a notification). */
type RpcReply = { status: number; body: unknown } | null;

/** A success reply carrying `result` under the request's id. */
function rpcResult(id: string | number | null, result: unknown): RpcReply {
  return { status: 200, body: { jsonrpc: '2.0', id, result } };
}

/** An error reply. JSON-RPC errors ride HTTP 200 except where the transport says otherwise. */
function rpcError(id: string | number | null, code: number, message: string, status = 200): RpcReply {
  return { status, body: { jsonrpc: '2.0', id, error: { code, message } } };
}

/** The server/discover result (modern era): identity, capabilities and revisions in one answer. */
function discoverResult(): Record<string, unknown> {
  const serverInfo = { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION };
  return {
    resultType: 'io.modelcontextprotocol/discover-result',
    supportedVersions: [...MCP_SUPPORTED_VERSIONS],
    capabilities: { tools: {} },
    serverInfo,
    _meta: {
      'io.modelcontextprotocol/serverInfo': serverInfo,
      'io.modelcontextprotocol/protocolVersion': MCP_PREFERRED_VERSION,
    },
  };
}

/** Handle one decoded JSON-RPC value; null when it is a notification (no reply). */
function handleOne(forge: Forge, value: unknown): RpcReply {
  if (!isRecord(value)) return rpcError(null, JSON_RPC_INVALID_REQUEST, 'Invalid Request', 400);
  const hasId = 'id' in value;
  const rawId: unknown = value.id;
  const id: string | number | null =
    typeof rawId === 'string' || typeof rawId === 'number' ? rawId : null;
  if (hasId && rawId !== null && typeof rawId !== 'string' && typeof rawId !== 'number') {
    return rpcError(null, JSON_RPC_INVALID_REQUEST, 'Invalid Request: id must be a string or number', 400);
  }
  const method = value.method;
  if (typeof method !== 'string' || method === '') {
    // A notification with no method gets no reply; a request gets -32600.
    if (!hasId) return null;
    return rpcError(id, JSON_RPC_INVALID_REQUEST, 'Invalid Request: method must be a string', 400);
  }
  // Notifications (no id) never get a reply, whatever the method.
  if (!hasId) return null;
  if (method.startsWith('notifications/')) return rpcResult(id, {});
  switch (method) {
    case 'server/discover':
      return rpcResult(id, discoverResult());
    case 'initialize': {
      const params = isRecord(value.params) ? value.params : {};
      const version = params.protocolVersion;
      if (typeof version !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(version)) {
        return rpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params: protocolVersion must be a YYYY-MM-DD revision');
      }
      return rpcResult(id, {
        protocolVersion: version,
        capabilities: { tools: {} },
        serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
      });
    }
    case 'ping':
      return rpcResult(id, {});
    case 'tools/list':
      return rpcResult(id, { tools: MCP_TOOLS });
    case 'tools/call': {
      const params = value.params;
      if (!isRecord(params)) {
        return rpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params: tools/call needs an object params');
      }
      const name = params.name;
      if (typeof name !== 'string' || name === '') {
        return rpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params: tools/call needs a tool name');
      }
      // An unknown tool name is a JSON-RPC error (-32602), never HTTP 500
      // (check id mcp/unknown-tool accepts -32602 or -32601).
      if (!KNOWN_TOOL_NAMES.has(normalizeToolName(name))) {
        return rpcError(id, JSON_RPC_INVALID_PARAMS, `Unknown tool: ${name}`);
      }
      const args = params.arguments === undefined ? {} : params.arguments;
      if (!isRecord(args)) {
        return rpcError(id, JSON_RPC_INVALID_PARAMS, 'Invalid params: arguments must be an object');
      }
      const outcome = callTool(forge, name, args);
      if (!outcome.ok) {
        // A tool execution failure (missing argument, missing repo, unmergeable PR)
        // answers isError:true (check id mcp/missing-arguments accepts isError:true
        // or JSON-RPC -32602).
        return rpcResult(id, { content: [{ type: 'text', text: outcome.message }], isError: true });
      }
      return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(outcome.value) }], isError: false });
    }
    default:
      return rpcError(id, JSON_RPC_METHOD_NOT_FOUND, `Method not found: ${method}`);
  }
}

// ---------------------------------------------------------------- the HTTP entry point

/**
 * Handle POST /mcp. Returns true when the request was POST /mcp (handled, even on
 * error), false otherwise so app.ts can route it elsewhere. Stateless: no session is
 * issued, and none is required — the client sends no Mcp-Session-Id unless the server
 * handed one out, and this server never does.
 */
export async function handleMcp(req: IncomingMessage, res: ServerResponse, forge: Forge): Promise<boolean> {
  if (req.method !== 'POST') return false;
  if (pathOf(req) !== '/mcp') return false;
  if (!isAuthorized(req)) {
    sendUnauthorized(res);
    return true;
  }
  const jsonHeaders = { 'content-type': 'application/json' };
  let raw: Buffer;
  try {
    raw = await readBody(req);
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: JSON_RPC_PARSE_ERROR, message: 'Parse error' } }, jsonHeaders);
    return true;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8')) as unknown;
  } catch {
    // A body that is not JSON answers HTTP 400 with JSON-RPC -32700
    // (check id mcp/parse-error).
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: JSON_RPC_PARSE_ERROR, message: 'Parse error' } }, jsonHeaders);
    return true;
  }
  if (Array.isArray(parsed)) {
    // A batch: one reply per request that carried an id, in order.
    if (parsed.length === 0) {
      sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: JSON_RPC_INVALID_REQUEST, message: 'Invalid Request' } }, jsonHeaders);
      return true;
    }
    const replies: unknown[] = [];
    for (const item of parsed) {
      const reply = handleOne(forge, item);
      if (reply !== null) replies.push(reply.body);
    }
    if (replies.length === 0) {
      sendBytes(res, 202, Buffer.alloc(0), 'application/json');
      return true;
    }
    sendJson(res, 200, replies, jsonHeaders);
    return true;
  }
  const reply = handleOne(forge, parsed);
  if (reply === null) {
    // A notification: no reply body, 202 accepted.
    sendBytes(res, 202, Buffer.alloc(0), 'application/json');
    return true;
  }
  sendJson(res, reply.status, reply.body, jsonHeaders);
  return true;
}

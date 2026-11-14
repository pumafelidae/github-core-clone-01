// The GitHub REST v3 surface: every /api/v3/* route except POST /api/graphql (owned by
// graphql.ts). One Forge holds all state; this module only reads and writes through it, so a
// change on one surface (REST, GraphQL, MCP, git) is visible on the others.
//
// Contract: sdk/conformance/checks-rest.ts. The checks are the spec: exact statuses, JSON
// shapes, pagination Link headers, auth (401 without a token), ownership (a repo under another
// login is 404, never 403), and the protocol rules (application/json everywhere, a JSON 404
// for unknown routes, 400 for a malformed JSON body, a non-empty X-GitHub-Request-Id on every
// reply). app.ts does not add those headers, so every reply here carries them.
//
// Node 22 stdlib only, no dependencies, no network, no git binary.

import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { encodeCommit, parseCommit } from './store.ts';
import type { Forge, Issue, IssueComment, Label, PullRequest, RepoRecord } from './store.ts';
import {
  fromBase64,
  gitObjectId,
  isAuthorized,
  isoNow,
  isRecord,
  pageParams,
  paginate,
  readJsonBody,
  sendJson,
  toBase64,
} from './util.ts';

/** The scopes a token carries, reported on the API root (and every reply, as GitHub does). */
const SCOPES = 'repo, read:org';

/** Merge SHAs by "<fullName>#<pull number>": PullRequest carries no merge_commit_sha field. */
const mergeShas = new Map<string, string>();

/** A GitHub node id: base64("<Type>:<id>"). */
function nodeId(type: string, id: number): string {
  return Buffer.from(`${type}:${id}`, 'utf8').toString('base64');
}

/** The request's origin (scheme + host), for absolute Link and url fields. */
function originOf(req: IncomingMessage): string {
  return `http://${req.headers.host ?? 'localhost'}`;
}

/** The API base, e.g. http://127.0.0.1:1234/api/v3. */
function apiBaseOf(req: IncomingMessage): string {
  return `${originOf(req)}/api/v3`;
}

/** Answer with a JSON body, always carrying the protocol headers the checks require. */
function reply(res: ServerResponse, status: number, body: unknown, extra: Readonly<Record<string, string>> = {}): void {
  sendJson(res, status, body, { 'x-github-request-id': randomUUID(), 'x-oauth-scopes': SCOPES, ...extra });
}

/** Answer with an empty body (204 deletes), still carrying the protocol headers. */
function replyEmpty(res: ServerResponse, status = 204): void {
  res.writeHead(status, { 'x-github-request-id': randomUUID(), 'x-oauth-scopes': SCOPES });
  res.end();
}

/** GitHub's {"message": ...} error body, optionally with a Validation Failed errors array. */
function replyError(res: ServerResponse, status: number, message: string, errors?: Array<Record<string, unknown>>): void {
  const body: Record<string, unknown> = { message };
  if (errors !== undefined) body.errors = errors;
  if (status === 422) body.documentation_url = 'https://docs.github.com/rest';
  reply(res, status, body);
}

function replyNotFound(res: ServerResponse, message = 'Not Found'): void {
  replyError(res, 404, message);
}

function replyMethodNotAllowed(res: ServerResponse): void {
  replyError(res, 405, 'Method Not Allowed');
}

/**
 * Read a JSON request body. Returns the parsed object, an empty object for an empty body, or
 * the string 'malformed' when the body is not valid JSON (the caller answers 400).
 */
async function jsonBody(req: IncomingMessage): Promise<Record<string, unknown> | 'malformed'> {
  let raw: unknown;
  try {
    raw = await readJsonBody(req);
  } catch {
    return 'malformed';
  }
  if (raw === null) return {};
  return isRecord(raw) ? raw : {};
}

/** A string field of a JSON body, or '' when absent or not a string. */
function strField(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  return typeof value === 'string' ? value : '';
}

/** A string array field (strings, or objects with a name), or [] when absent. */
function strArrayField(body: Record<string, unknown>, field: string): string[] {
  const value = body[field];
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    if (typeof item === 'string') out.push(item);
    else if (isRecord(item) && typeof item.name === 'string') out.push(item.name);
  }
  return out;
}

/** Split a request path into decoded segments, dropping empty ones. */
function segmentsOf(path: string): string[] {
  const out: string[] = [];
  for (const part of path.split('/')) {
    if (part === '') continue;
    try {
      out.push(decodeURIComponent(part));
    } catch {
      out.push(part);
    }
  }
  return out;
}

/** A numeric path segment, or null when it is not a positive integer. */
function numSegment(segment: string | undefined): number | null {
  if (segment === undefined || !/^\d+$/.test(segment)) return null;
  const value = Number.parseInt(segment, 10);
  return Number.isSafeInteger(value) && value >= 1 ? value : null;
}

// --------------------------------------------------------------------------- JSON shapes

/** A GitHub user (or org) object for a login. */
function userJson(forge: Forge, req: IncomingMessage, login: string): Record<string, unknown> {
  const user = forge.users.get(login);
  const isOrg = login === forge.scenario.org;
  const id = user?.id ?? (isOrg ? 1 : 0);
  return {
    login,
    id,
    node_id: nodeId(isOrg ? 'Organization' : 'User', id),
    avatar_url: `https://avatars.githubusercontent.com/u/${id}?v=4`,
    gravatar_id: '',
    url: `${apiBaseOf(req)}/users/${login}`,
    html_url: `https://github.com/${login}`,
    followers_url: `${apiBaseOf(req)}/users/${login}/followers`,
    following_url: `${apiBaseOf(req)}/users/${login}/following{/other_user}`,
    gists_url: `${apiBaseOf(req)}/users/${login}/gists{/gist_id}`,
    starred_url: `${apiBaseOf(req)}/users/${login}/starred{/owner}{/repo}`,
    subscriptions_url: `${apiBaseOf(req)}/users/${login}/subscriptions`,
    organizations_url: `${apiBaseOf(req)}/users/${login}/orgs`,
    repos_url: `${apiBaseOf(req)}/users/${login}/repos`,
    events_url: `${apiBaseOf(req)}/users/${login}/events{/privacy}`,
    received_events_url: `${apiBaseOf(req)}/users/${login}/received_events`,
    type: isOrg ? 'Organization' : 'User',
    user_view_type: 'public',
    site_admin: false,
    name: user?.name ?? login,
    company: null,
    blog: '',
    location: null,
    email: user?.email ?? null,
    hireable: null,
    bio: null,
    twitter_username: null,
    public_repos: 0,
    public_gists: 0,
    followers: 0,
    following: 0,
    created_at: forge.scenario.viewer === user ? '2025-01-01T00:00:00.000Z' : isoNow(),
    updated_at: isoNow(),
  };
}

/** A GitHub repository object. */
function repoJson(forge: Forge, req: IncomingMessage, repo: RepoRecord): Record<string, unknown> {
  const base = apiBaseOf(req);
  const openIssues = [...repo.issues.values()].filter((issue) => issue.state === 'open').length;
  return {
    id: repo.id,
    node_id: nodeId('Repository', repo.id),
    name: repo.name,
    full_name: repo.fullName,
    owner: userJson(forge, req, repo.owner),
    private: repo.private,
    html_url: `https://github.com/${repo.fullName}`,
    description: repo.description,
    fork: false,
    url: `${base}/repos/${repo.fullName}`,
    archive_url: `${base}/repos/${repo.fullName}/{archive_format}{/ref}`,
    assignees_url: `${base}/repos/${repo.fullName}/assignees{/user}`,
    blobs_url: `${base}/repos/${repo.fullName}/git/blobs{/sha}`,
    branches_url: `${base}/repos/${repo.fullName}/branches{/branch}`,
    clone_url: `https://github.com/${repo.fullName}.git`,
    collaborators_url: `${base}/repos/${repo.fullName}/collaborators{/collaborator}`,
    comments_url: `${base}/repos/${repo.fullName}/comments{/number}`,
    commits_url: `${base}/repos/${repo.fullName}/commits{/sha}`,
    compare_url: `${base}/repos/${repo.fullName}/compare/{base}...{head}`,
    contents_url: `${base}/repos/${repo.fullName}/contents/{+path}`,
    contributors_url: `${base}/repos/${repo.fullName}/contributors`,
    deployments_url: `${base}/repos/${repo.fullName}/deployments`,
    downloads_url: `${base}/repos/${repo.fullName}/downloads`,
    events_url: `${base}/repos/${repo.fullName}/events`,
    forks_url: `${base}/repos/${repo.fullName}/forks`,
    git_commits_url: `${base}/repos/${repo.fullName}/git/commits{/sha}`,
    git_refs_url: `${base}/repos/${repo.fullName}/git/refs{/sha}`,
    git_tags_url: `${base}/repos/${repo.fullName}/git/tags{/sha}`,
    git_url: `git://github.com/${repo.fullName}.git`,
    issue_comment_url: `${base}/repos/${repo.fullName}/issues/comments{/number}`,
    issue_events_url: `${base}/repos/${repo.fullName}/issues/events{/number}`,
    issues_url: `${base}/repos/${repo.fullName}/issues{/number}`,
    keys_url: `${base}/repos/${repo.fullName}/keys{/key_id}`,
    labels_url: `${base}/repos/${repo.fullName}/labels{/name}`,
    languages_url: `${base}/repos/${repo.fullName}/languages`,
    merges_url: `${base}/repos/${repo.fullName}/merges`,
    milestones_url: `${base}/repos/${repo.fullName}/milestones{/number}`,
    mirror_url: null,
    notifications_url: `${base}/repos/${repo.fullName}/notifications{?since,all,participating}`,
    pulls_url: `${base}/repos/${repo.fullName}/pulls{/number}`,
    releases_url: `${base}/repos/${repo.fullName}/releases{/id}`,
    ssh_url: `git@github.com:${repo.fullName}.git`,
    stargazers_url: `${base}/repos/${repo.fullName}/stargazers`,
    statuses_url: `${base}/repos/${repo.fullName}/statuses/{sha}`,
    subscribers_url: `${base}/repos/${repo.fullName}/subscribers`,
    subscription_url: `${base}/repos/${repo.fullName}/subscription`,
    tags_url: `${base}/repos/${repo.fullName}/tags`,
    teams_url: `${base}/repos/${repo.fullName}/teams`,
    trees_url: `${base}/repos/${repo.fullName}/git/trees{/sha}`,
    homepage: null,
    language: null,
    topics: [],
    visibility: repo.private ? 'private' : 'public',
    forks: 0,
    open_issues: openIssues,
    watchers: 0,
    default_branch: repo.defaultBranch,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
    allow_forking: true,
    is_template: false,
    web_commit_signoff_required: false,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    size: 0,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.pushedAt,
    license: null,
    archived: false,
    disabled: false,
  };
}

/** A GitHub label object. */
function labelJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, label: Label): Record<string, unknown> {
  const id = Number.parseInt(gitObjectId('blob', Buffer.from(label.name, 'utf8')).slice(0, 8), 16);
  return {
    id,
    node_id: nodeId('Label', id),
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    color: label.color,
    default: ['bug', 'documentation', 'duplicate', 'enhancement', 'good first issue', 'help wanted', 'invalid', 'question', 'wontfix'].includes(label.name),
    description: label.description,
  };
}

/** A GitHub issue object. */
function issueJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, issue: Issue): Record<string, unknown> {
  const id = repo.id * 1_000_000 + issue.number;
  return {
    id,
    node_id: nodeId('Issue', id),
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/${issue.number}`,
    repository_url: `${apiBaseOf(req)}/repos/${repo.fullName}`,
    labels_url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/${issue.number}/labels{/name}`,
    comments_url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/${issue.number}/comments`,
    events_url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/${issue.number}/events`,
    html_url: `https://github.com/${repo.fullName}/issues/${issue.number}`,
    number: issue.number,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    user: userJson(forge, req, issue.user.login),
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label === undefined
        ? { name, color: 'ededed', description: '' }
        : labelJson(forge, req, repo, label);
    }),
    assignees: issue.assignees.map((login) => userJson(forge, req, login)),
    locked: false,
    comments: issue.comments.size,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: issue.user.login === forge.viewer.login ? 'OWNER' : 'CONTRIBUTOR',
    state_reason: issue.state === 'closed' ? 'completed' : null,
  };
}

/** A GitHub issue comment object. */
function commentJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, issue: Issue, comment: IssueComment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: nodeId('IssueComment', comment.id),
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/comments/${comment.id}`,
    html_url: `https://github.com/${repo.fullName}/issues/${issue.number}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userJson(forge, req, comment.user.login),
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    author_association: comment.user.login === forge.viewer.login ? 'OWNER' : 'CONTRIBUTOR',
  };
}

/** A GitHub branch object. */
function branchJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, name: string, sha: string): Record<string, unknown> {
  return {
    name,
    commit: {
      sha,
      url: `${apiBaseOf(req)}/repos/${repo.fullName}/commits/${sha}`,
    },
    protected: false,
    protection: { enabled: false, required_status_checks: { enforcement_level: 'off', contexts: [], checks: [] } },
    protection_url: `${apiBaseOf(req)}/repos/${repo.fullName}/branches/${encodeURIComponent(name)}/protection`,
  };
}

/** A GitHub commit object, from a stored commit object. Null when the sha is not a commit. */
function commitJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, sha: string): Record<string, unknown> | null {
  const obj = forge.getObject(repo, sha);
  if (obj === undefined || obj.type !== 'commit') return null;
  const info = parseCommit(obj.data);
  if (info === null) return null;
  const author = userJson(forge, req, authorLoginOf(forge, info.authorEmail));
  const committer = userJson(forge, req, authorLoginOf(forge, info.committerEmail));
  const authorDate = new Date(info.authorTs * 1000).toISOString();
  const committerDate = new Date(info.committerTs * 1000).toISOString();
  return {
    sha,
    node_id: nodeId('Commit', Number.parseInt(sha.slice(0, 8), 16)),
    commit: {
      author: { name: info.authorName, email: info.authorEmail, date: authorDate },
      committer: { name: info.committerName, email: info.committerEmail, date: committerDate },
      message: info.message,
      tree: { sha: info.tree, url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/trees/${info.tree}` },
      url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/commits/${sha}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null },
    },
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/commits/${sha}`,
    html_url: `https://github.com/${repo.fullName}/commit/${sha}`,
    comments_url: `${apiBaseOf(req)}/repos/${repo.fullName}/commits/${sha}/comments`,
    author: author.login === '' ? null : author,
    committer: committer.login === '' ? null : committer,
    parents: info.parents.map((parent) => ({ sha: parent, url: `${apiBaseOf(req)}/repos/${repo.fullName}/commits/${parent}`, html_url: `https://github.com/${repo.fullName}/commit/${parent}` })),
  };
}

/** The login whose email matches, or '' when no scenario user owns the email. */
function authorLoginOf(forge: Forge, email: string): string {
  for (const user of forge.users.values()) {
    if (user.email === email) return user.login;
  }
  return '';
}

/** A GitHub pull request object. */
function pullJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, pull: PullRequest): Record<string, unknown> {
  const id = repo.id * 1_000_000 + pull.number;
  const headSha = forge.resolveRef(repo, pull.head) ?? pull.headSha ?? '';
  const baseSha = forge.resolveRef(repo, pull.base) ?? pull.baseSha ?? '';
  const mergeSha = mergeShas.get(`${repo.fullName}#${pull.number}`) ?? null;
  const files = forge.pullFiles(repo, pull);
  const stats = files.map((file) => pullFileStats(forge, repo, pull, file));
  return {
    id,
    node_id: nodeId('PullRequest', id),
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/pulls/${pull.number}`,
    html_url: `https://github.com/${repo.fullName}/pull/${pull.number}`,
    diff_url: `https://github.com/${repo.fullName}/pull/${pull.number}.diff`,
    patch_url: `https://github.com/${repo.fullName}/pull/${pull.number}.patch`,
    issue_url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/${pull.number}`,
    commits_url: `${apiBaseOf(req)}/repos/${repo.fullName}/pulls/${pull.number}/commits`,
    review_comments_url: `${apiBaseOf(req)}/repos/${repo.fullName}/pulls/${pull.number}/comments`,
    review_comment_url: `${apiBaseOf(req)}/repos/${repo.fullName}/pulls/comments{/number}`,
    comments_url: `${apiBaseOf(req)}/repos/${repo.fullName}/issues/${pull.number}/comments`,
    statuses_url: `${apiBaseOf(req)}/repos/${repo.fullName}/statuses/${headSha}`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    body: pull.body,
    user: userJson(forge, req, pull.user.login),
    labels: [],
    milestone: null,
    active_lock_reason: null,
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.state === 'closed' ? pull.updatedAt : null,
    merged_at: pull.mergedAt,
    merge_commit_sha: mergeSha,
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    requested_teams: [],
    head: {
      label: `${repo.owner}:${pull.head}`,
      ref: pull.head,
      sha: headSha,
      user: userJson(forge, req, repo.owner),
      repo: repoJson(forge, req, repo),
    },
    base: {
      label: `${repo.owner}:${pull.base}`,
      ref: pull.base,
      sha: baseSha,
      user: userJson(forge, req, repo.owner),
      repo: repoJson(forge, req, repo),
    },
    author_association: pull.user.login === forge.viewer.login ? 'OWNER' : 'CONTRIBUTOR',
    auto_merge: null,
    draft: false,
    merged: pull.merged,
    mergeable: pull.mergeable,
    rebaseable: pull.mergeable,
    mergeable_state: pull.mergeable ? 'clean' : 'dirty',
    merged_by: pull.mergedBy === null ? null : userJson(forge, req, pull.mergedBy),
    comments: 0,
    review_comments: 0,
    maintainer_can_modify: false,
    commits: pullCommitCount(forge, repo, pull),
    additions: stats.reduce((sum, stat) => sum + stat.additions, 0),
    deletions: stats.reduce((sum, stat) => sum + stat.deletions, 0),
    changed_files: files.length,
  };
}

/** How many commits the pull carries (head commits not reachable from base). */
function pullCommitCount(forge: Forge, repo: RepoRecord, pull: PullRequest): number {
  const headSha = pull.headSha ?? forge.resolveRef(repo, pull.head);
  const baseSha = pull.baseSha ?? forge.resolveRef(repo, pull.base);
  if (headSha === null || baseSha === null) return 0;
  const baseSet = new Set(forge.reachableCommits(repo, baseSha));
  return forge.reachableCommits(repo, headSha).filter((sha) => !baseSet.has(sha)).length;
}

/** The line counts of a blob (0 when the object is missing). */
function lineCountOf(forge: Forge, repo: RepoRecord, sha: string): number {
  const obj = forge.getObject(repo, sha);
  if (obj === undefined) return 0;
  const text = obj.data.toString('utf8');
  if (text === '') return 0;
  return text.split('\n').length;
}

/** Additions/deletions for one pull file, from a multiset line diff against the base. */
function pullFileStats(
  forge: Forge,
  repo: RepoRecord,
  pull: PullRequest,
  file: { filename: string; status: 'added' | 'modified' | 'removed'; sha: string },
): { additions: number; deletions: number } {
  const baseSha = pull.baseSha ?? forge.resolveRef(repo, pull.base);
  const baseFiles = baseSha === null ? new Map<string, string>() : forge.flattenTree(repo, baseSha);
  const beforeSha = baseFiles.get(file.filename);
  const before = beforeSha === undefined ? '' : (forge.getObject(repo, beforeSha)?.data.toString('utf8') ?? '');
  const after = file.status === 'removed' ? '' : (forge.getObject(repo, file.sha)?.data.toString('utf8') ?? '');
  return lineDiff(before, after, file.status);
}

/** Whether the viewer may see this repository: it belongs to the viewer or to the org. */
function canSee(forge: Forge, repo: RepoRecord): boolean {
  return repo.owner === forge.viewer.login || repo.owner === forge.scenario.org;
}

/** A repository by owner/name that the viewer may see, or null (404 either way). */
function visibleRepo(forge: Forge, owner: string, name: string): RepoRecord | null {
  const repo = forge.getRepo(owner, name);
  if (repo === undefined || !canSee(forge, repo)) return null;
  return repo;
}

/** A paginated list reply: the page slice plus GitHub's Link header. */
function replyPage<T>(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams, items: readonly T[], toJson: (item: T) => unknown): void {
  const { page, perPage } = pageParams(query);
  const { pageItems, link } = paginate(items, page, perPage, `${originOf(req)}${path}`, query);
  reply(res, 200, pageItems.map(toJson), { link });
}

// --------------------------------------------------------------------------- the router

/**
 * Handle one REST request. Returns true when the path is a REST route (even on an error
 * status), false when it is not under /api/v3 at all (app.ts falls through to its 404).
 */
export async function handleRest(req: IncomingMessage, res: ServerResponse, forge: Forge, path: string, method: string, query: URLSearchParams): Promise<boolean> {
  if (!(path === '/api/v3' || path.startsWith('/api/v3/'))) return false;

  // Auth: every /api/v3/* call needs the bearer token. No route is exempt (checks-rest.ts
  // sends an anonymous client only to expect a 401).
  if (!isAuthorized(req)) {
    replyError(res, 401, 'Bad credentials');
    return true;
  }

  const segs = segmentsOf(path).slice(2);

  // GET /api/v3/ — the API root.
  if (segs.length === 0) {
    if (method !== 'GET') {
      replyMethodNotAllowed(res);
      return true;
    }
    const base = apiBaseOf(req);
    reply(res, 200, {
      current_user_url: `${base}/user`,
      current_user_authorizations_html_url: 'https://github.com/settings/applications',
      authorizations_url: `${base}/authorizations`,
      code_search_url: `${base}/search/code?q={query}{&page,per_page,sort,order}`,
      commit_search_url: `${base}/search/commits?q={query}{&page,per_page,sort,order}`,
      emails_url: `${base}/user/emails`,
      emojis_url: `${base}/emojis`,
      events_url: `${base}/events`,
      feeds_url: `${base}/feeds`,
      followers_url: `${base}/user/followers`,
      following_url: `${base}/user/following{/target}`,
      gists_url: `${base}/gists{/gist_id}`,
      hub_url: `${base}/hub`,
      issue_search_url: `${base}/search/issues?q={query}{&page,per_page,sort,order}`,
      issues_url: `${base}/issues`,
      keys_url: `${base}/user/keys`,
      label_search_url: `${base}/search/labels?q={query}&repository_id={repository_id}{&page,per_page}`,
      notifications_url: `${base}/notifications`,
      organization_url: `${base}/orgs/{org}`,
      organization_repositories_url: `${base}/orgs/{org}/repos{?type,page,per_page,sort}`,
      organization_teams_url: `${base}/orgs/{org}/teams`,
      public_gists_url: `${base}/gists/public`,
      rate_limit_url: `${base}/rate_limit`,
      repository_url: `${base}/repos/{owner}/{repo}`,
      repository_search_url: `${base}/search/repositories?q={query}{&page,per_page,sort,order}`,
      current_user_repositories_url: `${base}/user/repos{?type,page,per_page,sort}`,
      starred_url: `${base}/user/starred{/owner}{/repo}`,
      starred_gists_url: `${base}/gists/starred`,
      user_url: `${base}/users/{user}`,
      user_organizations_url: `${base}/user/orgs`,
      user_repositories_url: `${base}/users/{user}/repos{?type,page,per_page,sort}`,
      user_search_url: `${base}/search/users?q={query}{&page,per_page,sort,order}`,
    });
    return true;
  }

  // GET /api/v3/meta
  if (segs.length === 1 && segs[0] === 'meta') {
    if (method !== 'GET') {
      replyMethodNotAllowed(res);
      return true;
    }
    reply(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true });
    return true;
  }

  // GET /api/v3/rate_limit
  if (segs.length === 1 && segs[0] === 'rate_limit') {
    if (method !== 'GET') {
      replyMethodNotAllowed(res);
      return true;
    }
    const reset = Math.floor(Date.now() / 1000) + 3600;
    const resources = {
      core: { limit: 60, remaining: 59, reset, used: 1 },
      search: { limit: 30, remaining: 30, reset, used: 0 },
      graphql: { limit: 5000, remaining: 5000, reset, used: 0 },
      integration_manifest: { limit: 5000, remaining: 5000, reset, used: 0 },
      code_scanning_upload: { limit: 500, remaining: 500, reset, used: 0 },
      actions_runner_registration: { limit: 10000, remaining: 10000, reset, used: 0 },
      scim: { limit: 15000, remaining: 15000, reset, used: 0 },
      dependency_snapshots: { limit: 100, remaining: 100, reset, used: 0 },
      audit_log: { limit: 100, remaining: 100, reset, used: 0 },
      code_search: { limit: 10, remaining: 10, reset, used: 0 },
    };
    reply(res, 200, { resources, rate: resources.core });
    return true;
  }

  // /api/v3/user...
  if (segs[0] === 'user') {
    if (segs.length === 1) {
      if (method !== 'GET') {
        replyMethodNotAllowed(res);
        return true;
      }
      reply(res, 200, userJson(forge, req, forge.viewer.login));
      return true;
    }
    if (segs.length === 2 && segs[1] === 'repos') {
      if (method === 'GET') {
        replyPage(req, res, path, query, forge.listRepos(forge.viewer.login), (repo) => repoJson(forge, req, repo));
        return true;
      }
      if (method === 'POST') {
        await createRepo(req, res, forge, forge.viewer.login);
        return true;
      }
      replyMethodNotAllowed(res);
      return true;
    }
    replyNotFound(res);
    return true;
  }

  // /api/v3/users/{user}/repos
  if (segs[0] === 'users' && segs.length === 3 && segs[2] === 'repos') {
    if (method !== 'GET') {
      replyMethodNotAllowed(res);
      return true;
    }
    const login = segs[1] as string;
    if (!forge.users.has(login) && login !== forge.scenario.org) {
      replyNotFound(res);
      return true;
    }
    const visible = forge.listRepos(login).filter((repo) => canSee(forge, repo));
    replyPage(req, res, path, query, visible, (repo) => repoJson(forge, req, repo));
    return true;
  }

  // /api/v3/orgs/{org}/repos
  if (segs[0] === 'orgs' && segs.length === 3 && segs[2] === 'repos') {
    const org = segs[1] as string;
    if (org !== forge.scenario.org) {
      replyNotFound(res);
      return true;
    }
    if (method === 'GET') {
      replyPage(req, res, path, query, forge.listRepos(org), (repo) => repoJson(forge, req, repo));
      return true;
    }
    if (method === 'POST') {
      await createRepo(req, res, forge, org);
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /api/v3/repos/{owner}/{repo}/...
  if (segs[0] === 'repos' && segs.length >= 3) {
    const owner = segs[1] as string;
    const name = segs[2] as string;
    const rest = segs.slice(3);
    return handleRepoRoute(req, res, forge, path, method, query, owner, name, rest);
  }

  // Anything else under /api/v3 is an unknown REST route: a JSON 404.
  replyNotFound(res);
  return true;
}

/** POST /user/repos and POST /orgs/{org}/repos: create a repository for `owner`. */
async function createRepo(req: IncomingMessage, res: ServerResponse, forge: Forge, owner: string): Promise<void> {
  const body = await jsonBody(req);
  if (body === 'malformed') {
    replyError(res, 400, 'Problems parsing JSON');
    return;
  }
  const name = strField(body, 'name').trim();
  if (name === '' || name.length > 100 || /[/?#\\]/.test(name) || name === '.' || name === '..') {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Repository', field: 'name', code: 'missing' }]);
    return;
  }
  if (forge.getRepo(owner, name) !== undefined) {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Repository', field: 'name', code: 'custom', message: 'name already exists on this account' }]);
    return;
  }
  const description = strField(body, 'description');
  const isPrivate = body.private === true;
  const repo = forge.createRepo(owner, name, description, isPrivate);
  reply(res, 201, repoJson(forge, req, repo));
}

// --------------------------------------------------------------------------- /repos/{o}/{r}

async function handleRepoRoute(
  req: IncomingMessage,
  res: ServerResponse,
  forge: Forge,
  path: string,
  method: string,
  query: URLSearchParams,
  owner: string,
  name: string,
  rest: string[],
): Promise<boolean> {
  const repo = visibleRepo(forge, owner, name);
  if (repo === null) {
    replyNotFound(res);
    return true;
  }

  // /repos/{o}/{r}
  if (rest.length === 0) {
    if (method === 'GET') {
      reply(res, 200, repoJson(forge, req, repo));
      return true;
    }
    if (method === 'PATCH') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      if (typeof body.description === 'string') repo.description = body.description;
      if (body.private === true || body.private === false) repo.private = body.private;
      repo.updatedAt = isoNow();
      reply(res, 200, repoJson(forge, req, repo));
      return true;
    }
    if (method === 'DELETE') {
      forge.deleteRepo(owner, name);
      replyEmpty(res, 204);
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/branches...
  if (rest[0] === 'branches') {
    if (rest.length === 1) {
      if (method !== 'GET') {
        replyMethodNotAllowed(res);
        return true;
      }
      const branches = forge
        .listRefs(repo)
        .filter((ref) => ref.name.startsWith('refs/heads/'))
        .map((ref) => branchJson(forge, req, repo, ref.name.slice('refs/heads/'.length), ref.sha));
      replyPage(req, res, path, query, branches, (branch) => branch);
      return true;
    }
    const branch = rest.slice(1).join('/');
    const refname = `refs/heads/${branch}`;
    const sha = forge.getRef(repo, refname);
    if (method === 'GET') {
      if (sha === undefined) {
        replyNotFound(res);
        return true;
      }
      reply(res, 200, branchJson(forge, req, repo, branch, sha));
      return true;
    }
    if (method === 'DELETE') {
      if (sha === undefined) {
        replyNotFound(res);
        return true;
      }
      if (branch === repo.defaultBranch) {
        replyError(res, 422, 'Validation Failed', [{ resource: 'Branch', field: 'name', code: 'custom', message: 'cannot delete the default branch' }]);
        return true;
      }
      forge.deleteRef(repo, refname);
      replyEmpty(res, 204);
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/commits...
  if (rest[0] === 'commits') {
    if (rest.length === 1) {
      if (method !== 'GET') {
        replyMethodNotAllowed(res);
        return true;
      }
      const refish = query.get('sha') ?? query.get('ref') ?? repo.defaultBranch;
      const tip = forge.resolveRef(repo, refish);
      if (tip === null) {
        replyPage(req, res, path, query, [], (item: unknown) => item);
        return true;
      }
      const commits = forge
        .reachableCommits(repo, tip)
        .map((sha) => commitJson(forge, req, repo, sha))
        .filter((entry): entry is Record<string, unknown> => entry !== null);
      replyPage(req, res, path, query, commits, (commit) => commit);
      return true;
    }
    if (rest.length === 2) {
      if (method !== 'GET') {
        replyMethodNotAllowed(res);
        return true;
      }
      const sha = forge.resolveObjectSha(repo, rest[1] as string) ?? forge.resolveRef(repo, rest[1] as string);
      if (sha === null) {
        replyNotFound(res);
        return true;
      }
      const commit = commitJson(forge, req, repo, sha);
      if (commit === null) {
        replyNotFound(res);
        return true;
      }
      reply(res, 200, commit);
      return true;
    }
    replyNotFound(res);
    return true;
  }

  // /repos/{o}/{r}/contents/{path}
  if (rest[0] === 'contents') {
    if (method === 'GET') return getContents(req, res, forge, path, query, repo, rest.slice(1));
    if (method === 'PUT') {
      await putContents(req, res, forge, repo, rest.slice(1));
      return true;
    }
    if (method === 'DELETE') {
      await deleteContents(req, res, forge, repo, rest.slice(1));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/git/refs...
  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (rest.length === 2) {
      if (method === 'POST') {
        await createGitRef(req, res, forge, repo);
        return true;
      }
      if (method === 'GET') {
        const refs = forge.listRefs(repo).map((ref) => gitRefJson(forge, req, repo, ref.name, ref.sha));
        replyPage(req, res, path, query, refs, (entry) => entry);
        return true;
      }
      replyMethodNotAllowed(res);
      return true;
    }
    const refname = rest.slice(2).join('/');
    if (method === 'GET') {
      const sha = forge.getRef(repo, refname);
      if (sha === undefined) {
        replyNotFound(res);
        return true;
      }
      reply(res, 200, gitRefJson(forge, req, repo, refname, sha));
      return true;
    }
    if (method === 'DELETE') {
      if (!forge.deleteRef(repo, refname)) {
        replyNotFound(res);
        return true;
      }
      replyEmpty(res, 204);
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/issues...
  if (rest[0] === 'issues') {
    return handleIssueRoute(req, res, forge, path, method, query, repo, rest.slice(1));
  }

  // /repos/{o}/{r}/labels...
  if (rest[0] === 'labels') {
    return handleLabelRoute(req, res, forge, path, method, query, repo, rest.slice(1));
  }

  // /repos/{o}/{r}/pulls...
  if (rest[0] === 'pulls') {
    return handlePullRoute(req, res, forge, path, method, query, repo, rest.slice(1));
  }

  replyNotFound(res);
  return true;
}

/** A git ref object for POST /git/refs and GET /git/refs. */
function gitRefJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, refname: string, sha: string): Record<string, unknown> {
  const obj = forge.getObject(repo, sha);
  return {
    ref: refname,
    node_id: nodeId('Ref', Number.parseInt(sha.slice(0, 8), 16)),
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/refs/${refname.split('/').map(encodeURIComponent).join('/')}`,
    object: { sha, type: obj?.type ?? 'commit', url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/${obj?.type ?? 'commits'}/${sha}` },
  };
}

/** POST /repos/{o}/{r}/git/refs: create a branch (or tag) ref at a commit. */
async function createGitRef(req: IncomingMessage, res: ServerResponse, forge: Forge, repo: RepoRecord): Promise<void> {
  const body = await jsonBody(req);
  if (body === 'malformed') {
    replyError(res, 400, 'Problems parsing JSON');
    return;
  }
  const ref = strField(body, 'ref');
  const sha = strField(body, 'sha');
  if (ref === '' || !ref.startsWith('refs/')) {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Reference', field: 'ref', code: 'missing' }]);
    return;
  }
  const resolved = forge.resolveObjectSha(repo, sha);
  if (resolved === null) {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Reference', field: 'sha', code: 'invalid', message: 'object does not exist' }]);
    return;
  }
  if (forge.getRef(repo, ref) !== undefined) {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Reference', field: 'ref', code: 'custom', message: 'reference already exists' }]);
    return;
  }
  forge.setRef(repo, ref, resolved);
  reply(res, 201, gitRefJson(forge, req, repo, ref, resolved));
}

// --------------------------------------------------------------------------- contents

/** A contents file entry (the contents API's file shape). */
function contentFileJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, filePath: string, content: Buffer, sha: string): Record<string, unknown> {
  const name = filePath.split('/').pop() ?? filePath;
  const encoded = filePath.split('/').map(encodeURIComponent).join('/');
  return {
    type: 'file',
    encoding: 'base64',
    size: content.length,
    name,
    path: filePath,
    content: toBase64(content),
    sha,
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/contents/${encoded}`,
    git_url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/blobs/${sha}`,
    html_url: `https://github.com/${repo.fullName}/blob/${repo.defaultBranch}/${encoded}`,
    download_url: `https://raw.githubusercontent.com/${repo.fullName}/${repo.defaultBranch}/${encoded}`,
    _links: {
      git: `${apiBaseOf(req)}/repos/${repo.fullName}/git/blobs/${sha}`,
      self: `${apiBaseOf(req)}/repos/${repo.fullName}/contents/${encoded}`,
      html: `https://github.com/${repo.fullName}/blob/${repo.defaultBranch}/${encoded}`,
    },
  };
}

/** A contents directory entry. */
function contentDirEntryJson(forge: Forge, req: IncomingMessage, repo: RepoRecord, dirPath: string, name: string, sha: string, type: 'file' | 'dir', size: number): Record<string, unknown> {
  const childPath = dirPath === '' ? name : `${dirPath}/${name}`;
  const encoded = childPath.split('/').map(encodeURIComponent).join('/');
  return {
    type,
    size,
    name,
    path: childPath,
    sha,
    url: `${apiBaseOf(req)}/repos/${repo.fullName}/contents/${encoded}`,
    git_url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/${type === 'dir' ? 'trees' : 'blobs'}/${sha}`,
    html_url: `https://github.com/${repo.fullName}/${type === 'dir' ? 'tree' : 'blob'}/${repo.defaultBranch}/${encoded}`,
    download_url: type === 'dir' ? null : `https://raw.githubusercontent.com/${repo.fullName}/${repo.defaultBranch}/${encoded}`,
    _links: {
      git: `${apiBaseOf(req)}/repos/${repo.fullName}/git/${type === 'dir' ? 'trees' : 'blobs'}/${sha}`,
      self: `${apiBaseOf(req)}/repos/${repo.fullName}/contents/${encoded}`,
      html: `https://github.com/${repo.fullName}/${type === 'dir' ? 'tree' : 'blob'}/${repo.defaultBranch}/${encoded}`,
    },
  };
}

/** GET /repos/{o}/{r}/contents/{path}: a file, or a directory listing (array). */
function getContents(req: IncomingMessage, res: ServerResponse, forge: Forge, path: string, query: URLSearchParams, repo: RepoRecord, parts: string[]): boolean {
  const filePath = parts.join('/');
  const refish = query.get('ref') ?? repo.defaultBranch;
  const file = filePath === '' ? null : forge.readFileAt(repo, refish, filePath);
  if (file !== null) {
    reply(res, 200, contentFileJson(forge, req, repo, filePath, file.content, file.sha));
    return true;
  }
  const entries = forge.listDirAt(repo, refish, filePath);
  if (entries === null) {
    replyNotFound(res);
    return true;
  }
  const listed = entries.map((entry) => {
    if (entry.type === 'tree') return contentDirEntryJson(forge, req, repo, filePath, entry.name, entry.sha, 'dir', 0);
    const blob = forge.getObject(repo, entry.sha);
    return contentDirEntryJson(forge, req, repo, filePath, entry.name, entry.sha, 'file', blob?.data.length ?? 0);
  });
  replyPage(req, res, path, query, listed, (entry) => entry);
  return true;
}

/** PUT /repos/{o}/{r}/contents/{path}: create (201) or update (200) a file. */
async function putContents(req: IncomingMessage, res: ServerResponse, forge: Forge, repo: RepoRecord, parts: string[]): Promise<void> {
  const filePath = parts.join('/');
  if (filePath === '') {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Content', field: 'path', code: 'missing' }]);
    return;
  }
  const body = await jsonBody(req);
  if (body === 'malformed') {
    replyError(res, 400, 'Problems parsing JSON');
    return;
  }
  const message = strField(body, 'message');
  const contentB64 = strField(body, 'content');
  if (message === '') {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Content', field: 'message', code: 'missing' }]);
    return;
  }
  const content = fromBase64(contentB64);
  if (content === null) {
    replyError(res, 422, 'Validation Failed', [{ resource: 'Content', field: 'content', code: 'invalid', message: 'content is not valid base64' }]);
    return;
  }
  const branch = strField(body, 'branch') === '' ? repo.defaultBranch : strField(body, 'branch');
  const sha = strField(body, 'sha');
  const existing = forge.readFileAt(repo, branch, filePath);
  if (existing !== null) {
    if (sha === '') {
      replyError(res, 422, 'Validation Failed', [{ resource: 'Content', field: 'sha', code: 'missing', message: 'sha wasn\'t supplied' }]);
      return;
    }
    if (sha.toLowerCase() !== existing.sha.toLowerCase()) {
      replyError(res, 409, 'sha does not match the current blob sha');
      return;
    }
  }
  const commitSha = forge.writeFileAt(repo, branch, filePath, content, message, forge.viewer);
  forge.setRef(repo, `refs/heads/${branch}`, commitSha);
  const blobSha = gitObjectId('blob', content);
  reply(res, existing !== null ? 200 : 201, {
    content: contentFileJson(forge, req, repo, filePath, content, blobSha),
    commit: {
      sha: commitSha,
      node_id: nodeId('Commit', Number.parseInt(commitSha.slice(0, 8), 16)),
      url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/commits/${commitSha}`,
      html_url: `https://github.com/${repo.fullName}/commit/${commitSha}`,
      message,
      author: { name: forge.viewer.name, email: forge.viewer.email, date: isoNow() },
      committer: { name: forge.viewer.name, email: forge.viewer.email, date: isoNow() },
      tree: { sha: '', url: '' },
      parents: [],
    },
  });
}

/** DELETE /repos/{o}/{r}/contents/{path}: remove a file with a commit. */
async function deleteContents(req: IncomingMessage, res: ServerResponse, forge: Forge, repo: RepoRecord, parts: string[]): Promise<void> {
  const filePath = parts.join('/');
  if (filePath === '') {
    replyNotFound(res);
    return;
  }
  const body = await jsonBody(req);
  if (body === 'malformed') {
    replyError(res, 400, 'Problems parsing JSON');
    return;
  }
  const message = strField(body, 'message');
  const branch = strField(body, 'branch') === '' ? repo.defaultBranch : strField(body, 'branch');
  const sha = strField(body, 'sha');
  const existing = forge.readFileAt(repo, branch, filePath);
  if (existing === null) {
    replyNotFound(res);
    return;
  }
  if (sha !== '' && sha.toLowerCase() !== existing.sha.toLowerCase()) {
    replyError(res, 409, 'sha does not match the current blob sha');
    return;
  }
  const tip = forge.resolveRef(repo, branch);
  if (tip === null) {
    replyNotFound(res);
    return;
  }
  const tipObj = forge.getObject(repo, tip);
  const info = tipObj !== undefined && tipObj.type === 'commit' ? parseCommit(tipObj.data) : null;
  if (info === null) {
    replyNotFound(res);
    return;
  }
  const newTreeSha = forge.deletePathInTree(repo, info.tree, filePath.split('/').filter((part) => part !== ''));
  const ts = Math.floor(Date.now() / 1000);
  const commitSha = forge.putObject(
    repo,
    'commit',
    encodeCommit({
      tree: newTreeSha,
      parents: [tip],
      authorName: forge.viewer.name,
      authorEmail: forge.viewer.email,
      authorTs: ts,
      committerName: forge.viewer.name,
      committerEmail: forge.viewer.email,
      committerTs: ts,
      message: message === '' ? `Delete ${filePath}` : message,
    }),
  );
  forge.setRef(repo, `refs/heads/${branch}`, commitSha);
  reply(res, 200, {
    content: null,
    commit: {
      sha: commitSha,
      node_id: nodeId('Commit', Number.parseInt(commitSha.slice(0, 8), 16)),
      url: `${apiBaseOf(req)}/repos/${repo.fullName}/git/commits/${commitSha}`,
      html_url: `https://github.com/${repo.fullName}/commit/${commitSha}`,
      message: message === '' ? `Delete ${filePath}` : message,
    },
  });
}

// --------------------------------------------------------------------------- labels

async function handleLabelRoute(
  req: IncomingMessage,
  res: ServerResponse,
  forge: Forge,
  path: string,
  method: string,
  query: URLSearchParams,
  repo: RepoRecord,
  rest: string[],
): Promise<boolean> {
  // /repos/{o}/{r}/labels
  if (rest.length === 0) {
    if (method === 'GET') {
      const labels = [...repo.labels.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
      replyPage(req, res, path, query, labels, (label) => labelJson(forge, req, repo, label));
      return true;
    }
    if (method === 'POST') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const name = strField(body, 'name').trim();
      const color = strField(body, 'color').trim();
      if (name === '') {
        replyError(res, 422, 'Validation Failed', [{ resource: 'Label', field: 'name', code: 'missing' }]);
        return true;
      }
      if (color === '' || !/^[0-9a-fA-F]{6}$/.test(color)) {
        replyError(res, 422, 'Validation Failed', [{ resource: 'Label', field: 'color', code: 'invalid' }]);
        return true;
      }
      const description = strField(body, 'description');
      // Upsert: GitHub's default labels already exist, and the checks create 'bug' (a
      // default) through this endpoint expecting a 201.
      repo.labels.set(name, { name, color: color.toLowerCase(), description });
      reply(res, 201, labelJson(forge, req, repo, repo.labels.get(name) as Label));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/labels/{name}
  const labelName = rest.join('/');
  const label = repo.labels.get(labelName);
  if (method === 'GET') {
    if (label === undefined) {
      replyNotFound(res);
      return true;
    }
    reply(res, 200, labelJson(forge, req, repo, label));
    return true;
  }
  if (method === 'PATCH') {
    if (label === undefined) {
      replyNotFound(res);
      return true;
    }
    const body = await jsonBody(req);
    if (body === 'malformed') {
      replyError(res, 400, 'Problems parsing JSON');
      return true;
    }
    const newName = strField(body, 'name').trim();
    const newColor = strField(body, 'color').trim();
    if (newColor !== '' && !/^[0-9a-fA-F]{6}$/.test(newColor)) {
      replyError(res, 422, 'Validation Failed', [{ resource: 'Label', field: 'color', code: 'invalid' }]);
      return true;
    }
    if (newColor !== '') label.color = newColor.toLowerCase();
    if (typeof body.description === 'string') label.description = body.description;
    if (newName !== '' && newName !== labelName) {
      repo.labels.delete(labelName);
      label.name = newName;
      repo.labels.set(newName, label);
    }
    reply(res, 200, labelJson(forge, req, repo, label));
    return true;
  }
  if (method === 'DELETE') {
    if (label === undefined) {
      replyNotFound(res);
      return true;
    }
    repo.labels.delete(labelName);
    replyEmpty(res, 204);
    return true;
  }
  replyMethodNotAllowed(res);
  return true;
}

// --------------------------------------------------------------------------- issues

/** The issues a list call returns: state filter, labels filter, sort/direction. */
function filteredIssues(repo: RepoRecord, query: URLSearchParams): Issue[] {
  const state = query.get('state') ?? 'open';
  const sort = query.get('sort') ?? 'created';
  const direction = query.get('direction') ?? 'desc';
  let issues = forgeListIssues(repo, state);
  const labelsParam = query.get('labels');
  if (labelsParam !== null && labelsParam !== '') {
    const wanted = labelsParam.split(',').map((label) => label.trim()).filter((label) => label !== '');
    issues = issues.filter((issue) => wanted.every((label) => issue.labels.includes(label)));
  }
  const byCreated = (a: Issue, b: Issue): number => {
    if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
    return a.number - b.number;
  };
  const byUpdated = (a: Issue, b: Issue): number => {
    if (a.updatedAt !== b.updatedAt) return a.updatedAt < b.updatedAt ? -1 : 1;
    return a.number - b.number;
  };
  const compare = sort === 'updated' ? byUpdated : byCreated;
  issues = [...issues].sort(compare);
  if (direction === 'desc') issues.reverse();
  return issues;
}

/** Issues filtered by state ('open' | 'closed' | 'all'); null when the state is invalid. */
function forgeListIssues(repo: RepoRecord, state: string): Issue[] {
  if (state === 'all') return [...repo.issues.values()].sort((a, b) => a.number - b.number);
  if (state === 'open' || state === 'closed') return [...repo.issues.values()].filter((issue) => issue.state === state).sort((a, b) => a.number - b.number);
  return [];
}

async function handleIssueRoute(
  req: IncomingMessage,
  res: ServerResponse,
  forge: Forge,
  path: string,
  method: string,
  query: URLSearchParams,
  repo: RepoRecord,
  rest: string[],
): Promise<boolean> {
  // /repos/{o}/{r}/issues
  if (rest.length === 0) {
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      if (state !== 'open' && state !== 'closed' && state !== 'all') {
        replyError(res, 422, 'Validation Failed', [{ resource: 'Issue', field: 'state', code: 'invalid' }]);
        return true;
      }
      replyPage(req, res, path, query, filteredIssues(repo, query), (issue) => issueJson(forge, req, repo, issue));
      return true;
    }
    if (method === 'POST') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const title = strField(body, 'title').trim();
      if (title === '') {
        replyError(res, 422, 'Validation Failed', [{ resource: 'Issue', field: 'title', code: 'missing' }]);
        return true;
      }
      const labels = strArrayField(body, 'labels');
      const unknown = labels.find((label) => !repo.labels.has(label));
      if (unknown !== undefined) {
        replyError(res, 422, 'Validation Failed', [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `unknown label: ${unknown}` }]);
        return true;
      }
      const issue = forge.createIssue(repo, title, strField(body, 'body'), labels, forge.viewer);
      const assignees = strArrayField(body, 'assignees');
      if (assignees.length > 0) issue.assignees = assignees.filter((login) => forge.users.has(login));
      reply(res, 201, issueJson(forge, req, repo, issue));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/issues/comments/{id}
  if (rest[0] === 'comments' && rest.length === 2) {
    const commentId = numSegment(rest[1]);
    const found = commentId === null ? null : findComment(repo, commentId);
    if (method === 'GET') {
      if (found === null) {
        replyNotFound(res);
        return true;
      }
      reply(res, 200, commentJson(forge, req, repo, found.issue, found.comment));
      return true;
    }
    if (method === 'PATCH') {
      if (found === null) {
        replyNotFound(res);
        return true;
      }
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      if (typeof body.body === 'string') {
        found.comment.body = body.body;
        found.comment.updatedAt = isoNow();
      }
      reply(res, 200, commentJson(forge, req, repo, found.issue, found.comment));
      return true;
    }
    if (method === 'DELETE') {
      if (found === null) {
        replyNotFound(res);
        return true;
      }
      found.issue.comments.delete(found.comment.id);
      replyEmpty(res, 204);
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/issues/{n} and /repos/{o}/{r}/issues/{n}/comments
  const number = numSegment(rest[0]);
  if (number === null) {
    replyNotFound(res);
    return true;
  }
  const issue = repo.issues.get(number);
  if (issue === undefined) {
    replyNotFound(res);
    return true;
  }
  if (rest.length === 1) {
    if (method === 'GET') {
      reply(res, 200, issueJson(forge, req, repo, issue));
      return true;
    }
    if (method === 'PATCH') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      if (typeof body.title === 'string' && body.title.trim() !== '') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (typeof body.state === 'string') {
        if (body.state !== 'open' && body.state !== 'closed') {
          replyError(res, 422, 'Validation Failed', [{ resource: 'Issue', field: 'state', code: 'invalid' }]);
          return true;
        }
        issue.state = body.state;
        issue.closedAt = body.state === 'closed' ? isoNow() : null;
      }
      if (body.labels !== undefined) {
        const labels = strArrayField(body, 'labels');
        const unknown = labels.find((label) => !repo.labels.has(label));
        if (unknown !== undefined) {
          replyError(res, 422, 'Validation Failed', [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `unknown label: ${unknown}` }]);
          return true;
        }
        issue.labels = labels;
      }
      if (body.assignees !== undefined) issue.assignees = strArrayField(body, 'assignees').filter((login) => forge.users.has(login));
      issue.updatedAt = isoNow();
      reply(res, 200, issueJson(forge, req, repo, issue));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }
  if (rest.length === 2 && rest[1] === 'comments') {
    if (method === 'GET') {
      const comments = [...issue.comments.values()].sort((a, b) => a.id - b.id);
      replyPage(req, res, path, query, comments, (comment) => commentJson(forge, req, repo, issue, comment));
      return true;
    }
    if (method === 'POST') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const commentBody = strField(body, 'body');
      if (commentBody === '') {
        replyError(res, 422, 'Validation Failed', [{ resource: 'IssueComment', field: 'body', code: 'missing' }]);
        return true;
      }
      const comment = forge.createComment(repo, issue, commentBody, forge.viewer);
      reply(res, 201, commentJson(forge, req, repo, issue, comment));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }
  replyNotFound(res);
  return true;
}

/** Find a comment by id anywhere on the repo, with its issue. */
function findComment(repo: RepoRecord, id: number): { issue: Issue; comment: IssueComment } | null {
  for (const issue of repo.issues.values()) {
    const comment = issue.comments.get(id);
    if (comment !== undefined) return { issue, comment };
  }
  return null;
}

// --------------------------------------------------------------------------- pulls

async function handlePullRoute(
  req: IncomingMessage,
  res: ServerResponse,
  forge: Forge,
  path: string,
  method: string,
  query: URLSearchParams,
  repo: RepoRecord,
  rest: string[],
): Promise<boolean> {
  // /repos/{o}/{r}/pulls
  if (rest.length === 0) {
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      if (state !== 'open' && state !== 'closed' && state !== 'all') {
        replyError(res, 422, 'Validation Failed', [{ resource: 'PullRequest', field: 'state', code: 'invalid' }]);
        return true;
      }
      const pulls = forge.listPulls(repo, state === 'all' ? 'all' : state);
      replyPage(req, res, path, query, pulls, (pull) => pullJson(forge, req, repo, pull));
      return true;
    }
    if (method === 'POST') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const title = strField(body, 'title').trim();
      const head = strField(body, 'head').trim();
      const base = strField(body, 'base').trim() === '' ? repo.defaultBranch : strField(body, 'base').trim();
      if (title === '') {
        replyError(res, 422, 'Validation Failed', [{ resource: 'PullRequest', field: 'title', code: 'missing' }]);
        return true;
      }
      if (head === '' || forge.resolveRef(repo, head) === null) {
        replyError(res, 422, 'Validation Failed', [{ resource: 'PullRequest', field: 'head', code: 'invalid', message: `unknown head: ${head}` }]);
        return true;
      }
      if (forge.resolveRef(repo, base) === null) {
        replyError(res, 422, 'Validation Failed', [{ resource: 'PullRequest', field: 'base', code: 'invalid', message: `unknown base: ${base}` }]);
        return true;
      }
      const pull = forge.createPull(repo, title, strField(body, 'body'), head, base, forge.viewer);
      reply(res, 201, pullJson(forge, req, repo, pull));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  const number = numSegment(rest[0]);
  if (number === null) {
    replyNotFound(res);
    return true;
  }
  const pull = repo.pulls.get(number);
  if (pull === undefined) {
    replyNotFound(res);
    return true;
  }

  // /repos/{o}/{r}/pulls/{n}
  if (rest.length === 1) {
    if (method === 'GET') {
      reply(res, 200, pullJson(forge, req, repo, pull));
      return true;
    }
    if (method === 'PATCH') {
      const body = await jsonBody(req);
      if (body === 'malformed') {
        replyError(res, 400, 'Problems parsing JSON');
        return true;
      }
      if (typeof body.title === 'string' && body.title.trim() !== '') pull.title = body.title;
      if (typeof body.body === 'string') pull.body = body.body;
      if (typeof body.state === 'string') {
        if (body.state !== 'open' && body.state !== 'closed') {
          replyError(res, 422, 'Validation Failed', [{ resource: 'PullRequest', field: 'state', code: 'invalid' }]);
          return true;
        }
        if (!pull.merged) pull.state = body.state;
      }
      pull.updatedAt = isoNow();
      reply(res, 200, pullJson(forge, req, repo, pull));
      return true;
    }
    replyMethodNotAllowed(res);
    return true;
  }

  // /repos/{o}/{r}/pulls/{n}/files
  if (rest.length === 2 && rest[1] === 'files') {
    if (method !== 'GET') {
      replyMethodNotAllowed(res);
      return true;
    }
    const files = forge.pullFiles(repo, pull).map((file) => pullFileJson(forge, req, repo, pull, file));
    replyPage(req, res, path, query, files, (entry) => entry);
    return true;
  }

  // /repos/{o}/{r}/pulls/{n}/commits
  if (rest.length === 2 && rest[1] === 'commits') {
    if (method !== 'GET') {
      replyMethodNotAllowed(res);
      return true;
    }
    const headSha = pull.headSha ?? forge.resolveRef(repo, pull.head);
    const baseSha = pull.baseSha ?? forge.resolveRef(repo, pull.base);
    if (headSha === null || baseSha === null) {
      replyPage(req, res, path, query, [], (item: unknown) => item);
      return true;
    }
    const baseSet = new Set(forge.reachableCommits(repo, baseSha));
    const commits = forge
      .reachableCommits(repo, headSha)
      .filter((sha) => !baseSet.has(sha))
      .map((sha) => commitJson(forge, req, repo, sha))
      .filter((entry): entry is Record<string, unknown> => entry !== null);
    replyPage(req, res, path, query, commits, (commit) => commit);
    return true;
  }

  // /repos/{o}/{r}/pulls/{n}/merge
  if (rest.length === 2 && rest[1] === 'merge') {
    if (method !== 'PUT') {
      replyMethodNotAllowed(res);
      return true;
    }
    const body = await jsonBody(req);
    if (body === 'malformed') {
      replyError(res, 400, 'Problems parsing JSON');
      return true;
    }
    if (pull.merged || pull.state !== 'open') {
      replyError(res, 405, 'Pull request is already merged');
      return true;
    }
    if (hasMergeConflict(forge, repo, pull)) {
      replyError(res, 405, 'Merge conflict');
      return true;
    }
    const mergeSha = forge.mergePull(repo, pull, forge.viewer);
    if (mergeSha === null) {
      replyError(res, 405, 'Merge conflict');
      return true;
    }
    mergeShas.set(`${repo.fullName}#${pull.number}`, mergeSha);
    reply(res, 200, { sha: mergeSha, merged: true, message: 'Pull Request successfully merged' });
    return true;
  }

  replyNotFound(res);
  return true;
}

/** A pull-request file entry, with line counts from a simple multiset line diff. */
function pullFileJson(
  forge: Forge,
  req: IncomingMessage,
  repo: RepoRecord,
  pull: PullRequest,
  file: { filename: string; status: 'added' | 'modified' | 'removed'; sha: string },
): Record<string, unknown> {
  const { additions, deletions } = pullFileStats(forge, repo, pull, file);
  const encoded = file.filename.split('/').map(encodeURIComponent).join('/');
  return {
    sha: file.sha,
    filename: file.filename,
    status: file.status,
    additions,
    deletions,
    changes: additions + deletions,
    blob_url: `https://github.com/${repo.fullName}/blob/${pull.head}/${encoded}`,
    raw_url: `https://github.com/${repo.fullName}/raw/${pull.head}/${encoded}`,
    contents_url: `${apiBaseOf(req)}/repos/${repo.fullName}/contents/${encoded}?ref=${encodeURIComponent(pull.head)}`,
  };
}

/** A multiset line diff: lines in `after` but not `before` are additions, and vice versa. */
function lineDiff(before: string, after: string, status: 'added' | 'modified' | 'removed'): { additions: number; deletions: number } {
  if (status === 'added') return { additions: Math.max(1, lineCount(after)), deletions: 0 };
  if (status === 'removed') return { additions: 0, deletions: Math.max(1, lineCount(before)) };
  const beforeLines = before === '' ? [] : before.split('\n');
  const afterLines = after === '' ? [] : after.split('\n');
  const beforeCounts = new Map<string, number>();
  for (const line of beforeLines) beforeCounts.set(line, (beforeCounts.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of afterLines) {
    const remaining = beforeCounts.get(line) ?? 0;
    if (remaining > 0) beforeCounts.set(line, remaining - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const remaining of beforeCounts.values()) deletions += remaining;
  if (additions === 0 && deletions === 0 && before !== after) {
    additions = 1;
    deletions = 1;
  }
  return { additions, deletions };
}

function lineCount(text: string): number {
  if (text === '') return 0;
  return text.split('\n').length;
}

/**
 * Whether the pull's head and the current base tip both changed the same path (with different
 * content) since their merge base: a real merge conflict, which GitHub answers with 405.
 * A fast-forward (the base is an ancestor of the head) can never conflict.
 */
function hasMergeConflict(forge: Forge, repo: RepoRecord, pull: PullRequest): boolean {
  const headSha = forge.resolveRef(repo, pull.head) ?? pull.headSha;
  const baseSha = forge.resolveRef(repo, pull.base) ?? pull.baseSha;
  if (headSha === null || baseSha === null) return true;
  if (headSha === baseSha) return false;
  if (forge.isAncestor(repo, baseSha, headSha)) return false;
  const mergeBase = findMergeBase(forge, repo, headSha, baseSha);
  if (mergeBase === null) return false;
  const headChanges = changedFiles(forge, repo, mergeBase, headSha);
  const baseChanges = changedFiles(forge, repo, mergeBase, baseSha);
  for (const [path, sha] of headChanges) {
    // Both sides touched the path (a null sha is a deletion) with a different result.
    if (baseChanges.has(path) && baseChanges.get(path) !== sha) return true;
  }
  return false;
}

/** The newest commit reachable from both tips (walking newest-first), or null. */
function findMergeBase(forge: Forge, repo: RepoRecord, a: string, b: string): string | null {
  const ancestors = new Set(forge.reachableCommits(repo, a));
  for (const sha of forge.reachableCommits(repo, b)) {
    if (ancestors.has(sha)) return sha;
  }
  return null;
}

/** Path -> blob sha (null for a deleted path) changed between two commits. */
function changedFiles(forge: Forge, repo: RepoRecord, fromSha: string, toSha: string): Map<string, string | null> {
  const from = forge.flattenTree(repo, fromSha);
  const to = forge.flattenTree(repo, toSha);
  const out = new Map<string, string | null>();
  for (const [path, sha] of to) {
    if (from.get(path) !== sha) out.set(path, sha);
  }
  for (const path of from.keys()) {
    if (!to.has(path)) out.set(path, null);
  }
  return out;
}

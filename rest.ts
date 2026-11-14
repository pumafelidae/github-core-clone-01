// GitHub REST v3 surface: repositories, branches, commits, contents, issues,
// comments, labels, pull requests, files and merges.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Store, VIEWER_LOGIN, VIEWER_ID, VIEWER_NAME, VIEWER_EMAIL, gitId, type Repo, type Issue, type PullRequest } from './store.ts';
import { sendJson, errMessage, notFound, readBody, parseJsonBody, isRecord, paginate, requestBase, bearerToken, queryOf, requestId, isAuthed } from './util.ts';

/** 401 when unauthenticated; returns true when the request may proceed. */
export function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  if (isAuthed(req)) return true;
  errMessage(res, 401, 'Requires authentication');
  return false;
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.dbId,
    node_id: gitId('Repository', repo.dbId),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    git_url: `git://example.invalid/${repo.owner}/${repo.name}.git`,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    pushed_at: '2025-01-01T00:00:00Z',
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: repo.dbId * 100000 + issue.number,
    node_id: gitId('Issue', repo.dbId, String(issue.number)),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
    comments: issue.comments.length,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullJson(repo: Repo, pr: PullRequest): Record<string, unknown> {
  return {
    id: repo.dbId * 100000 + pr.number,
    node_id: gitId('PullRequest', repo.dbId, String(pr.number)),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.merged_at,
    merge_commit_sha: pr.merge_commit_sha,
    head: { ref: pr.head.ref, sha: pr.head.sha, label: `${repo.owner}:${pr.head.ref}`, user: { login: VIEWER_LOGIN, id: VIEWER_ID } },
    base: { ref: pr.base.ref, sha: pr.base.sha, label: `${repo.owner}:${pr.base.ref}`, user: { login: VIEWER_LOGIN, id: VIEWER_ID } },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
  };
}

function base64Of(buf: Buffer): string {
  return buf.toString('base64');
}

function decodeBase64(s: string): Buffer | null {
  try {
    const clean = s.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) return null;
    return Buffer.from(clean, 'base64');
  } catch {
    return null;
  }
}

/** Resolve a repo from the path; sends 404 when missing or foreign-owned. */
function resolveRepo(store: Store, owner: string, name: string, res: ServerResponse): Repo | null {
  const repo = store.getRepo(owner, name);
  if (!repo) {
    errMessage(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

export async function handleRest(req: IncomingMessage, res: ServerResponse, store: Store, segments: string[]): Promise<boolean> {
  const method = req.method ?? 'GET';
  const query = queryOf(req);
  const base = requestBase(req);

  // GET /api/v3/user
  if (segments.length === 1 && segments[0] === 'user' && method === 'GET') {
    if (!requireAuth(req, res)) return true;
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return true;
  }

  // /api/v3/user/repos
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (!requireAuth(req, res)) return true;
    if (method === 'GET') {
      const repos = store.listViewerRepos().map(repoJson);
      const { page, link } = paginate(repos, query, base, '/api/v3/user/repos');
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    if (method === 'POST') {
      const buf = await readBody(req);
      if (buf === null) {
        errMessage(res, 400, 'Bad Request');
        return true;
      }
      const { value, error } = parseJsonBody(buf);
      if (error || !isRecord(value)) {
        errMessage(res, 400, 'Problems parsing JSON');
        return true;
      }
      const name = typeof value.name === 'string' ? value.name.trim() : '';
      if (name === '') {
        errMessage(res, 422, 'Validation Failed: name is required');
        return true;
      }
      if (store.getRepo(VIEWER_LOGIN, name)) {
        errMessage(res, 422, 'Validation Failed: name already exists on this account');
        return true;
      }
      const repo = store.createRepo(name, value.private === true, typeof value.description === 'string' ? value.description : '');
      sendJson(res, 201, repoJson(repo));
      return true;
    }
    return false;
  }

  // GET /api/v3/meta
  if (segments.length === 1 && segments[0] === 'meta' && method === 'GET') {
    if (!requireAuth(req, res)) return true;
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true });
    return true;
  }

  // /api/v3/repos/:owner/:repo/...
  if (segments.length >= 3 && segments[0] === 'repos') {
    const owner = decodeURIComponent(segments[1]!);
    const name = decodeURIComponent(segments[2]!);
    const rest = segments.slice(3);
    if (!requireAuth(req, res)) return true;

    // Repo itself: GET / PATCH / DELETE /repos/:owner/:repo
    if (rest.length === 0) {
      if (method === 'GET') {
        const repo = resolveRepo(store, owner, name, res);
        if (!repo) return true;
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        const repo = resolveRepo(store, owner, name, res);
        if (!repo) return true;
        const buf = await readBody(req);
        if (buf === null) {
          errMessage(res, 400, 'Bad Request');
          return true;
        }
        const { value, error } = parseJsonBody(buf);
        if (error || !isRecord(value)) {
          errMessage(res, 400, 'Problems parsing JSON');
          return true;
        }
        if (typeof value.description === 'string') repo.description = value.description;
        if (typeof value.private === 'boolean') repo.private = value.private;
        if (typeof value.default_branch === 'string' && value.default_branch !== '') repo.defaultBranch = value.default_branch;
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        const repo = resolveRepo(store, owner, name, res);
        if (!repo) return true;
        store.deleteRepo(repo);
        res.writeHead(204, { 'x-github-request-id': requestId(), 'x-oauth-scopes': 'repo, read:org' });
        res.end();
        return true;
      }
      return false;
    }

    const repo = resolveRepo(store, owner, name, res);
    if (!repo) return true;

    // GET /repos/:o/:r/branches
    if (rest.length === 1 && rest[0] === 'branches' && method === 'GET') {
      const out = [...repo.branches.entries()]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .map(([branch, sha]) => ({ name: branch, commit: { sha }, protected: false }));
      sendJson(res, 200, out);
      return true;
    }

    // GET /repos/:o/:r/branches/:branch
    if (rest.length === 2 && rest[0] === 'branches' && method === 'GET') {
      const branch = decodeURIComponent(rest[1]!);
      const sha = repo.branches.get(branch);
      if (!sha) {
        errMessage(res, 404, 'Branch not found');
        return true;
      }
      sendJson(res, 200, { name: branch, commit: { sha }, protected: false });
      return true;
    }

    // GET /repos/:o/:r/commits
    if (rest.length === 1 && rest[0] === 'commits' && method === 'GET') {
      const ref = query.get('sha') ?? repo.defaultBranch;
      const tip = repo.branches.get(ref) ?? (store.objects.has(ref) ? ref : undefined);
      if (!tip) {
        errMessage(res, 404, 'No commit found for SHA');
        return true;
      }
      const shas = store.walkCommits(tip);
      const { page, link } = paginate(
        shas.map((sha) => ({
          sha,
          commit: {
            message: store.commitMessage(sha),
            author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: new Date(store.commitTime(sha) * 1000).toISOString() },
            committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: new Date(store.commitTime(sha) * 1000).toISOString() },
          },
          author: { login: VIEWER_LOGIN, id: VIEWER_ID },
        })),
        query,
        base,
        `/api/v3/repos/${owner}/${name}/commits`,
      );
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }

    // /repos/:o/:r/contents/:path...
    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      if (method === 'GET') return getContents(req, res, store, repo, owner, name, filePath, query);
      if (method === 'PUT') return putContents(req, res, store, repo, filePath);
      if (method === 'DELETE') return deleteContents(req, res, store, repo, filePath);
      return false;
    }

    // /repos/:o/:r/git/refs...
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const buf = await readBody(req);
        if (buf === null) {
          errMessage(res, 400, 'Bad Request');
          return true;
        }
        const { value, error } = parseJsonBody(buf);
        if (error || !isRecord(value)) {
          errMessage(res, 400, 'Problems parsing JSON');
          return true;
        }
        const ref = typeof value.ref === 'string' ? value.ref : '';
        const sha = typeof value.sha === 'string' ? value.sha : '';
        const m = /^refs\/heads\/(.+)$/.exec(ref);
        if (!m || !/^[0-9a-f]{40}$/i.test(sha) || !store.objects.has(sha.toLowerCase())) {
          errMessage(res, 422, 'Validation Failed');
          return true;
        }
        const branch = m[1]!;
        if (repo.branches.has(branch)) {
          errMessage(res, 422, 'Validation Failed: Reference already exists');
          return true;
        }
        repo.branches.set(branch, sha.toLowerCase());
        sendJson(res, 201, { ref, object: { sha: sha.toLowerCase(), type: 'commit' }, url: `/api/v3/repos/${owner}/${name}/git/refs/heads/${branch}` });
        return true;
      }
      if (method === 'GET') {
        // GET /git/refs/heads/:branch or /git/refs (list)
        if (rest.length === 2) {
          const out: Record<string, unknown>[] = [];
          for (const [branch, sha] of repo.branches) out.push({ ref: `refs/heads/${branch}`, object: { sha, type: 'commit' } });
          sendJson(res, 200, out);
          return true;
        }
        const refPath = rest.slice(2).map((s) => decodeURIComponent(s)).join('/');
        const m = /^heads\/(.+)$/.exec(refPath);
        if (m) {
          const sha = repo.branches.get(m[1]!);
          if (!sha) {
            errMessage(res, 404, 'Not Found');
            return true;
          }
          sendJson(res, 200, { ref: `refs/heads/${m[1]}`, object: { sha, type: 'commit' } });
          return true;
        }
        errMessage(res, 404, 'Not Found');
        return true;
      }
      return false;
    }

    // /repos/:o/:r/labels
    if (rest.length === 1 && rest[0] === 'labels') {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color })));
        return true;
      }
      if (method === 'POST') {
        const buf = await readBody(req);
        if (buf === null) {
          errMessage(res, 400, 'Bad Request');
          return true;
        }
        const { value, error } = parseJsonBody(buf);
        if (error || !isRecord(value)) {
          errMessage(res, 400, 'Problems parsing JSON');
          return true;
        }
        const labelName = typeof value.name === 'string' ? value.name : '';
        if (labelName === '') {
          errMessage(res, 422, 'Validation Failed: name is required');
          return true;
        }
        const color = typeof value.color === 'string' ? value.color : 'ededed';
        repo.labels.set(labelName, { name: labelName, color });
        sendJson(res, 201, { name: labelName, color });
        return true;
      }
      return false;
    }

    // /repos/:o/:r/issues...
    if (rest[0] === 'issues') return handleIssues(req, res, store, repo, owner, name, rest.slice(1), method, query, base);

    // /repos/:o/:r/pulls...
    if (rest[0] === 'pulls') return handlePulls(req, res, store, repo, owner, name, rest.slice(1), method, query, base);

    return false;
  }

  return false;
}

function getContents(
  _req: IncomingMessage,
  res: ServerResponse,
  store: Store,
  repo: Repo,
  owner: string,
  name: string,
  filePath: string,
  query: URLSearchParams,
): boolean {
  const ref = query.get('ref') ?? repo.defaultBranch;
  const files = store.branchFiles(repo, ref);
  if (filePath === '') {
    // Root listing.
    const entries = dirEntries(store, repo, ref, files, '');
    sendJson(res, 200, entries);
    return true;
  }
  const content = files.get(filePath);
  if (content !== undefined) {
    const blobSha = store.writeBlob(content);
    sendJson(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: content.length,
      name: filePath.split('/').pop(),
      path: filePath,
      content: base64Of(content),
      sha: blobSha,
      url: `/api/v3/repos/${owner}/${name}/contents/${filePath}`,
      html_url: `https://example.invalid/${owner}/${name}/blob/${ref}/${filePath}`,
      download_url: `https://example.invalid/${owner}/${name}/raw/${ref}/${filePath}`,
    });
    return true;
  }
  // Directory?
  const prefix = filePath.endsWith('/') ? filePath : `${filePath}/`;
  const hasChild = [...files.keys()].some((p) => p.startsWith(prefix));
  if (hasChild) {
    sendJson(res, 200, dirEntries(store, repo, ref, files, prefix));
    return true;
  }
  errMessage(res, 404, 'Not Found');
  return true;
}

function dirEntries(store: Store, repo: Repo, ref: string, files: Map<string, Buffer>, prefix: string): Record<string, unknown>[] {
  const seen = new Map<string, { type: 'file' | 'dir'; name: string; path: string; sha: string; size?: number }>();
  for (const [path, content] of files) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash === -1) {
      seen.set(rest, { type: 'file', name: rest, path, sha: store.writeBlob(content), size: content.length });
    } else {
      const dir = rest.slice(0, slash);
      if (!seen.has(dir)) {
        const tip = repo.branches.get(ref);
        const treeSha = tip ? store.treeShaOfCommit(tip) : null;
        seen.set(dir, { type: 'dir', name: dir, path: prefix + dir, sha: treeSha ?? '0'.repeat(40) });
      }
    }
  }
  return [...seen.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
}

async function putContents(req: IncomingMessage, res: ServerResponse, store: Store, repo: Repo, filePath: string): Promise<boolean> {
  const buf = await readBody(req);
  if (buf === null) {
    errMessage(res, 400, 'Bad Request');
    return true;
  }
  const { value, error } = parseJsonBody(buf);
  if (error || !isRecord(value)) {
    errMessage(res, 400, 'Problems parsing JSON');
    return true;
  }
  const message = typeof value.message === 'string' ? value.message : 'Update file';
  const contentB64 = typeof value.content === 'string' ? value.content : '';
  const content = decodeBase64(contentB64);
  if (content === null) {
    errMessage(res, 422, 'Validation Failed: content is not valid base64');
    return true;
  }
  let branch = typeof value.branch === 'string' && value.branch !== '' ? value.branch : repo.defaultBranch;
  let tip = repo.branches.get(branch);
  if (!tip) {
    // Create the branch from the default tip (or empty) — GitHub does this for a new branch.
    const defaultTip = repo.branches.get(repo.defaultBranch);
    if (defaultTip) repo.branches.set(branch, defaultTip);
    tip = defaultTip;
  }
  const files = tip ? store.filesOfCommit(tip) : new Map<string, Buffer>();
  const existing = files.get(filePath);
  const sha = typeof value.sha === 'string' ? value.sha.toLowerCase() : null;
  if (existing !== undefined) {
    const currentSha = store.writeBlob(existing);
    if (sha === null) {
      errMessage(res, 409, 'Conflict: sha is required to update a file');
      return true;
    }
    if (sha !== currentSha) {
      errMessage(res, 409, 'Conflict: sha does not match the current file');
      return true;
    }
  } else if (sha !== null) {
    errMessage(res, 422, 'Validation Failed: sha does not match an existing file');
    return true;
  }
  const isUpdate = existing !== undefined;
  files.set(filePath, content);
  const parents = tip ? [tip] : [];
  const commitSha = store.createCommit(repo, branch, files, message, parents);
  const blobSha = store.writeBlob(content);
  sendJson(res, isUpdate ? 200 : 201, {
    content: { name: filePath.split('/').pop(), path: filePath, sha: blobSha, size: content.length, type: 'file', encoding: 'base64', content: base64Of(content) },
    commit: { sha: commitSha, message },
  });
  return true;
}

async function deleteContents(req: IncomingMessage, res: ServerResponse, store: Store, repo: Repo, filePath: string): Promise<boolean> {
  const buf = await readBody(req);
  if (buf === null) {
    errMessage(res, 400, 'Bad Request');
    return true;
  }
  const { value, error } = parseJsonBody(buf);
  if (error || !isRecord(value)) {
    errMessage(res, 400, 'Problems parsing JSON');
    return true;
  }
  const branch = typeof value.branch === 'string' && value.branch !== '' ? value.branch : repo.defaultBranch;
  const tip = repo.branches.get(branch);
  if (!tip) {
    errMessage(res, 404, 'Not Found');
    return true;
  }
  const files = store.filesOfCommit(tip);
  const existing = files.get(filePath);
  if (existing === undefined) {
    errMessage(res, 404, 'Not Found');
    return true;
  }
  const sha = typeof value.sha === 'string' ? value.sha.toLowerCase() : null;
  if (sha !== null && sha !== store.writeBlob(existing)) {
    errMessage(res, 409, 'Conflict: sha does not match the current file');
    return true;
  }
  files.delete(filePath);
  const message = typeof value.message === 'string' ? value.message : 'Delete file';
  const commitSha = store.createCommit(repo, branch, files, message, [tip]);
  sendJson(res, 200, { commit: { sha: commitSha, message } });
  return true;
}

async function handleIssues(
  req: IncomingMessage,
  res: ServerResponse,
  store: Store,
  repo: Repo,
  owner: string,
  name: string,
  rest: string[],
  method: string,
  query: URLSearchParams,
  base: string,
): Promise<boolean> {
  // POST/GET /issues
  if (rest.length === 0) {
    if (method === 'POST') {
      const buf = await readBody(req);
      if (buf === null) {
        errMessage(res, 400, 'Bad Request');
        return true;
      }
      const { value, error } = parseJsonBody(buf);
      if (error || !isRecord(value)) {
        errMessage(res, 400, 'Problems parsing JSON');
        return true;
      }
      const title = typeof value.title === 'string' ? value.title : '';
      if (title === '') {
        errMessage(res, 422, 'Validation Failed: title is required');
        return true;
      }
      const labels: string[] = [];
      if (Array.isArray(value.labels)) {
        for (const l of value.labels) {
          if (typeof l !== 'string') continue;
          if (!repo.labels.has(l)) {
            errMessage(res, 422, `Validation Failed: label "${l}" does not exist`);
            return true;
          }
          labels.push(l);
        }
      }
      const number = store.nextNumber(repo);
      const issue: Issue = {
        number,
        id: gitId('Issue', repo.dbId, String(number)),
        title,
        body: typeof value.body === 'string' ? value.body : '',
        state: 'open',
        labels,
        comments: [],
        seq: repo.counter,
      };
      repo.issues.push(issue);
      sendJson(res, 201, issueJson(repo, issue));
      return true;
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      let list = repo.issues.slice();
      if (state !== 'all') list = list.filter((i) => i.state === state);
      const sort = query.get('sort') ?? 'created';
      const direction = query.get('direction') ?? (sort === 'created' ? 'desc' : 'desc');
      if (sort === 'created') {
        list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      }
      const { page, link } = paginate(list.map((i) => issueJson(repo, i)), query, base, `/api/v3/repos/${owner}/${name}/issues`);
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    return false;
  }

  const num = Number(rest[0]);
  if (!Number.isSafeInteger(num) || num < 1) return false;
  const issue = repo.issues.find((i) => i.number === num);
  if (!issue) {
    errMessage(res, 404, 'Not Found');
    return true;
  }

  // GET/PATCH /issues/:n
  if (rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, issueJson(repo, issue));
      return true;
    }
    if (method === 'PATCH') {
      const buf = await readBody(req);
      if (buf === null) {
        errMessage(res, 400, 'Bad Request');
        return true;
      }
      const { value, error } = parseJsonBody(buf);
      if (error || !isRecord(value)) {
        errMessage(res, 400, 'Problems parsing JSON');
        return true;
      }
      if (value.state === 'open' || value.state === 'closed') issue.state = value.state;
      if (typeof value.title === 'string') issue.title = value.title;
      if (typeof value.body === 'string') issue.body = value.body;
      sendJson(res, 200, issueJson(repo, issue));
      return true;
    }
    return false;
  }

  // /issues/:n/comments
  if (rest.length === 2 && rest[1] === 'comments') {
    if (method === 'GET') {
      sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } })));
      return true;
    }
    if (method === 'POST') {
      const buf = await readBody(req);
      if (buf === null) {
        errMessage(res, 400, 'Bad Request');
        return true;
      }
      const { value, error } = parseJsonBody(buf);
      if (error || !isRecord(value)) {
        errMessage(res, 400, 'Problems parsing JSON');
        return true;
      }
      const body = typeof value.body === 'string' ? value.body : '';
      if (body === '') {
        errMessage(res, 422, 'Validation Failed: body is required');
        return true;
      }
      repo.commentCounter += 1;
      const comment = { id: repo.commentCounter, body };
      issue.comments.push(comment);
      sendJson(res, 201, { id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } });
      return true;
    }
    return false;
  }

  return false;
}

async function handlePulls(
  req: IncomingMessage,
  res: ServerResponse,
  store: Store,
  repo: Repo,
  owner: string,
  name: string,
  rest: string[],
  method: string,
  query: URLSearchParams,
  base: string,
): Promise<boolean> {
  // POST/GET /pulls
  if (rest.length === 0) {
    if (method === 'POST') {
      const buf = await readBody(req);
      if (buf === null) {
        errMessage(res, 400, 'Bad Request');
        return true;
      }
      const { value, error } = parseJsonBody(buf);
      if (error || !isRecord(value)) {
        errMessage(res, 400, 'Problems parsing JSON');
        return true;
      }
      const title = typeof value.title === 'string' ? value.title : '';
      const headRaw = typeof value.head === 'string' ? value.head : '';
      const baseRaw = typeof value.base === 'string' ? value.base : '';
      const head = headRaw.includes(':') ? headRaw.split(':').pop()! : headRaw;
      const baseRef = baseRaw.includes(':') ? baseRaw.split(':').pop()! : baseRaw;
      if (title === '' || head === '' || baseRef === '') {
        errMessage(res, 422, 'Validation Failed: title, head and base are required');
        return true;
      }
      const headSha = repo.branches.get(head);
      const baseSha = repo.branches.get(baseRef);
      if (!headSha || !baseSha) {
        errMessage(res, 422, 'Validation Failed: head or base branch does not exist');
        return true;
      }
      const baseFiles = store.filesOfCommit(baseSha);
      const headFiles = store.filesOfCommit(headSha);
      const files = store.diffFiles(baseFiles, headFiles);
      const number = store.nextNumber(repo);
      const pr: PullRequest = {
        number,
        id: gitId('PullRequest', repo.dbId, String(number)),
        title,
        body: typeof value.body === 'string' ? value.body : '',
        state: 'open',
        merged: false,
        merged_at: null,
        merge_commit_sha: null,
        head: { ref: head, sha: headSha },
        base: { ref: baseRef, sha: baseSha },
        baseSha,
        files,
        seq: repo.counter,
      };
      repo.prs.push(pr);
      sendJson(res, 201, pullJson(repo, pr));
      return true;
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      let list = repo.prs.slice();
      if (state !== 'all') list = list.filter((p) => p.state === state);
      list.sort((a, b) => b.seq - a.seq);
      const { page, link } = paginate(list.map((p) => pullJson(repo, p)), query, base, `/api/v3/repos/${owner}/${name}/pulls`);
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    return false;
  }

  const num = Number(rest[0]);
  if (!Number.isSafeInteger(num) || num < 1) return false;
  const pr = repo.prs.find((p) => p.number === num);
  if (!pr) {
    errMessage(res, 404, 'Not Found');
    return true;
  }

  if (rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, pullJson(repo, pr));
      return true;
    }
    return false;
  }

  // GET /pulls/:n/files
  if (rest.length === 2 && rest[1] === 'files' && method === 'GET') {
    sendJson(res, 200, pr.files);
    return true;
  }

  // PUT /pulls/:n/merge
  if (rest.length === 2 && rest[1] === 'merge' && method === 'PUT') {
    const buf = await readBody(req);
    if (buf === null) {
      errMessage(res, 400, 'Bad Request');
      return true;
    }
    const { value, error } = parseJsonBody(buf);
    if (error) {
      errMessage(res, 400, 'Problems parsing JSON');
      return true;
    }
    if (pr.merged || pr.state === 'closed') {
      errMessage(res, 405, 'Pull Request is already merged or closed');
      return true;
    }
    const baseTip = repo.branches.get(pr.base.ref);
    if (!baseTip) {
      errMessage(res, 404, 'Base branch not found');
      return true;
    }
    // Conflict: the base moved since the PR was opened AND changed a file the PR also changed.
    if (baseTip !== pr.baseSha) {
      const prBaseFiles = store.filesOfCommit(pr.baseSha);
      const baseNowFiles = store.filesOfCommit(baseTip);
      const baseChanged = new Set(store.diffFiles(prBaseFiles, baseNowFiles).map((f) => f.filename));
      const prChanged = new Set(pr.files.map((f) => f.filename));
      const overlap = [...prChanged].some((f) => baseChanged.has(f));
      if (overlap) {
        errMessage(res, 405, 'Merge conflict: the base branch changed a file this pull request also changed');
        return true;
      }
    }
    // Squash merge: base files overlaid with the PR's changed files.
    const mergedFiles = store.filesOfCommit(baseTip);
    const headFiles = store.filesOfCommit(pr.head.sha);
    for (const f of pr.files) {
      if (f.status === 'removed') mergedFiles.delete(f.filename);
      else {
        const content = headFiles.get(f.filename);
        if (content !== undefined) mergedFiles.set(f.filename, content);
      }
    }
    const mergeSha = store.createCommit(repo, pr.base.ref, mergedFiles, `${pr.title} (#${pr.number})`, [baseTip]);
    pr.merged = true;
    pr.state = 'closed';
    pr.merged_at = new Date().toISOString();
    pr.merge_commit_sha = mergeSha;
    sendJson(res, 200, { merged: true, sha: mergeSha, message: 'Pull Request successfully merged' });
    return true;
  }

  return false;
}

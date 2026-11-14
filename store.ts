// The forge's in-memory state: every repository, git object, ref, issue, pull request and label.
// One Forge holds the whole server. Nothing here touches the network; the modules (rest, graphql,
// mcp, git) read and write through this class, so a change on one surface is visible on the others.
//
// Git objects are content-addressed by SHA-1, exactly as git hashes them:
//   blob   sha1("blob <len>\0" + bytes)
//   tree   sha1("tree <len>\0" + entries), each entry "<mode> <name>\0" + 20-byte sha
//   commit sha1("commit <len>\0" + "tree <sha>\n" + "parent <sha>\n"* + "author ...\ncommitter ...\n\n" + message)
//   tag    sha1("tag <len>\0" + "object <sha>\ntype <type>\ntag <name>\ntagger ...\n\n" + message)

import { gitObjectId, isoNow, sha1Hex } from './util.ts';
import type { Scenario, ScenarioUser } from './wire.ts';
import { buildScenario } from './wire.ts';

/** The four git object types. */
export type GitObjectType = 'blob' | 'tree' | 'commit' | 'tag';

/** One stored git object: its type and raw bytes (the content after the "<type> <len>\0" header). */
export interface GitObject {
  readonly type: GitObjectType;
  readonly data: Buffer;
}

/** One tree entry: mode, name, and the object it points at. */
export interface TreeEntry {
  readonly mode: string;
  readonly name: string;
  readonly sha: string;
  readonly type: GitObjectType;
}

/** A parsed commit object. */
export interface CommitInfo {
  readonly tree: string;
  readonly parents: readonly string[];
  readonly authorName: string;
  readonly authorEmail: string;
  readonly authorTs: number;
  readonly committerName: string;
  readonly committerEmail: string;
  readonly committerTs: number;
  readonly message: string;
}

/** A parsed tag object. */
export interface TagInfo {
  readonly object: string;
  readonly type: GitObjectType;
  readonly tag: string;
  readonly taggerName: string;
  readonly taggerEmail: string;
  readonly taggerTs: number;
  readonly message: string;
}

/** Encode a commit object body (without the git header). */
export function encodeCommit(info: {
  tree: string;
  parents: readonly string[];
  authorName: string;
  authorEmail: string;
  authorTs: number;
  committerName: string;
  committerEmail: string;
  committerTs: number;
  message: string;
}): Buffer {
  const lines: string[] = [`tree ${info.tree}`];
  for (const parent of info.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${info.authorName} <${info.authorEmail}> ${info.authorTs} +0000`);
  lines.push(`committer ${info.committerName} <${info.committerEmail}> ${info.committerTs} +0000`);
  return Buffer.from(`${lines.join('\n')}\n\n${info.message}`, 'utf8');
}

/** Parse a commit object body. Returns null when the body is not a well-formed commit. */
export function parseCommit(data: Buffer): CommitInfo | null {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  if (split < 0) return null;
  const header = text.slice(0, split);
  const message = text.slice(split + 2);
  const lines = header.split('\n');
  let tree = '';
  const parents: string[] = [];
  let authorName = '';
  let authorEmail = '';
  let authorTs = 0;
  let committerName = '';
  let committerEmail = '';
  let committerTs = 0;
  for (const line of lines) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) {
      const m = /^author (.*) <(.*)> (\d+) [+-]\d{4}$/.exec(line);
      if (m !== null) {
        authorName = m[1] ?? '';
        authorEmail = m[2] ?? '';
        authorTs = Number(m[3] ?? '0');
      }
    } else if (line.startsWith('committer ')) {
      const m = /^committer (.*) <(.*)> (\d+) [+-]\d{4}$/.exec(line);
      if (m !== null) {
        committerName = m[1] ?? '';
        committerEmail = m[2] ?? '';
        committerTs = Number(m[3] ?? '0');
      }
    }
  }
  if (tree === '') return null;
  return { tree, parents, authorName, authorEmail, authorTs, committerName, committerEmail, committerTs, message };
}

/** Encode a tree object body (without the git header). Entries are sorted by name, git-style. */
export function encodeTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.type === 'tree' ? `${a.name}/` : a.name;
    const bn = b.type === 'tree' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.sha, 'hex'));
  }
  return Buffer.concat(parts);
}

/** Parse a tree object body. Returns null when the body is malformed. */
export function parseTree(data: Buffer): TreeEntry[] | null {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) return null;
    const nul = data.indexOf(0x00, space);
    if (nul < 0 || nul + 21 > data.length) return null;
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const sha = data.subarray(nul + 1, nul + 21).toString('hex');
    const type: GitObjectType = mode === '40000' ? 'tree' : mode === '160000' ? 'commit' : 'blob';
    entries.push({ mode, name, sha, type });
    offset = nul + 21;
  }
  return entries;
}

/** Encode a tag object body (without the git header). */
export function encodeTag(info: {
  object: string;
  type: GitObjectType;
  tag: string;
  taggerName: string;
  taggerEmail: string;
  taggerTs: number;
  message: string;
}): Buffer {
  const lines = [
    `object ${info.object}`,
    `type ${info.type}`,
    `tag ${info.tag}`,
    `tagger ${info.taggerName} <${info.taggerEmail}> ${info.taggerTs} +0000`,
  ];
  return Buffer.from(`${lines.join('\n')}\n\n${info.message}`, 'utf8');
}

/** Parse a tag object body. Returns null when the body is not a well-formed tag. */
export function parseTag(data: Buffer): TagInfo | null {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  if (split < 0) return null;
  const header = text.slice(0, split);
  const message = text.slice(split + 2);
  let object = '';
  let type: GitObjectType = 'commit';
  let tag = '';
  let taggerName = '';
  let taggerEmail = '';
  let taggerTs = 0;
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim() as GitObjectType;
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) {
      const m = /^tagger (.*) <(.*)> (\d+) [+-]\d{4}$/.exec(line);
      if (m !== null) {
        taggerName = m[1] ?? '';
        taggerEmail = m[2] ?? '';
        taggerTs = Number(m[3] ?? '0');
      }
    }
  }
  if (object === '' || tag === '') return null;
  return { object, type, tag, taggerName, taggerEmail, taggerTs, message };
}

/** A comment on an issue. */
export interface IssueComment {
  readonly id: number;
  body: string;
  readonly user: ScenarioUser;
  readonly createdAt: string;
  updatedAt: string;
}

/** An issue. */
export interface Issue {
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  readonly user: ScenarioUser;
  assignees: string[];
  readonly createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  readonly comments: Map<number, IssueComment>;
  commentSeq: number;
}

/** A pull request. */
export interface PullRequest {
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string;
  base: string;
  headSha: string | null;
  baseSha: string | null;
  merged: boolean;
  mergeable: boolean;
  readonly user: ScenarioUser;
  readonly createdAt: string;
  updatedAt: string;
  mergedAt: string | null;
  mergedBy: string | null;
}

/** A label. */
export interface Label {
  name: string;
  color: string;
  description: string;
}

/** One repository: its metadata, git objects, refs, issues, pulls and labels. */
export interface RepoRecord {
  readonly id: number;
  readonly owner: string;
  readonly name: string;
  readonly fullName: string;
  description: string;
  private: boolean;
  readonly defaultBranch: string;
  readonly createdAt: string;
  updatedAt: string;
  pushedAt: string | null;
  /** Git objects by SHA-1. */
  readonly objects: Map<string, GitObject>;
  /** Refs by full name (refs/heads/*, refs/tags/*). */
  readonly refs: Map<string, string>;
  /** Issues by number. */
  readonly issues: Map<number, Issue>;
  issueSeq: number;
  /** Pull requests by number. */
  readonly pulls: Map<number, PullRequest>;
  pullSeq: number;
  /** Labels by name. */
  readonly labels: Map<string, Label>;
}

// ---------------------------------------------------------------- the forge

/** The whole server's state. One Forge per process; modules share it. */
export class Forge {
  readonly scenario: Scenario;
  readonly viewer: ScenarioUser;
  /** Users by login. */
  readonly users = new Map<string, ScenarioUser>();
  /** Repositories by full name (owner/name). */
  readonly repos = new Map<string, RepoRecord>();
  private nextRepoId = 8000;
  private nextCommentId = 1;

  constructor() {
    this.scenario = buildScenario();
    this.viewer = this.scenario.viewer;
    for (const user of this.scenario.users) this.users.set(user.login, user);
    // Seed the scenario's repositories (empty, like a fresh GitHub repo: no commits yet).
    for (const repo of [...this.scenario.repos, ...this.scenario.orgRepos, ...this.scenario.strangerRepos]) {
      this.repos.set(repo.fullName, this.newRepoRecord(repo.id, repo.owner, repo.name, repo.description, repo.private, repo.defaultBranch));
    }
  }

  private newRepoRecord(id: number, owner: string, name: string, description: string, isPrivate: boolean, defaultBranch: string): RepoRecord {
    const now = isoNow();
    const record: RepoRecord = {
      id,
      owner,
      name,
      fullName: `${owner}/${name}`,
      description,
      private: isPrivate,
      defaultBranch,
      createdAt: now,
      updatedAt: now,
      pushedAt: null,
      objects: new Map<string, GitObject>(),
      refs: new Map<string, string>(),
      issues: new Map<number, Issue>(),
      issueSeq: 0,
      pulls: new Map<number, PullRequest>(),
      pullSeq: 0,
      labels: new Map<string, Label>(),
    };
    // GitHub's default labels on every repository.
    for (const [lname, color, desc] of [
      ['bug', 'd73a4a', "Something isn't working"],
      ['documentation', '0075ca', 'Improvements or additions to documentation'],
      ['duplicate', 'cfd3d7', 'This issue or pull request already exists'],
      ['enhancement', 'a2eeef', 'New feature or request'],
      ['good first issue', '7057ff', 'Good for newcomers'],
      ['help wanted', '008672', 'Extra attention is needed'],
      ['invalid', 'e4e669', 'This doesn\'t seem right'],
      ['question', 'd876e3', 'Further information is requested'],
      ['wontfix', 'ffffff', 'This will not be worked on'],
    ] as const) {
      record.labels.set(lname, { name: lname, color, description: desc });
    }
    return record;
  }

  // ---------------------------------------------------------------- git objects

  /** Store an object (hashing it first); returns its SHA-1. Idempotent: storing twice is a no-op. */
  putObject(repo: RepoRecord, type: GitObjectType, data: Buffer): string {
    const sha = gitObjectId(type, data);
    if (!repo.objects.has(sha)) repo.objects.set(sha, { type, data });
    return sha;
  }

  /** Fetch an object by SHA-1 (accepts a unique short prefix too). */
  getObject(repo: RepoRecord, sha: string): GitObject | undefined {
    const found = repo.objects.get(sha);
    if (found !== undefined) return found;
    if (/^[0-9a-f]{4,39}$/.test(sha)) {
      for (const [key, value] of repo.objects) {
        if (key.startsWith(sha)) return value;
      }
    }
    return undefined;
  }

  /** Whether an object exists (full SHA or unique short prefix). */
  hasObject(repo: RepoRecord, sha: string): boolean {
    return this.getObject(repo, sha) !== undefined;
  }

  /** The SHA a full or short id resolves to, or null. */
  resolveObjectSha(repo: RepoRecord, sha: string): string | null {
    if (repo.objects.has(sha)) return sha;
    if (/^[0-9a-f]{4,39}$/.test(sha)) {
      let match: string | null = null;
      for (const key of repo.objects.keys()) {
        if (key.startsWith(sha)) {
          if (match !== null) return null;
          match = key;
        }
      }
      return match;
    }
    return null;
  }

  // ---------------------------------------------------------------- refs

  /** A ref's target SHA, or undefined. */
  getRef(repo: RepoRecord, refname: string): string | undefined {
    return repo.refs.get(refname);
  }

  /** Set a ref (creating it when new). */
  setRef(repo: RepoRecord, refname: string, sha: string): void {
    repo.refs.set(refname, sha);
    repo.pushedAt = isoNow();
    repo.updatedAt = isoNow();
  }

  /** Delete a ref; true when it existed. */
  deleteRef(repo: RepoRecord, refname: string): boolean {
    return repo.refs.delete(refname);
  }

  /** All refs, sorted by name. */
  listRefs(repo: RepoRecord): Array<{ name: string; sha: string }> {
    return [...repo.refs.entries()].map(([name, sha]) => ({ name, sha })).sort((a, b) => (a.name < b.name ? -1 : 1));
  }

  /** The default branch's ref name. */
  defaultRef(repo: RepoRecord): string {
    return `refs/heads/${repo.defaultBranch}`;
  }

  /** Resolve a ref-ish to a commit SHA: full ref, branch name, HEAD, or a SHA/prefix. */
  resolveRef(repo: RepoRecord, refish: string): string | null {
    if (refish === 'HEAD') return repo.refs.get(this.defaultRef(repo)) ?? null;
    if (repo.refs.has(refish)) return repo.refs.get(refish) ?? null;
    const branch = `refs/heads/${refish}`;
    if (repo.refs.has(branch)) return repo.refs.get(branch) ?? null;
    const tag = `refs/tags/${refish}`;
    if (repo.refs.has(tag)) {
      const target = repo.refs.get(tag) ?? '';
      const obj = this.getObject(repo, target);
      if (obj !== undefined && obj.type === 'tag') {
        const info = parseTag(obj.data);
        if (info !== null) return this.resolveObjectSha(repo, info.object);
      }
      return target;
    }
    return this.resolveObjectSha(repo, refish);
  }

  /** Whether `sha` is an ancestor of `tip` (or equal), walking first-parent and all parents. */
  isAncestor(repo: RepoRecord, ancestor: string, tip: string): boolean {
    if (ancestor === tip) return true;
    const seen = new Set<string>();
    const stack = [tip];
    while (stack.length > 0) {
      const current = stack.pop() as string;
      if (seen.has(current)) continue;
      seen.add(current);
      const obj = this.getObject(repo, current);
      if (obj === undefined || obj.type !== 'commit') continue;
      const info = parseCommit(obj.data);
      if (info === null) continue;
      for (const parent of info.parents) {
        if (parent === ancestor) return true;
        stack.push(parent);
      }
    }
    return false;
  }

  /** All commits reachable from `tip`, newest-first by committer time then SHA (stable). */
  reachableCommits(repo: RepoRecord, tip: string): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    const stack = [tip];
    while (stack.length > 0) {
      const current = stack.pop() as string;
      if (seen.has(current)) continue;
      seen.add(current);
      const obj = this.getObject(repo, current);
      if (obj === undefined || obj.type !== 'commit') continue;
      const info = parseCommit(obj.data);
      if (info === null) continue;
      out.push(current);
      for (const parent of info.parents) stack.push(parent);
    }
    out.sort((a, b) => {
      const ia = parseCommit(this.getObject(repo, a)?.data ?? Buffer.alloc(0));
      const ib = parseCommit(this.getObject(repo, b)?.data ?? Buffer.alloc(0));
      const ta = ia?.committerTs ?? 0;
      const tb = ib?.committerTs ?? 0;
      if (ta !== tb) return tb - ta;
      return a < b ? -1 : 1;
    });
    return out;
  }

  /** Read a file's bytes at a ref (walking trees); null when the ref, path or file is missing. */
  readFileAt(repo: RepoRecord, refish: string, path: string): { content: Buffer; sha: string } | null {
    const tip = this.resolveRef(repo, refish);
    if (tip === null) return null;
    const commit = this.getObject(repo, tip);
    if (commit === undefined || commit.type !== 'commit') return null;
    const info = parseCommit(commit.data);
    if (info === null) return null;
    const parts = path.split('/').filter((part) => part !== '');
    let treeSha = info.tree;
    for (let i = 0; i < parts.length; i += 1) {
      const treeObj = this.getObject(repo, treeSha);
      if (treeObj === undefined || treeObj.type !== 'tree') return null;
      const entries = parseTree(treeObj.data);
      if (entries === null) return null;
      const part = parts[i] as string;
      const entry = entries.find((candidate) => candidate.name === part);
      if (entry === undefined) return null;
      if (i === parts.length - 1) {
        if (entry.type !== 'blob') return null;
        const blob = this.getObject(repo, entry.sha);
        if (blob === undefined) return null;
        return { content: blob.data, sha: entry.sha };
      }
      if (entry.type !== 'tree') return null;
      treeSha = entry.sha;
    }
    return null;
  }

  /** List a directory's entries at a ref (or the root when path is ''); null when the ref is missing. */
  listDirAt(repo: RepoRecord, refish: string, path: string): TreeEntry[] | null {
    const tip = this.resolveRef(repo, refish);
    if (tip === null) return null;
    const commit = this.getObject(repo, tip);
    if (commit === undefined || commit.type !== 'commit') return null;
    const info = parseCommit(commit.data);
    if (info === null) return null;
    let treeSha = info.tree;
    const parts = path.split('/').filter((part) => part !== '');
    for (const part of parts) {
      const treeObj = this.getObject(repo, treeSha);
      if (treeObj === undefined || treeObj.type !== 'tree') return null;
      const entries = parseTree(treeObj.data);
      if (entries === null) return null;
      const entry = entries.find((candidate) => candidate.name === part);
      if (entry === undefined || entry.type !== 'tree') return null;
      treeSha = entry.sha;
    }
    const treeObj = this.getObject(repo, treeSha);
    if (treeObj === undefined || treeObj.type !== 'tree') return null;
    return parseTree(treeObj.data);
  }

  /**
   * Write (or replace) a file at a ref, building the trees and a commit on top of the ref's tip.
   * Returns the new commit SHA. When `refish` has no commit yet, the new commit has no parent.
   * `baseTree` (when given) replaces the tip's tree as the starting point (used for multi-file writes).
   */
  writeFileAt(
    repo: RepoRecord,
    refish: string,
    path: string,
    content: Buffer,
    message: string,
    author: ScenarioUser,
    baseTree?: string,
  ): string {
    const tip = this.resolveRef(repo, refish);
    let baseTreeSha = baseTree;
    let parents: string[] = [];
    if (baseTreeSha === undefined) {
      if (tip !== null) {
        const commit = this.getObject(repo, tip);
        const info = commit !== undefined && commit.type === 'commit' ? parseCommit(commit.data) : null;
        if (info !== null) {
          baseTreeSha = info.tree;
          parents = [tip];
        }
      }
    }
    const blobSha = this.putObject(repo, 'blob', content);
    const newTreeSha = this.setPathInTree(repo, baseTreeSha, path.split('/').filter((part) => part !== ''), blobSha);
    const ts = Math.floor(Date.now() / 1000);
    const commitSha = this.putObject(
      repo,
      'commit',
      encodeCommit({
        tree: newTreeSha,
        parents,
        authorName: author.name,
        authorEmail: author.email,
        authorTs: ts,
        committerName: author.name,
        committerEmail: author.email,
        committerTs: ts,
        message,
      }),
    );
    return commitSha;
  }

  /** Return a tree identical to `treeSha` (or empty) with `parts` set to `blobSha`; new tree SHA. */
  setPathInTree(repo: RepoRecord, treeSha: string | undefined, parts: readonly string[], blobSha: string): string {
    if (parts.length === 0) return treeSha ?? this.putObject(repo, 'tree', encodeTree([]));
    const [head, ...rest] = parts as [string, ...string[]];
    let entries: TreeEntry[] = [];
    if (treeSha !== undefined) {
      const obj = this.getObject(repo, treeSha);
      if (obj !== undefined && obj.type === 'tree') entries = parseTree(obj.data) ?? [];
    }
    const existing = entries.find((entry) => entry.name === head);
    if (rest.length === 0) {
      const next: TreeEntry[] = entries.filter((entry) => entry.name !== head);
      next.push({ mode: '100644', name: head, sha: blobSha, type: 'blob' });
      return this.putObject(repo, 'tree', encodeTree(next));
    }
    const childTree = existing !== undefined && existing.type === 'tree' ? existing.sha : undefined;
    const newChild = this.setPathInTree(repo, childTree, rest, blobSha);
    const next: TreeEntry[] = entries.filter((entry) => entry.name !== head);
    next.push({ mode: '40000', name: head, sha: newChild, type: 'tree' });
    return this.putObject(repo, 'tree', encodeTree(next));
  }

  /** Delete a path from a tree; returns the new tree SHA (or the same SHA when the path is absent). */
  deletePathInTree(repo: RepoRecord, treeSha: string | undefined, parts: readonly string[]): string {
    if (parts.length === 0 || treeSha === undefined) return treeSha ?? this.putObject(repo, 'tree', encodeTree([]));
    const obj = this.getObject(repo, treeSha);
    if (obj === undefined || obj.type !== 'tree') return treeSha;
    const entries = parseTree(obj.data) ?? [];
    const [head, ...rest] = parts as [string, ...string[]];
    if (rest.length === 0) {
      const next = entries.filter((entry) => entry.name !== head);
      if (next.length === entries.length) return treeSha;
      return this.putObject(repo, 'tree', encodeTree(next));
    }
    const existing = entries.find((entry) => entry.name === head);
    if (existing === undefined || existing.type !== 'tree') return treeSha;
    const newChild = this.deletePathInTree(repo, existing.sha, rest);
    if (newChild === existing.sha) return treeSha;
    const next = entries.filter((entry) => entry.name !== head);
    if (newChild !== this.putObject(repo, 'tree', encodeTree([])) || true) {
      next.push({ mode: '40000', name: head, sha: newChild, type: 'tree' });
    }
    return this.putObject(repo, 'tree', encodeTree(next));
  }

  // ---------------------------------------------------------------- repositories

  /** Create a repository (the viewer owns it unless `owner` names the org or another user). */
  createRepo(owner: string, name: string, description: string, isPrivate: boolean): RepoRecord {
    const id = this.nextRepoId;
    this.nextRepoId += 1;
    const record = this.newRepoRecord(id, owner, name, description, isPrivate, 'main');
    this.repos.set(record.fullName, record);
    return record;
  }

  /** A repository by owner/name, or undefined. */
  getRepo(owner: string, name: string): RepoRecord | undefined {
    return this.repos.get(`${owner}/${name}`);
  }

  /** All repositories, optionally filtered to one owner, in id order. */
  listRepos(owner?: string): RepoRecord[] {
    const all = [...this.repos.values()].sort((a, b) => a.id - b.id);
    return owner === undefined ? all : all.filter((repo) => repo.owner === owner);
  }

  /** Delete a repository; true when it existed. */
  deleteRepo(owner: string, name: string): boolean {
    return this.repos.delete(`${owner}/${name}`);
  }

  // ---------------------------------------------------------------- issues

  /** Create an issue on a repository. */
  createIssue(repo: RepoRecord, title: string, body: string, labels: string[], user: ScenarioUser): Issue {
    repo.issueSeq += 1;
    const now = isoNow();
    const issue: Issue = {
      number: repo.issueSeq,
      title,
      body,
      state: 'open',
      labels: labels.slice(),
      user,
      assignees: [],
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      comments: new Map<number, IssueComment>(),
      commentSeq: 0,
    };
    repo.issues.set(issue.number, issue);
    return issue;
  }

  /** An issue by number, or undefined. */
  getIssue(repo: RepoRecord, number: number): Issue | undefined {
    return repo.issues.get(number);
  }

  /** All issues on a repository, optionally filtered by state, in number order. */
  listIssues(repo: RepoRecord, state?: 'open' | 'closed' | 'all'): Issue[] {
    const all = [...repo.issues.values()].sort((a, b) => a.number - b.number);
    if (state === undefined || state === 'all') return all;
    return all.filter((issue) => issue.state === state);
  }

  /** Create a comment on an issue. */
  createComment(repo: RepoRecord, issue: Issue, body: string, user: ScenarioUser): IssueComment {
    issue.commentSeq += 1;
    const now = isoNow();
    const comment: IssueComment = { id: this.nextCommentId, body, user, createdAt: now, updatedAt: now };
    this.nextCommentId += 1;
    issue.comments.set(comment.id, comment);
    issue.updatedAt = now;
    return comment;
  }

  // ---------------------------------------------------------------- pull requests

  /** Create a pull request on a repository. */
  createPull(repo: RepoRecord, title: string, body: string, head: string, base: string, user: ScenarioUser): PullRequest {
    repo.pullSeq += 1;
    const now = isoNow();
    const headSha = this.resolveRef(repo, head);
    const baseSha = this.resolveRef(repo, base);
    const pull: PullRequest = {
      number: repo.pullSeq,
      title,
      body,
      state: 'open',
      head,
      base,
      headSha,
      baseSha,
      merged: false,
      mergeable: headSha !== null && baseSha !== null,
      user,
      createdAt: now,
      updatedAt: now,
      mergedAt: null,
      mergedBy: null,
    };
    repo.pulls.set(pull.number, pull);
    return pull;
  }

  /** A pull request by number, or undefined. */
  getPull(repo: RepoRecord, number: number): PullRequest | undefined {
    return repo.pulls.get(number);
  }

  /** All pull requests on a repository, optionally filtered by state, in number order. */
  listPulls(repo: RepoRecord, state?: 'open' | 'closed' | 'all'): PullRequest[] {
    const all = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
    if (state === undefined || state === 'all') return all;
    return all.filter((pull) => pull.state === state);
  }

  /**
   * Merge a pull request: fast-forward the base ref to the head commit when the head is ahead, else
   * create a merge commit with both as parents. Returns the merge commit SHA, or null when unmergeable.
   */
  mergePull(repo: RepoRecord, pull: PullRequest, user: ScenarioUser): string | null {
    if (pull.state !== 'open' || pull.merged) return null;
    const headSha = pull.headSha ?? this.resolveRef(repo, pull.head);
    const baseSha = pull.baseSha ?? this.resolveRef(repo, pull.base);
    if (headSha === null || baseSha === null) return null;
    const headObj = this.getObject(repo, headSha);
    if (headObj === undefined || headObj.type !== 'commit') return null;
    const baseRef = `refs/heads/${pull.base}`;
    let mergeSha: string;
    if (this.isAncestor(repo, baseSha, headSha)) {
      // Fast-forward: the base just moves to the head.
      mergeSha = headSha;
    } else {
      const baseObj = this.getObject(repo, baseSha);
      const baseInfo = baseObj !== undefined && baseObj.type === 'commit' ? parseCommit(baseObj.data) : null;
      const headInfo = parseCommit(headObj.data);
      if (baseInfo === null || headInfo === null) return null;
      const ts = Math.floor(Date.now() / 1000);
      mergeSha = this.putObject(
        repo,
        'commit',
        encodeCommit({
          tree: headInfo.tree,
          parents: [baseSha, headSha],
          authorName: user.name,
          authorEmail: user.email,
          authorTs: ts,
          committerName: user.name,
          committerEmail: user.email,
          committerTs: ts,
          message: `Merge pull request #${pull.number} from ${pull.head}`,
        }),
      );
    }
    this.setRef(repo, baseRef, mergeSha);
    pull.merged = true;
    pull.state = 'closed';
    pull.mergedAt = isoNow();
    pull.mergedBy = user.login;
    pull.updatedAt = isoNow();
    return mergeSha;
  }

  /** The files changed between a pull's base and head (added/modified/deleted with their paths). */
  pullFiles(repo: RepoRecord, pull: PullRequest): Array<{ filename: string; status: 'added' | 'modified' | 'removed'; sha: string }> {
    const headSha = pull.headSha ?? this.resolveRef(repo, pull.head);
    const baseSha = pull.baseSha ?? this.resolveRef(repo, pull.base);
    if (headSha === null || baseSha === null) return [];
    const headFiles = this.flattenTree(repo, headSha);
    const baseFiles = this.flattenTree(repo, baseSha);
    const out: Array<{ filename: string; status: 'added' | 'modified' | 'removed'; sha: string }> = [];
    for (const [path, sha] of headFiles) {
      const before = baseFiles.get(path);
      if (before === undefined) out.push({ filename: path, status: 'added', sha });
      else if (before !== sha) out.push({ filename: path, status: 'modified', sha });
    }
    for (const [path, sha] of baseFiles) {
      if (!headFiles.has(path)) out.push({ filename: path, status: 'removed', sha });
    }
    out.sort((a, b) => (a.filename < b.filename ? -1 : 1));
    return out;
  }

  /** All files at a commit, as path -> blob SHA (recursive). */
  flattenTree(repo: RepoRecord, commitSha: string): Map<string, string> {
    const out = new Map<string, string>();
    const commit = this.getObject(repo, commitSha);
    if (commit === undefined || commit.type !== 'commit') return out;
    const info = parseCommit(commit.data);
    if (info === null) return out;
    const walk = (treeSha: string, prefix: string): void => {
      const obj = this.getObject(repo, treeSha);
      if (obj === undefined || obj.type !== 'tree') return;
      const entries = parseTree(obj.data);
      if (entries === null) return;
      for (const entry of entries) {
        const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.type === 'tree') walk(entry.sha, path);
        else if (entry.type === 'blob') out.set(path, entry.sha);
      }
    };
    walk(info.tree, '');
    return out;
  }

  /** A repo's SHA-1 helper (exposed for modules that build objects directly). */
  sha1(data: Buffer | string): string {
    return sha1Hex(data);
  }
}

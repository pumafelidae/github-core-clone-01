// In-memory forge store: git objects (blob/tree/commit, SHA-1) plus the REST view
// (repos, branches, issues, PRs, labels). One process, one trial: everything lives here.
import { createHash } from 'node:crypto';
import { buildScenario } from './wire.ts';

export const SCENARIO = buildScenario();
export const VIEWER_LOGIN = SCENARIO.viewer.login;
export const VIEWER_ID = SCENARIO.viewer.id;
export const VIEWER_EMAIL = SCENARIO.viewer.email;
export const VIEWER_NAME = SCENARIO.viewer.name;

export function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

export function gitId(kind: string, dbId: number, extra = ''): string {
  return Buffer.from(`${kind}:${dbId}${extra ? `:${extra}` : ''}`).toString('base64');
}

export interface GitObject {
  type: 'blob' | 'tree' | 'commit';
  data: Buffer;
}

export interface Comment {
  id: number;
  body: string;
}

export interface Issue {
  number: number;
  id: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: Comment[];
  seq: number;
}

export interface PrFile {
  filename: string;
  status: 'added' | 'modified' | 'removed' | 'changed';
  additions: number;
  deletions: number;
  changes: number;
}

export interface PullRequest {
  number: number;
  id: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  merged_at: string | null;
  merge_commit_sha: string | null;
  head: { ref: string; sha: string };
  base: { ref: string; sha: string };
  baseSha: string;
  files: PrFile[];
  seq: number;
}

export interface Repo {
  dbId: number;
  name: string;
  owner: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  branches: Map<string, string>; // branch -> commit sha
  tags: Map<string, string>; // tag -> commit sha
  labels: Map<string, { name: string; color: string }>;
  issues: Issue[];
  prs: PullRequest[];
  counter: number; // shared issue/PR number counter
  commentCounter: number;
  seq: number;
}

export class Store {
  objects = new Map<string, GitObject>();
  repos = new Map<string, Repo>(); // key owner/name
  repoSeq = 0;
  dbIdSeq = 0;
  private commitCounter = 0;

  repoKey(owner: string, name: string): string {
    return `${owner}/${name}`;
  }

  getRepo(owner: string, name: string): Repo | undefined {
    return this.repos.get(this.repoKey(owner, name));
  }

  createRepo(name: string, isPrivate: boolean, description: string): Repo {
    const dbId = ++this.dbIdSeq;
    const repo: Repo = {
      dbId,
      name,
      owner: VIEWER_LOGIN,
      description,
      private: isPrivate,
      defaultBranch: 'main',
      branches: new Map(),
      tags: new Map(),
      labels: new Map(),
      issues: [],
      prs: [],
      counter: 0,
      commentCounter: 0,
      seq: ++this.repoSeq,
    };
    this.repos.set(this.repoKey(VIEWER_LOGIN, name), repo);
    return repo;
  }

  deleteRepo(repo: Repo): void {
    this.repos.delete(this.repoKey(repo.owner, repo.name));
  }

  listViewerRepos(): Repo[] {
    const out: Repo[] = [];
    for (const repo of this.repos.values()) if (repo.owner === VIEWER_LOGIN) out.push(repo);
    out.sort((a, b) => a.seq - b.seq);
    return out;
  }

  // ---- git objects ----

  writeObject(type: GitObject['type'], data: Buffer): string {
    const header = Buffer.from(`${type} ${data.length}\0`, 'ascii');
    const sha = sha1(Buffer.concat([header, data]));
    if (!this.objects.has(sha)) this.objects.set(sha, { type, data });
    return sha;
  }

  writeBlob(content: Buffer): string {
    return this.writeObject('blob', content);
  }

  /** Build (and store) a tree object from a flat path->content map. Returns tree sha. */
  buildTree(files: Map<string, Buffer>): string {
    // Nested dir structure: Map<dirPath, Map<name, {blobSha}|{subtree}>> — build bottom-up.
    const buildDir = (prefix: string): string => {
      const entries: { name: string; mode: string; sha: string; isDir: boolean }[] = [];
      const subdirs = new Map<string, string[]>();
      for (const path of files.keys()) {
        if (!path.startsWith(prefix)) continue;
        const rest = path.slice(prefix.length);
        const slash = rest.indexOf('/');
        if (slash === -1) {
          entries.push({ name: rest, mode: '100644', sha: this.writeBlob(files.get(path)!), isDir: false });
        } else {
          const dir = rest.slice(0, slash);
          if (!subdirs.has(dir)) subdirs.set(dir, []);
          subdirs.get(dir)!.push(path);
        }
      }
      for (const dir of subdirs.keys()) {
        entries.push({ name: dir, mode: '40000', sha: buildDir(prefix + dir + '/'), isDir: true });
      }
      entries.sort((a, b) => {
        const an = a.isDir ? `${a.name}/` : a.name;
        const bn = b.isDir ? `${b.name}/` : b.name;
        return an < bn ? -1 : an > bn ? 1 : 0;
      });
      const parts: Buffer[] = [];
      for (const e of entries) {
        parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'ascii'));
        parts.push(Buffer.from(e.sha, 'hex'));
      }
      return this.writeObject('tree', Buffer.concat(parts));
    };
    return buildDir('');
  }

  /** Flatten a tree object into path->blob-sha. */
  flattenTree(treeSha: string, prefix = '', out = new Map<string, string>()): Map<string, string> {
    const obj = this.objects.get(treeSha);
    if (!obj || obj.type !== 'tree') return out;
    let off = 0;
    const data = obj.data;
    while (off < data.length) {
      const sp = data.indexOf(0x20, off);
      const nul = data.indexOf(0x00, sp);
      const mode = data.subarray(off, sp).toString('ascii');
      const name = data.subarray(sp + 1, nul).toString('utf8');
      const sha = data.subarray(nul + 1, nul + 21).toString('hex');
      off = nul + 21;
      if (mode === '40000') this.flattenTree(sha, prefix + name + '/', out);
      else out.set(prefix + name, sha);
    }
    return out;
  }

  /** Flat path->content map for a commit sha. */
  filesOfCommit(commitSha: string): Map<string, Buffer> {
    const out = new Map<string, Buffer>();
    const commit = this.objects.get(commitSha);
    if (!commit || commit.type !== 'commit') return out;
    const text = commit.data.toString('utf8');
    const treeLine = text.split('\n').find((l) => l.startsWith('tree '));
    if (!treeLine) return out;
    const flat = this.flattenTree(treeLine.slice(5).trim());
    for (const [path, blobSha] of flat) {
      const blob = this.objects.get(blobSha);
      if (blob) out.set(path, blob.data);
    }
    return out;
  }

  treeShaOfCommit(commitSha: string): string | null {
    const commit = this.objects.get(commitSha);
    if (!commit || commit.type !== 'commit') return null;
    const line = commit.data.toString('utf8').split('\n').find((l) => l.startsWith('tree '));
    return line ? line.slice(5).trim() : null;
  }

  parentsOfCommit(commitSha: string): string[] {
    const commit = this.objects.get(commitSha);
    if (!commit || commit.type !== 'commit') return [];
    return commit.data
      .toString('utf8')
      .split('\n')
      .filter((l) => l.startsWith('parent '))
      .map((l) => l.slice(7).trim());
  }

  commitMessage(commitSha: string): string {
    const commit = this.objects.get(commitSha);
    if (!commit || commit.type !== 'commit') return '';
    const text = commit.data.toString('utf8');
    const idx = text.indexOf('\n\n');
    return idx === -1 ? '' : text.slice(idx + 2);
  }

  commitTime(commitSha: string): number {
    const commit = this.objects.get(commitSha);
    if (!commit || commit.type !== 'commit') return 0;
    const m = commit.data.toString('utf8').match(/> (\d+) \+0000/);
    return m ? Number(m[1]) : 0;
  }

  /** Create a commit on `branch` from a flat file map; returns commit sha. */
  createCommit(repo: Repo, branch: string, files: Map<string, Buffer>, message: string, parents: string[]): string {
    const treeSha = this.buildTree(files);
    this.commitCounter += 1;
    const ts = 1735689600 + this.commitCounter * 60;
    const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${ts} +0000`;
    let body = `tree ${treeSha}\n`;
    for (const p of parents) body += `parent ${p}\n`;
    body += `author ${ident}\ncommitter ${ident}\n\n${message}`;
    const sha = this.writeObject('commit', Buffer.from(body, 'utf8'));
    repo.branches.set(branch, sha);
    return sha;
  }

  /** Files at a branch tip (empty map when the branch has no commits). */
  branchFiles(repo: Repo, branch: string): Map<string, Buffer> {
    const tip = repo.branches.get(branch);
    if (!tip) return new Map();
    return this.filesOfCommit(tip);
  }

  /** Ancestry walk from a commit, newest first (BFS by time, dedup). */
  walkCommits(tip: string, limit = 10000): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    const queue: string[] = [tip];
    while (queue.length > 0 && out.length < limit) {
      // Pop the commit with the greatest timestamp (ties: insertion order).
      let best = 0;
      for (let i = 1; i < queue.length; i += 1) {
        if (this.commitTime(queue[i]!) > this.commitTime(queue[best]!)) best = i;
      }
      const sha = queue.splice(best, 1)[0]!;
      if (seen.has(sha)) continue;
      seen.add(sha);
      out.push(sha);
      for (const p of this.parentsOfCommit(sha)) if (!seen.has(p)) queue.push(p);
    }
    return out;
  }

  /** Is `ancestor` reachable from `tip`? */
  isAncestor(ancestor: string, tip: string): boolean {
    if (ancestor === tip) return true;
    const seen = new Set<string>();
    const queue = [tip];
    while (queue.length > 0) {
      const sha = queue.pop()!;
      if (sha === ancestor) return true;
      if (seen.has(sha)) continue;
      seen.add(sha);
      for (const p of this.parentsOfCommit(sha)) queue.push(p);
    }
    return false;
  }

  /** Diff two flat file maps into PR-file entries. */
  diffFiles(oldFiles: Map<string, Buffer>, newFiles: Map<string, Buffer>): PrFile[] {
    const out: PrFile[] = [];
    const names = new Set([...oldFiles.keys(), ...newFiles.keys()]);
    for (const name of [...names].sort()) {
      const oldB = oldFiles.get(name);
      const newB = newFiles.get(name);
      if (oldB && newB && oldB.equals(newB)) continue;
      const countLines = (b: Buffer): number => {
        const s = b.toString('utf8');
        if (s === '') return 0;
        return s.split('\n').length - (s.endsWith('\n') ? 1 : 0);
      };
      if (!oldB && newB) {
        const additions = countLines(newB);
        out.push({ filename: name, status: 'added', additions, deletions: 0, changes: additions });
      } else if (oldB && !newB) {
        const deletions = countLines(oldB);
        out.push({ filename: name, status: 'removed', additions: 0, deletions, changes: deletions });
      } else if (oldB && newB) {
        const a = countLines(newB);
        const d = countLines(oldB);
        out.push({ filename: name, status: 'modified', additions: a, deletions: d, changes: a + d });
      }
    }
    return out;
  }

  nextNumber(repo: Repo): number {
    repo.counter += 1;
    return repo.counter;
  }
}

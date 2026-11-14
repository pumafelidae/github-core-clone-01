// GitHub GraphQL v4: the documents gh and github-mcp-server actually send.
// A small purpose-built parser + evaluator for exactly that surface (no dependency).
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Store, VIEWER_LOGIN, gitId, type Repo, type Issue, type PullRequest } from './store.ts';
import { sendJson, errMessage, readBody, parseJsonBody, isRecord, isAuthed } from './util.ts';

// ---------------------------------------------------------------- tokenizer

type Token =
  | { kind: 'name'; value: string }
  | { kind: 'int'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'punct'; value: string }
  | { kind: 'spread'; value: '...' };

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',' || c === ';') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}():!$[]=@|&'.includes(c)) {
      tokens.push({ kind: 'punct', value: c });
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1]!;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c) && (c !== '-' || /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i;
      while (j < src.length && /[0-9.]/.test(src[j]!)) j += 1;
      tokens.push({ kind: 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j]!)) j += 1;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    // Unknown character: skip.
    i += 1;
  }
  return tokens;
}

// ---------------------------------------------------------------- AST

export interface ValueNode {
  kind: 'var' | 'string' | 'int' | 'bool' | 'null' | 'enum' | 'list' | 'object';
  value: unknown;
}

export interface FieldNode {
  alias: string | null;
  name: string;
  args: Record<string, ValueNode>;
  selections: FieldNode[] | null;
  fragmentType: string | null; // inline fragment `... on Type { }`
}

export interface Operation {
  type: 'query' | 'mutation';
  name: string | null;
  selections: FieldNode[];
}

class Parser {
  private pos = 0;
  private tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  peek(): Token | undefined {
    return this.tokens[this.pos];
  }
  next(): Token | undefined {
    return this.tokens[this.pos++];
  }
  expectPunct(v: string): void {
    const t = this.next();
    if (!t || t.kind !== 'punct' || t.value !== v) throw new Error(`expected ${v}`);
  }
  parseDocument(): Operation[] {
    const ops: Operation[] = [];
    while (this.pos < this.tokens.length) {
      ops.push(this.parseOperation());
    }
    return ops;
  }
  parseOperation(): Operation {
    const t = this.peek();
    let type: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    if (t?.kind === 'name' && (t.value === 'query' || t.value === 'mutation')) {
      type = t.value;
      this.next();
      const n = this.peek();
      if (n?.kind === 'name') {
        name = n.value;
        this.next();
      }
    }
    // Optional variable definitions: ($x: Type, ...)
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '(') {
      this.next();
      let depth = 1;
      while (depth > 0 && this.pos < this.tokens.length) {
        const tok = this.next()!;
        if (tok.kind === 'punct' && tok.value === '(') depth += 1;
        if (tok.kind === 'punct' && tok.value === ')') depth -= 1;
      }
    }
    const selections = this.parseSelectionSet();
    return { type, name, selections };
  }
  parseSelectionSet(): FieldNode[] {
    this.expectPunct('{');
    const fields: FieldNode[] = [];
    while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === '}')) {
      fields.push(this.parseField());
    }
    this.expectPunct('}');
    return fields;
  }
  parseField(): FieldNode {
    const t = this.peek();
    if (t?.kind === 'spread') {
      this.next();
      let fragmentType: string | null = null;
      const on = this.peek();
      if (on?.kind === 'name' && on.value === 'on') {
        this.next();
        const typeTok = this.next();
        fragmentType = typeTok?.kind === 'name' ? typeTok.value : null;
      } else {
        // Named fragment spread: skip the name; its selections are unknown — treat as empty.
        this.next();
      }
      const selections = this.peek()?.kind === 'punct' && this.peek()!.value === '{' ? this.parseSelectionSet() : [];
      return { alias: null, name: '', args: {}, selections, fragmentType };
    }
    let alias: string | null = null;
    let nameTok = this.next();
    if (!nameTok || nameTok.kind !== 'name') throw new Error('expected field name');
    if (this.peek()?.kind === 'punct' && this.peek()!.value === ':') {
      this.next();
      alias = nameTok.value;
      nameTok = this.next();
      if (!nameTok || nameTok.kind !== 'name') throw new Error('expected field name after alias');
    }
    const name = nameTok.value;
    let args: Record<string, ValueNode> = {};
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '(') args = this.parseArgs();
    let selections: FieldNode[] | null = null;
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '{') selections = this.parseSelectionSet();
    return { alias, name, args, selections, fragmentType: null };
  }
  parseArgs(): Record<string, ValueNode> {
    const args: Record<string, ValueNode> = {};
    this.expectPunct('(');
    while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === ')')) {
      const nameTok = this.next();
      if (!nameTok || nameTok.kind !== 'name') throw new Error('expected argument name');
      this.expectPunct(':');
      args[nameTok.value] = this.parseValue();
    }
    this.expectPunct(')');
    return args;
  }
  parseValue(): ValueNode {
    const t = this.next();
    if (!t) throw new Error('unexpected end of query');
    if (t.kind === 'punct' && t.value === '$') {
      const nameTok = this.next();
      return { kind: 'var', value: nameTok?.kind === 'name' ? nameTok.value : '' };
    }
    if (t.kind === 'string') return { kind: 'string', value: t.value };
    if (t.kind === 'int') return { kind: 'int', value: Number(t.value) };
    if (t.kind === 'name') {
      if (t.value === 'true') return { kind: 'bool', value: true };
      if (t.value === 'false') return { kind: 'bool', value: false };
      if (t.value === 'null') return { kind: 'null', value: null };
      return { kind: 'enum', value: t.value };
    }
    if (t.kind === 'punct' && t.value === '[') {
      const items: ValueNode[] = [];
      while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === ']')) items.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', value: items };
    }
    if (t.kind === 'punct' && t.value === '{') {
      const obj: Record<string, ValueNode> = {};
      while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === '}')) {
        const nameTok = this.next();
        if (!nameTok || nameTok.kind !== 'name') throw new Error('expected object key');
        this.expectPunct(':');
        obj[nameTok.value] = this.parseValue();
      }
      this.expectPunct('}');
      return { kind: 'object', value: obj };
    }
    throw new Error(`unexpected token ${JSON.stringify(t)}`);
  }
}

function resolveValue(node: ValueNode, variables: Record<string, unknown>): unknown {
  switch (node.kind) {
    case 'var':
      return variables[node.value as string];
    case 'string':
    case 'int':
    case 'bool':
    case 'null':
    case 'enum':
      return node.value;
    case 'list':
      return (node.value as ValueNode[]).map((v) => resolveValue(v, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node.value as Record<string, ValueNode>)) out[k] = resolveValue(v, variables);
      return out;
    }
  }
}

function argsOf(field: FieldNode, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) out[k] = resolveValue(v, variables);
  return out;
}

// ---------------------------------------------------------------- schema data

const ISSUE_FIELDS = ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'closedAt', 'repository'];
const PULL_REQUEST_FIELDS = ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'headRef', 'baseRef', 'author', 'createdAt', 'updatedAt', 'repository'];
const REPOSITORY_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt'];
const SEARCH_TYPE_VALUES = ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'TOPIC', 'PACKAGE', 'MILESTONE'];

interface Ctx {
  store: Store;
  variables: Record<string, unknown>;
  errors: { message: string }[];
}

type Obj = Record<string, unknown> & { __typename: string };

function repoObj(store: Store, repo: Repo): Obj {
  return { __typename: 'Repository', __repo: repo, id: gitId('Repository', repo.dbId), databaseId: repo.dbId, name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` };
}

function issueObj(repo: Repo, issue: Issue): Obj {
  return { __typename: 'Issue', __repo: repo, __issue: issue, id: issue.id, number: issue.number, title: issue.title, state: issue.state === 'open' ? 'OPEN' : 'CLOSED', body: issue.body };
}

function prObj(repo: Repo, pr: PullRequest): Obj {
  const state = pr.merged ? 'MERGED' : pr.state === 'closed' ? 'CLOSED' : 'OPEN';
  return { __typename: 'PullRequest', __repo: repo, __pr: pr, id: pr.id, number: pr.number, title: pr.title, body: pr.body, state, merged: pr.merged };
}

function decodeGlobalId(id: string): { kind: string; dbId: number; num: number } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const m = /^(\w+):(\d+)(?::(\d+))?$/.exec(text);
    if (!m) return null;
    return { kind: m[1]!, dbId: Number(m[2]), num: m[3] !== undefined ? Number(m[3]) : 0 };
  } catch {
    return null;
  }
}

function findRepoByDbId(store: Store, dbId: number): Repo | undefined {
  for (const repo of store.repos.values()) if (repo.dbId === dbId) return repo;
  return undefined;
}

// ---------------------------------------------------------------- evaluation

function selectFields(obj: Obj, fields: FieldNode[], ctx: Ctx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    if (field.fragmentType !== null) {
      // Inline fragment: apply only when the type matches.
      if (field.name === '' && field.fragmentType === obj.__typename) {
        Object.assign(out, selectFields(obj, field.selections ?? [], ctx));
      }
      continue;
    }
    const key = field.alias ?? field.name;
    out[key] = resolveField(obj, field, ctx);
  }
  return out;
}

function unknownField(ctx: Ctx, typeName: string, field: string): null {
  ctx.errors.push({ message: `Cannot query field "${field}" on type "${typeName}".` });
  return null;
}

function resolveField(obj: Obj, field: FieldNode, ctx: Ctx): unknown {
  const args = argsOf(field, ctx.variables);
  const name = field.name;
  const subs = field.selections;

  // Query root
  if (obj.__typename === 'Query') {
    if (name === 'viewer') {
      if (!subs) return null;
      return selectFields({ __typename: 'User', login: VIEWER_LOGIN } as Obj, subs, ctx);
    }
    if (name === 'repository') {
      const repo = [...ctx.store.repos.values()].find((r) => r.owner === args.owner && r.name === args.name);
      if (!repo) return null;
      if (!subs) return null;
      return selectFields(repoObj(ctx.store, repo), subs, ctx);
    }
    if (name === 'node') {
      const decoded = typeof args.id === 'string' ? decodeGlobalId(args.id) : null;
      if (!decoded) return null;
      if (decoded.kind === 'Repository') {
        const repo = findRepoByDbId(ctx.store, decoded.dbId);
        if (!repo) return null;
        if (!subs) return null;
        return selectFields(repoObj(ctx.store, repo), subs, ctx);
      }
      return null;
    }
    if (name === '__type') {
      const typeName = args.name as string;
      let fields: string[] | null = null;
      let enumValues: string[] | null = null;
      if (typeName === 'Issue') fields = ISSUE_FIELDS;
      else if (typeName === 'PullRequest') fields = PULL_REQUEST_FIELDS;
      else if (typeName === 'Repository') fields = REPOSITORY_FIELDS;
      else if (typeName === 'SearchType') enumValues = SEARCH_TYPE_VALUES;
      if (fields === null && enumValues === null) return null;
      const out: Record<string, unknown> = {};
      if (subs) {
        for (const sub of subs) {
          if (sub.name === 'fields') out[sub.alias ?? 'fields'] = (fields ?? []).map((f) => ({ name: f }));
          else if (sub.name === 'enumValues') out[sub.alias ?? 'enumValues'] = (enumValues ?? []).map((v) => ({ name: v }));
          else if (sub.name === 'name') out[sub.alias ?? 'name'] = typeName;
          else if (sub.name === 'kind') out[sub.alias ?? 'kind'] = enumValues ? 'ENUM' : 'OBJECT';
        }
      }
      return out;
    }
    return unknownField(ctx, 'Query', name);
  }

  // User
  if (obj.__typename === 'User') {
    if (name === 'login') return obj.login;
    return unknownField(ctx, 'User', name);
  }

  // Repository
  if (obj.__typename === 'Repository') {
    const repo = obj.__repo as Repo;
    switch (name) {
      case 'id':
      case 'databaseId':
      case 'name':
      case 'nameWithOwner':
        return obj[name];
      case 'owner':
        return subs ? selectFields({ __typename: 'User', login: repo.owner } as Obj, subs, ctx) : { login: repo.owner };
      case 'defaultBranchRef':
        return subs ? selectFields({ __typename: 'Ref', name: repo.defaultBranch } as Obj, subs, ctx) : { name: repo.defaultBranch };
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'description':
        return repo.description;
      case 'issue': {
        const issue = repo.issues.find((i) => i.number === args.number);
        if (!issue) return null;
        return subs ? selectFields(issueObj(repo, issue), subs, ctx) : issueObj(repo, issue);
      }
      case 'issues': {
        let list = repo.issues.slice();
        if (Array.isArray(args.states)) {
          const wanted = new Set((args.states as string[]).map((s) => String(s).toLowerCase()));
          list = list.filter((i) => wanted.has(i.state));
        }
        const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
        const dir = orderBy && orderBy.direction === 'ASC' ? 1 : -1;
        list.sort((a, b) => (a.seq - b.seq) * dir);
        const first = typeof args.first === 'number' ? args.first : list.length;
        let start = 0;
        if (typeof args.after === 'string' && args.after !== '') {
          const decoded = Buffer.from(args.after, 'base64').toString('utf8');
          const m = /^cursor:(\d+)$/.exec(decoded);
          if (m) {
            const idx = list.findIndex((i) => i.seq === Number(m[1]));
            if (idx >= 0) start = idx + 1;
          }
        }
        const page = list.slice(start, start + first);
        const hasNext = start + first < list.length;
        const endCursor = page.length > 0 ? Buffer.from(`cursor:${page[page.length - 1]!.seq}`).toString('base64') : null;
        const nodes = page.map((i) => (subs ? selectFields(issueObj(repo, i), nodeSelections(subs), ctx) : issueObj(repo, i)));
        return connectionResult(subs, nodes, hasNext, endCursor);
      }
      case 'pullRequests': {
        const first = typeof args.first === 'number' ? args.first : repo.prs.length;
        const page = repo.prs.slice(0, first);
        const nodes = page.map((p) => (subs ? selectFields(prObj(repo, p), nodeSelections(subs), ctx) : prObj(repo, p)));
        return connectionResult(subs, nodes, false, null);
      }
      case 'pullRequest': {
        const pr = repo.prs.find((p) => p.number === args.number);
        if (!pr) return null;
        return subs ? selectFields(prObj(repo, pr), subs, ctx) : prObj(repo, pr);
      }
      default:
        return unknownField(ctx, 'Repository', name);
    }
  }

  // Issue
  if (obj.__typename === 'Issue') {
    if (['id', 'number', 'title', 'state', 'body'].includes(name)) return obj[name];
    return unknownField(ctx, 'Issue', name);
  }

  // IssueComment
  if (obj.__typename === 'IssueComment') {
    if (name === 'id' || name === 'body') return obj[name];
    return unknownField(ctx, 'IssueComment', name);
  }

  // PullRequest
  if (obj.__typename === 'PullRequest') {
    const repo = obj.__repo as Repo;
    const pr = obj.__pr as PullRequest;
    switch (name) {
      case 'id':
      case 'number':
      case 'state':
      case 'merged':
        return obj[name];
      case 'headRefName':
        return pr.head.ref;
      case 'baseRefName':
        return pr.base.ref;
      case 'mergeable': {
        // Conflict when the base moved and changed a file the PR also changed.
        const baseTip = repo.branches.get(pr.base.ref);
        if (baseTip && baseTip !== pr.baseSha) {
          const prBaseFiles = ctx.store.filesOfCommit(pr.baseSha);
          const baseNowFiles = ctx.store.filesOfCommit(baseTip);
          const baseChanged = new Set(ctx.store.diffFiles(prBaseFiles, baseNowFiles).map((f) => f.filename));
          if (pr.files.some((f) => baseChanged.has(f.filename))) return 'CONFLICTING';
        }
        return 'MERGEABLE';
      }
      case 'files': {
        const first = typeof args.first === 'number' ? args.first : pr.files.length;
        const nodes = pr.files.slice(0, first).map((f) => {
          const fileSubs = nodeSelections(subs);
          const out: Record<string, unknown> = {};
          for (const s of fileSubs) {
            if (s.name === 'path') out[s.alias ?? 'path'] = f.filename;
            else if (s.name === 'additions') out[s.alias ?? 'additions'] = f.additions;
            else if (s.name === 'deletions') out[s.alias ?? 'deletions'] = f.deletions;
          }
          return out;
        });
        return connectionResult(subs, nodes, false, null);
      }
      default:
        return unknownField(ctx, 'PullRequest', name);
    }
  }

  // Ref
  if (obj.__typename === 'Ref') {
    if (name === 'name') return obj.name;
    return unknownField(ctx, 'Ref', name);
  }

  return unknownField(ctx, obj.__typename, name);
}

/** The `nodes` selection inside a connection field, or the connection's own selections. */
function nodeSelections(subs: FieldNode[] | null): FieldNode[] {
  if (!subs) return [];
  const nodesField = subs.find((s) => s.name === 'nodes');
  return nodesField?.selections ?? [];
}

function connectionResult(subs: FieldNode[] | null, nodes: unknown[], hasNextPage: boolean, endCursor: string | null): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!subs) return { nodes };
  for (const sub of subs) {
    if (sub.name === 'nodes') out[sub.alias ?? 'nodes'] = nodes;
    else if (sub.name === 'pageInfo') {
      const pi: Record<string, unknown> = {};
      for (const p of sub.selections ?? []) {
        if (p.name === 'hasNextPage') pi[p.alias ?? 'hasNextPage'] = hasNextPage;
        else if (p.name === 'endCursor') pi[p.alias ?? 'endCursor'] = endCursor;
      }
      out[sub.alias ?? 'pageInfo'] = pi;
    } else if (sub.name === 'totalCount') out[sub.alias ?? 'totalCount'] = nodes.length;
  }
  return out;
}

// ---------------------------------------------------------------- mutations

function executeMutation(op: Operation, ctx: Ctx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of op.selections) {
    const key = field.alias ?? field.name;
    const args = argsOf(field, ctx.variables);
    const subs = field.selections ?? [];
    if (field.name === 'createIssue') {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.repositoryId === 'string' ? decodeGlobalId(input.repositoryId) : null;
      const repo = decoded ? findRepoByDbId(ctx.store, decoded.dbId) : undefined;
      if (!repo || typeof input.title !== 'string') {
        ctx.errors.push({ message: 'createIssue: repository not found' });
        out[key] = null;
        continue;
      }
      const number = ctx.store.nextNumber(repo);
      const issue: Issue = {
        number,
        id: gitId('Issue', repo.dbId, String(number)),
        title: input.title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        comments: [],
        seq: repo.counter,
      };
      repo.issues.push(issue);
      out[key] = pick(subs, { issue: issueObj(repo, issue) }, ctx);
      continue;
    }
    if (field.name === 'closeIssue') {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.issueId === 'string' ? decodeGlobalId(input.issueId) : null;
      let found: { repo: Repo; issue: Issue } | null = null;
      if (decoded) {
        const repo = findRepoByDbId(ctx.store, decoded.dbId);
        if (repo) {
          const issue = repo.issues.find((i) => i.number === decoded.num);
          if (issue) found = { repo, issue };
        }
      }
      if (!found) {
        ctx.errors.push({ message: 'closeIssue: issue not found' });
        out[key] = null;
        continue;
      }
      found.issue.state = 'closed';
      out[key] = pick(subs, { issue: issueObj(found.repo, found.issue) }, ctx);
      continue;
    }
    if (field.name === 'createPullRequest') {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.repositoryId === 'string' ? decodeGlobalId(input.repositoryId) : null;
      const repo = decoded ? findRepoByDbId(ctx.store, decoded.dbId) : undefined;
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const baseRef = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const headSha = repo?.branches.get(head);
      const baseSha = repo?.branches.get(baseRef);
      if (!repo || !headSha || !baseSha || typeof input.title !== 'string') {
        ctx.errors.push({ message: 'createPullRequest: repository or branch not found' });
        out[key] = null;
        continue;
      }
      const files = ctx.store.diffFiles(ctx.store.filesOfCommit(baseSha), ctx.store.filesOfCommit(headSha));
      const number = ctx.store.nextNumber(repo);
      const pr: PullRequest = {
        number,
        id: gitId('PullRequest', repo.dbId, String(number)),
        title: input.title,
        body: '',
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
      out[key] = pick(subs, { pullRequest: prObj(repo, pr) }, ctx);
      continue;
    }
    if (field.name === 'mergePullRequest') {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.pullRequestId === 'string' ? decodeGlobalId(input.pullRequestId) : null;
      let found: { repo: Repo; pr: PullRequest } | null = null;
      if (decoded) {
        const repo = findRepoByDbId(ctx.store, decoded.dbId);
        if (repo) {
          const pr = repo.prs.find((p) => p.number === decoded.num);
          if (pr) found = { repo, pr };
        }
      }
      if (!found) {
        ctx.errors.push({ message: 'mergePullRequest: pull request not found' });
        out[key] = null;
        continue;
      }
      const { repo, pr } = found;
      if (!pr.merged && pr.state === 'open') {
        const baseTip = repo.branches.get(pr.base.ref);
        if (baseTip) {
          const mergedFiles = ctx.store.filesOfCommit(baseTip);
          const headFiles = ctx.store.filesOfCommit(pr.head.sha);
          for (const f of pr.files) {
            if (f.status === 'removed') mergedFiles.delete(f.filename);
            else {
              const c = headFiles.get(f.filename);
              if (c !== undefined) mergedFiles.set(f.filename, c);
            }
          }
          const mergeSha = ctx.store.createCommit(repo, pr.base.ref, mergedFiles, `${pr.title} (#${pr.number})`, [baseTip]);
          pr.merged = true;
          pr.state = 'closed';
          pr.merged_at = new Date().toISOString();
          pr.merge_commit_sha = mergeSha;
        }
      }
      out[key] = pick(subs, { pullRequest: prObj(repo, pr) }, ctx);
      continue;
    }
    if (field.name === 'addComment') {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.subjectId === 'string' ? decodeGlobalId(input.subjectId) : null;
      let found: { repo: Repo; issue: Issue } | null = null;
      if (decoded && decoded.kind === 'Issue') {
        const repo = findRepoByDbId(ctx.store, decoded.dbId);
        if (repo) {
          const issue = repo.issues.find((i) => i.number === decoded.num);
          if (issue) found = { repo, issue };
        }
      }
      if (!found || typeof input.body !== 'string') {
        ctx.errors.push({ message: 'addComment: subject not found' });
        out[key] = null;
        continue;
      }
      found.repo.commentCounter += 1;
      const comment = { id: found.repo.commentCounter, body: input.body };
      found.issue.comments.push(comment);
      const nodeObj: Obj = { __typename: 'IssueComment', id: gitId('IssueComment', found.repo.dbId, `${found.issue.number}:${comment.id}`), body: comment.body };
      out[key] = pick(subs, { commentEdge: { node: nodeObj } }, ctx);
      continue;
    }
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Mutation".` });
    out[key] = null;
  }
  return out;
}

/** Pick requested subfields from a value object (plain object or Obj). */
function pick(subs: FieldNode[], value: Record<string, unknown>, ctx: Ctx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sub of subs) {
    const key = sub.alias ?? sub.name;
    const v = value[sub.name];
    if (v !== null && typeof v === 'object' && sub.selections) {
      if (Array.isArray(v)) out[key] = v;
      else if ((v as Obj).__typename) out[key] = selectFields(v as Obj, sub.selections, ctx);
      else out[key] = pick(sub.selections, v as Record<string, unknown>, ctx);
    } else {
      out[key] = v ?? null;
    }
  }
  return out;
}

// ---------------------------------------------------------------- HTTP entry

function executeOne(query: string, variables: Record<string, unknown>, store: Store): { data: unknown; errors?: { message: string }[] } {
  let ops: Operation[];
  try {
    ops = new Parser(tokenize(query)).parseDocument();
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : 'GraphQL parse error' }] };
  }
  const op = ops[0];
  if (!op) return { data: null, errors: [{ message: 'No operation provided' }] };
  const ctx: Ctx = { store, variables, errors: [] };
  let data: Record<string, unknown>;
  if (op.type === 'mutation') {
    data = executeMutation(op, ctx);
  } else {
    data = selectFields({ __typename: 'Query' } as Obj, op.selections, ctx);
  }
  if (ctx.errors.length > 0) return { data, errors: ctx.errors };
  return { data };
}

export async function handleGraphQL(req: IncomingMessage, res: ServerResponse, store: Store): Promise<boolean> {
  if ((req.method ?? 'GET') !== 'POST') return false;
  if (!isAuthed(req)) {
    errMessage(res, 401, 'Requires authentication');
    return true;
  }
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
  if (Array.isArray(value)) {
    // Batched operations: one envelope per operation, in order.
    const results = value.map((op) => {
      if (!isRecord(op) || typeof op.query !== 'string') return { data: null, errors: [{ message: 'Invalid operation' }] };
      const vars = isRecord(op.variables) ? (op.variables as Record<string, unknown>) : {};
      return executeOne(op.query, vars, store);
    });
    sendJson(res, 200, results);
    return true;
  }
  if (!isRecord(value) || typeof value.query !== 'string') {
    errMessage(res, 400, 'A query is required');
    return true;
  }
  const vars = isRecord(value.variables) ? (value.variables as Record<string, unknown>) : {};
  const result = executeOne(value.query, vars, store);
  sendJson(res, 200, result);
  return true;
}

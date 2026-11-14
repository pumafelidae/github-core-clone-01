// The GraphQL v4 surface: POST /api/graphql, gh's and github-mcp-server's documents.
//
// A hand-written GraphQL parser and evaluator, Node stdlib only. No graphql library exists in
// this entry and none is needed: the documents the suite sends are fixed shapes (viewer,
// repository fields, __type probes, issue and pull-request reads, the create/close/merge/comment
// mutations, node(id:), cursor pagination, operation batching), and the evaluator resolves them
// generically against the Forge instead of hardcoding per-document answers.
//
// Global ids are opaque base64 of "<Type>:<key>" (Repository:<databaseId>,
// Issue:<repoId>:<number>, PullRequest:<repoId>:<number>, User:<login>,
// Label:<repoId>:<name>, IssueComment:<repoId>:<issueNumber>:<commentId>,
// Commit:<repoId>:<sha>), so an id returned by one query resolves through node(id:) and is
// stable across reads. Cursors are opaque base64 of "cursor:<index>".
//
// Error shape follows the wire: a GraphQL-level failure (an unknown field, a bad argument, an
// unresolvable mutation input) is a 200 whose body carries `errors` alongside whatever data
// resolved; a syntactically malformed document is a 400 with `errors`; a missing or wrong
// bearer token is a 401 {"message":"Bad credentials"}.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Forge, parseCommit, parseTag, parseTree } from './store.ts';
import type { Issue, IssueComment, Label, PullRequest, RepoRecord } from './store.ts';
import type { ScenarioUser } from './wire.ts';
import { fromBase64, isAuthorized, isRecord, isoNow, pathOf, readJsonBody, sendJson, sendUnauthorized, toBase64 } from './util.ts';

/** One node in the execution tree: its GraphQL type plus the store data behind it. */
interface Parent {
  readonly __typename: string;
  [key: string]: unknown;
}

/** One entry of a response's `errors` array. */
interface GraphQLError {
  message: string;
  path?: (string | number)[];
}

// ---------------------------------------------------------------------------
// Global ids and cursors
// ---------------------------------------------------------------------------

/** An opaque global id for a node: base64("<Type>:<key>"). */
function gid(type: string, key: string): string {
  return toBase64(Buffer.from(`${type}:${key}`, 'utf8'));
}

function repoGid(repo: RepoRecord): string {
  return gid('Repository', String(repo.id));
}

function issueGid(repo: RepoRecord, issue: Issue): string {
  return gid('Issue', `${repo.id}:${issue.number}`);
}

function pullGid(repo: RepoRecord, pull: PullRequest): string {
  return gid('PullRequest', `${repo.id}:${pull.number}`);
}

function userGid(login: string): string {
  return gid('User', login);
}

function labelGid(repo: RepoRecord, label: Label): string {
  return gid('Label', `${repo.id}:${label.name}`);
}

function commentGid(repo: RepoRecord, issue: Issue, comment: IssueComment): string {
  return gid('IssueComment', `${repo.id}:${issue.number}:${comment.id}`);
}

function commitGid(repo: RepoRecord, sha: string): string {
  return gid('Commit', `${repo.id}:${sha}`);
}

function refGid(repo: RepoRecord, name: string): string {
  return gid('Ref', `${repo.id}:${name}`);
}

/** Split "a:b" at the first colon; the rest may itself hold colons. */
function splitOnce(text: string): [string, string] {
  const index = text.indexOf(':');
  return index < 0 ? [text, ''] : [text.slice(0, index), text.slice(index + 1)];
}

/** Decode an opaque global id, or null when it is not one. */
function parseGid(id: string): { type: string; key: string } | null {
  const buf = fromBase64(id);
  if (buf === null) return null;
  const text = buf.toString('utf8');
  const [type, key] = splitOnce(text);
  if (type === '' || key === '') return null;
  return { type, key };
}

/** An opaque cursor for a connection offset: base64("cursor:<index>"). */
function encodeCursor(index: number): string {
  return toBase64(Buffer.from(`cursor:${index}`, 'utf8'));
}

/** Decode a cursor to its offset, or null when it is not one. */
function decodeCursor(cursor: unknown): number | null {
  if (typeof cursor !== 'string') return null;
  const buf = fromBase64(cursor);
  if (buf === null) return null;
  const match = /^cursor:(\d+)$/.exec(buf.toString('utf8'));
  return match === null ? null : Number(match[1]);
}

// ---------------------------------------------------------------------------
// Node parents
// ---------------------------------------------------------------------------

function userParent(user: ScenarioUser): Parent {
  return { __typename: 'User', user };
}

function syntheticUser(login: string): Parent {
  return { __typename: 'User', user: { id: 0, login, name: login, email: '' } as ScenarioUser };
}

/** A User node for a login: a scenario user when one exists, else a bare login holder. */
function userForLogin(forge: Forge, login: string): Parent {
  const found = forge.users.get(login);
  return found === undefined ? syntheticUser(login) : userParent(found);
}

function repoParent(repo: RepoRecord): Parent {
  return { __typename: 'Repository', repo };
}

function issueParent(repo: RepoRecord, issue: Issue): Parent {
  return { __typename: 'Issue', repo, issue };
}

function pullParent(repo: RepoRecord, pull: PullRequest): Parent {
  return { __typename: 'PullRequest', repo, pull };
}

function labelParent(repo: RepoRecord, label: Label): Parent {
  return { __typename: 'Label', repo, label };
}

function commentParent(repo: RepoRecord, issue: Issue, comment: IssueComment): Parent {
  return { __typename: 'IssueComment', repo, issue, comment };
}

function commitParent(repo: RepoRecord, sha: string): Parent {
  return { __typename: 'Commit', repo, sha };
}

function treeParent(repo: RepoRecord, sha: string): Parent {
  return { __typename: 'Tree', repo, sha };
}

function blobParent(repo: RepoRecord, sha: string, data: Buffer): Parent {
  return { __typename: 'Blob', repo, sha, data };
}

function refParent(repo: RepoRecord, name: string, sha: string): Parent {
  return { __typename: 'Ref', repo, name, sha };
}

function gitActorParent(name: string, email: string, ts: number): Parent {
  return { __typename: 'GitActor', name, email, date: new Date(ts * 1000).toISOString() };
}

/** A repository by numeric database id, or undefined. */
function findRepoById(forge: Forge, id: number): RepoRecord | undefined {
  for (const repo of forge.repos.values()) {
    if (repo.id === id) return repo;
  }
  return undefined;
}

/** Resolve a global id to its node, or null when it names nothing. */
function resolveNode(forge: Forge, id: string): Parent | null {
  const parsed = parseGid(id);
  if (parsed === null) return null;
  const { type, key } = parsed;
  if (type === 'User') return userForLogin(forge, key);
  const [repoIdText, rest] = splitOnce(key);
  const repo = findRepoById(forge, Number(repoIdText));
  if (repo === undefined) return null;
  if (type === 'Repository') return repoParent(repo);
  if (type === 'Issue') {
    const issue = forge.getIssue(repo, Number(rest));
    return issue === undefined ? null : issueParent(repo, issue);
  }
  if (type === 'PullRequest') {
    const pull = forge.getPull(repo, Number(rest));
    return pull === undefined ? null : pullParent(repo, pull);
  }
  if (type === 'Label') {
    const label = repo.labels.get(rest);
    return label === undefined ? null : labelParent(repo, label);
  }
  if (type === 'IssueComment') {
    const [issueText, commentText] = splitOnce(rest);
    const issue = forge.getIssue(repo, Number(issueText));
    if (issue === undefined) return null;
    const comment = issue.comments.get(Number(commentText));
    return comment === undefined ? null : commentParent(repo, issue, comment);
  }
  if (type === 'Commit') {
    const obj = forge.getObject(repo, rest);
    return obj !== undefined && obj.type === 'commit' ? commitParent(repo, rest) : null;
  }
  if (type === 'Tree') {
    const obj = forge.getObject(repo, rest);
    return obj !== undefined && obj.type === 'tree' ? treeParent(repo, rest) : null;
  }
  if (type === 'Blob') {
    const obj = forge.getObject(repo, rest);
    return obj !== undefined && obj.type === 'blob' ? blobParent(repo, rest, obj.data) : null;
  }
  if (type === 'Ref') {
    const sha = repo.refs.get(rest) ?? repo.refs.get(`refs/heads/${rest}`) ?? repo.refs.get(`refs/tags/${rest}`);
    return sha === undefined ? null : refParent(repo, rest, sha);
  }
  return null;
}

// ---------------------------------------------------------------------------
// The schema: field lists (validation + introspection) and introspection types
// ---------------------------------------------------------------------------

const CONNECTION_FIELDS = ['nodes', 'edges', 'pageInfo', 'totalCount'];
const EDGE_FIELDS = ['node', 'cursor'];

/** Every field each object type carries. The executor rejects anything not listed. */
const SCHEMA_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', 'nodes', 'search', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'isPrivate', 'defaultBranchRef',
    'url', 'createdAt', 'updatedAt', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues',
    'pullRequest', 'pullRequests', 'object', 'ref', 'refs', 'labels',
  ],
  Issue: [
    'id', 'number', 'title', 'body', 'state', 'author', 'labels', 'comments',
    'createdAt', 'updatedAt', 'closedAt', 'url', 'repository',
  ],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'author', 'labels', 'comments', 'createdAt', 'updatedAt',
    'url', 'repository', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'headRef', 'baseRef',
    'merged', 'mergeable', 'files',
  ],
  User: ['id', 'login', 'name', 'email', 'url'],
  Label: ['id', 'name', 'color', 'description', 'url'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'updatedAt', 'url'],
  Commit: ['id', 'oid', 'message', 'messageHeadline', 'author', 'committer', 'tree', 'parents', 'url'],
  Tree: ['id', 'oid', 'entries'],
  TreeEntry: ['name', 'mode', 'type', 'oid', 'object'],
  Blob: ['id', 'oid', 'text', 'byteSize', 'isBinary'],
  Ref: ['id', 'name', 'target'],
  GitActor: ['name', 'email', 'date', 'user'],
  IssueConnection: CONNECTION_FIELDS,
  PullRequestConnection: CONNECTION_FIELDS,
  IssueCommentConnection: CONNECTION_FIELDS,
  LabelConnection: CONNECTION_FIELDS,
  RefConnection: CONNECTION_FIELDS,
  PullRequestChangedFileConnection: CONNECTION_FIELDS,
  SearchResultItemConnection: [...CONNECTION_FIELDS, 'issueCount', 'repositoryCount'],
  IssueEdge: EDGE_FIELDS,
  PullRequestEdge: EDGE_FIELDS,
  IssueCommentEdge: EDGE_FIELDS,
  LabelEdge: EDGE_FIELDS,
  RefEdge: EDGE_FIELDS,
  PullRequestChangedFileEdge: EDGE_FIELDS,
  SearchResultItemEdge: EDGE_FIELDS,
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  __Schema: ['queryType', 'mutationType', 'subscriptionType', 'types', 'directives'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'ofType', 'possibleTypes'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason'],
  __InputValue: ['name', 'description', 'type', 'defaultValue'],
  __Directive: ['name', 'description', 'locations', 'args'],
};

/** The enum types and their values (for __type enumValues). */
const ENUM_VALUES: Readonly<Record<string, readonly string[]>> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
};

/** The types that implement the Node interface (for `... on Node` and node(id:)). */
const NODE_TYPES = new Set([
  'Repository', 'Issue', 'PullRequest', 'User', 'Label', 'IssueComment', 'Commit', 'Tree', 'Blob', 'Ref',
]);

/** The kind of each named type, for __type(name:). */
function typeKind(name: string): string {
  if (name in ENUM_VALUES) return 'ENUM';
  if (name === 'Node' || name === 'GitObject' || name === 'SearchResultItem') return name === 'Node' ? 'INTERFACE' : 'UNION';
  if (name === 'String' || name === 'Int' || name === 'Float' || name === 'Boolean' || name === 'ID') return 'SCALAR';
  return 'OBJECT';
}

/** Every named type the schema knows, for __schema.types. */
function allTypeNames(): string[] {
  const names = new Set<string>(Object.keys(SCHEMA_FIELDS));
  for (const name of Object.keys(ENUM_VALUES)) names.add(name);
  for (const name of ['Node', 'GitObject', 'SearchResultItem', 'String', 'Int', 'Float', 'Boolean', 'ID']) names.add(name);
  return [...names].sort();
}

/**
 * The introspection type of one field, in "String!", "[Issue!]!" shorthand; the __Type resolver
 * expands it into nested __Type parents.
 */
const FIELD_SPECS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  Query: {
    viewer: 'User', repository: 'Repository', node: 'Node', nodes: '[Node]', search: 'SearchResultItemConnection',
    __type: '__Type', __schema: '__Schema',
  },
  Mutation: {
    createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload',
    mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload',
  },
  Repository: {
    id: 'ID!', databaseId: 'Int!', name: 'String!', nameWithOwner: 'String!', owner: 'User!', description: 'String',
    isPrivate: 'Boolean!', defaultBranchRef: 'Ref', url: 'String!', createdAt: 'String!', updatedAt: 'String!',
    viewerPermission: 'RepositoryPermission', hasIssuesEnabled: 'Boolean!', issue: 'Issue', issues: 'IssueConnection!',
    pullRequest: 'PullRequest', pullRequests: 'PullRequestConnection!', object: 'GitObject', ref: 'Ref',
    refs: 'RefConnection!', labels: 'LabelConnection!',
  },
  Issue: {
    id: 'ID!', number: 'Int!', title: 'String!', body: 'String', state: 'IssueState!', author: 'User',
    labels: 'LabelConnection!', comments: 'IssueCommentConnection!', createdAt: 'String!', updatedAt: 'String!',
    closedAt: 'String', url: 'String!', repository: 'Repository!',
  },
  PullRequest: {
    id: 'ID!', number: 'Int!', title: 'String!', body: 'String', state: 'PullRequestState!', author: 'User',
    labels: 'LabelConnection!', comments: 'IssueCommentConnection!', createdAt: 'String!', updatedAt: 'String!',
    url: 'String!', repository: 'Repository!', headRefName: 'String!', baseRefName: 'String!', headRefOid: 'String',
    baseRefOid: 'String', headRef: 'Ref', baseRef: 'Ref', merged: 'Boolean!', mergeable: 'MergeableState!',
    files: 'PullRequestChangedFileConnection!',
  },
  User: { id: 'ID!', login: 'String!', name: 'String', email: 'String', url: 'String!' },
  Label: { id: 'ID!', name: 'String!', color: 'String!', description: 'String', url: 'String!' },
  IssueComment: { id: 'ID!', body: 'String!', author: 'User', createdAt: 'String!', updatedAt: 'String!', url: 'String!' },
  Commit: {
    id: 'ID!', oid: 'String!', message: 'String!', messageHeadline: 'String!', author: 'GitActor',
    committer: 'GitActor', tree: 'Tree!', parents: '[Commit!]', url: 'String!',
  },
  Tree: { id: 'ID!', oid: 'String!', entries: '[TreeEntry!]' },
  TreeEntry: { name: 'String!', mode: 'String!', type: 'String!', oid: 'String!', object: 'GitObject' },
  Blob: { id: 'ID!', oid: 'String!', text: 'String', byteSize: 'Int!', isBinary: 'Boolean!' },
  Ref: { id: 'ID!', name: 'String!', target: 'GitObject' },
  GitActor: { name: 'String', email: 'String', date: 'String', user: 'User' },
  IssueConnection: { nodes: '[Issue]', edges: '[IssueEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!' },
  PullRequestConnection: { nodes: '[PullRequest]', edges: '[PullRequestEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!' },
  IssueCommentConnection: { nodes: '[IssueComment]', edges: '[IssueCommentEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!' },
  LabelConnection: { nodes: '[Label]', edges: '[LabelEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!' },
  RefConnection: { nodes: '[Ref]', edges: '[RefEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!' },
  PullRequestChangedFileConnection: {
    nodes: '[PullRequestChangedFile]', edges: '[PullRequestChangedFileEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!',
  },
  SearchResultItemConnection: {
    nodes: '[SearchResultItem]', edges: '[SearchResultItemEdge]', pageInfo: 'PageInfo!', totalCount: 'Int!',
    issueCount: 'Int!', repositoryCount: 'Int!',
  },
  IssueEdge: { node: 'Issue', cursor: 'String!' },
  PullRequestEdge: { node: 'PullRequest', cursor: 'String!' },
  IssueCommentEdge: { node: 'IssueComment', cursor: 'String!' },
  LabelEdge: { node: 'Label', cursor: 'String!' },
  RefEdge: { node: 'Ref', cursor: 'String!' },
  PullRequestChangedFileEdge: { node: 'PullRequestChangedFile', cursor: 'String!' },
  SearchResultItemEdge: { node: 'SearchResultItem', cursor: 'String!' },
  PullRequestChangedFile: { path: 'String!', additions: 'Int!', deletions: 'Int!', changeType: 'String!' },
  PageInfo: { hasNextPage: 'Boolean!', hasPreviousPage: 'Boolean!', startCursor: 'String', endCursor: 'String' },
  CreateIssuePayload: { issue: 'Issue', clientMutationId: 'String' },
  CloseIssuePayload: { issue: 'Issue', clientMutationId: 'String' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest', clientMutationId: 'String' },
  MergePullRequestPayload: { pullRequest: 'PullRequest', clientMutationId: 'String' },
  AddCommentPayload: { commentEdge: 'IssueCommentEdge', clientMutationId: 'String' },
  __Schema: { queryType: '__Type', mutationType: '__Type', subscriptionType: '__Type', types: '[__Type!]', directives: '[__Directive!]' },
  __Type: {
    name: 'String', kind: 'String', description: 'String', fields: '[__Field!]', enumValues: '[__EnumValue!]',
    ofType: '__Type', possibleTypes: '[__Type!]',
  },
  __Field: {
    name: 'String!', description: 'String', args: '[__InputValue!]', type: '__Type!', isDeprecated: 'Boolean!',
    deprecationReason: 'String',
  },
  __EnumValue: { name: 'String!', description: 'String', isDeprecated: 'Boolean!', deprecationReason: 'String' },
  __InputValue: { name: 'String!', description: 'String', type: '__Type!', defaultValue: 'String' },
  __Directive: { name: 'String!', description: 'String', locations: '[String!]', args: '[__InputValue!]' },
};

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type TokenKind = 'Name' | 'Int' | 'Float' | 'String' | 'Punct' | 'EOF';

interface Token {
  kind: TokenKind;
  value: string;
  line: number;
  column: number;
}

function isNameStart(ch: string): boolean {
  return ch === '_' || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

function isNameChar(ch: string): boolean {
  return isNameStart(ch) || (ch >= '0' && ch <= '9');
}

function isDigit(ch: string): boolean {
  return ch >= '0' && ch <= '9';
}

/** Split a document into tokens; throws on an illegal character or unterminated string. */
function lex(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  let column = 1;
  const advance = (count = 1): void => {
    for (let n = 0; n < count; n += 1) {
      if (source[i] === '\n') {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
      i += 1;
    }
  };
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === ',') {
      advance();
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') advance();
      continue;
    }
    if (ch === '"') {
      const startLine = line;
      const startColumn = column;
      if (source.startsWith('"""', i)) {
        advance(3);
        let value = '';
        for (;;) {
          if (i >= source.length) throw new Error(`Unterminated block string at ${startLine}:${startColumn}`);
          if (source.startsWith('"""', i)) {
            advance(3);
            break;
          }
          value += source[i] as string;
          advance();
        }
        // A block string's first line break is ignored; dedenting is skipped (documents here do not use it).
        if (value.startsWith('\n')) value = value.slice(1);
        tokens.push({ kind: 'String', value, line: startLine, column: startColumn });
        continue;
      }
      advance();
      let value = '';
      for (;;) {
        if (i >= source.length) throw new Error(`Unterminated string at ${startLine}:${startColumn}`);
        const c = source[i] as string;
        if (c === '"') {
          advance();
          break;
        }
        if (c === '\n') throw new Error(`Unterminated string at ${startLine}:${startColumn}`);
        if (c === '\\') {
          advance();
          const esc = source[i] as string;
          if (esc === 'u') {
            const hex = source.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`Bad unicode escape at ${line}:${column}`);
            value += String.fromCharCode(Number.parseInt(hex, 16));
            advance(5);
          } else {
            const map: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
            const replacement = map[esc];
            if (replacement === undefined) throw new Error(`Bad escape "\\${esc}" at ${line}:${column}`);
            value += replacement;
            advance();
          }
          continue;
        }
        value += c;
        advance();
      }
      tokens.push({ kind: 'String', value, line: startLine, column: startColumn });
      continue;
    }
    if (isDigit(ch) || (ch === '-' && isDigit(source[i + 1] ?? ''))) {
      const startLine = line;
      const startColumn = column;
      let text = '';
      if (ch === '-') {
        text += '-';
        advance();
      }
      while (i < source.length && isDigit(source[i] as string)) {
        text += source[i] as string;
        advance();
      }
      let isFloat = false;
      if (source[i] === '.' && isDigit(source[i + 1] ?? '')) {
        isFloat = true;
        text += '.';
        advance();
        while (i < source.length && isDigit(source[i] as string)) {
          text += source[i] as string;
          advance();
        }
      }
      if (source[i] === 'e' || source[i] === 'E') {
        isFloat = true;
        text += source[i] as string;
        advance();
        if (source[i] === '+' || source[i] === '-') {
          text += source[i] as string;
          advance();
        }
        while (i < source.length && isDigit(source[i] as string)) {
          text += source[i] as string;
          advance();
        }
      }
      tokens.push({ kind: isFloat ? 'Float' : 'Int', value: text, line: startLine, column: startColumn });
      continue;
    }
    if (isNameStart(ch)) {
      const startLine = line;
      const startColumn = column;
      let text = '';
      while (i < source.length && isNameChar(source[i] as string)) {
        text += source[i] as string;
        advance();
      }
      tokens.push({ kind: 'Name', value: text, line: startLine, column: startColumn });
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push({ kind: 'Punct', value: '...', line, column });
      advance(3);
      continue;
    }
    if ('!$&():=@[]{}|'.includes(ch)) {
      tokens.push({ kind: 'Punct', value: ch, line, column });
      advance();
      continue;
    }
    throw new Error(`Unexpected character "${ch}" at ${line}:${column}`);
  }
  tokens.push({ kind: 'EOF', value: '', line, column });
  return tokens;
}

// ---------------------------------------------------------------------------
// Parser: document -> AST
// ---------------------------------------------------------------------------

type ValueNode =
  | { kind: 'Variable'; name: string }
  | { kind: 'IntValue'; value: number }
  | { kind: 'FloatValue'; value: number }
  | { kind: 'StringValue'; value: string }
  | { kind: 'BooleanValue'; value: boolean }
  | { kind: 'NullValue' }
  | { kind: 'EnumValue'; value: string }
  | { kind: 'ListValue'; values: ValueNode[] }
  | { kind: 'ObjectValue'; fields: { name: string; value: ValueNode }[] };

interface ArgumentNode {
  name: string;
  value: ValueNode;
}

interface DirectiveNode {
  name: string;
  args: ArgumentNode[];
}

interface FieldNode {
  kind: 'Field';
  alias: string | null;
  name: string;
  args: ArgumentNode[];
  directives: DirectiveNode[];
  selectionSet: SelectionNode[] | null;
}

interface FragmentSpreadNode {
  kind: 'FragmentSpread';
  name: string;
  directives: DirectiveNode[];
}

interface InlineFragmentNode {
  kind: 'InlineFragment';
  typeCondition: string | null;
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

type SelectionNode = FieldNode | FragmentSpreadNode | InlineFragmentNode;

type TypeNode = { kind: 'Named'; name: string } | { kind: 'List'; ofType: TypeNode } | { kind: 'NonNull'; ofType: TypeNode };

interface VariableDefinitionNode {
  name: string;
  type: TypeNode;
  defaultValue: ValueNode | null;
}

interface OperationNode {
  kind: 'Operation';
  operation: 'query' | 'mutation' | 'subscription';
  name: string | null;
  variableDefinitions: VariableDefinitionNode[];
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

interface FragmentNode {
  kind: 'Fragment';
  name: string;
  typeCondition: string;
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

interface DocumentNode {
  operations: OperationNode[];
  fragments: Map<string, FragmentNode>;
}

class Parser {
  private readonly tokens: Token[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = lex(source);
  }

  private peek(): Token {
    return this.tokens[this.pos] as Token;
  }

  private next(): Token {
    const token = this.tokens[this.pos] as Token;
    if (this.pos < this.tokens.length - 1) this.pos += 1;
    return token;
  }

  private atPunct(value: string): boolean {
    const token = this.peek();
    return token.kind === 'Punct' && token.value === value;
  }

  private atName(value: string): boolean {
    const token = this.peek();
    return token.kind === 'Name' && token.value === value;
  }

  private expectPunct(value: string): Token {
    const token = this.next();
    if (token.kind !== 'Punct' || token.value !== value) {
      throw new Error(`Expected "${value}" but found ${describeToken(token)} at ${token.line}:${token.column}`);
    }
    return token;
  }

  private expectName(what = 'a name'): Token {
    const token = this.next();
    if (token.kind !== 'Name') {
      throw new Error(`Expected ${what} but found ${describeToken(token)} at ${token.line}:${token.column}`);
    }
    return token;
  }

  private skipPunct(value: string): boolean {
    if (this.atPunct(value)) {
      this.next();
      return true;
    }
    return false;
  }

  parseDocument(): DocumentNode {
    const operations: OperationNode[] = [];
    const fragments = new Map<string, FragmentNode>();
    while (this.peek().kind !== 'EOF') {
      if (this.atPunct('{')) {
        operations.push({
          kind: 'Operation', operation: 'query', name: null, variableDefinitions: [], directives: [],
          selectionSet: this.parseSelectionSet(),
        });
        continue;
      }
      const keyword = this.expectName('an operation or fragment definition');
      if (keyword.value === 'fragment') {
        const fragment = this.parseFragment();
        fragments.set(fragment.name, fragment);
      } else if (keyword.value === 'query' || keyword.value === 'mutation' || keyword.value === 'subscription') {
        operations.push(this.parseOperation(keyword.value));
      } else {
        throw new Error(`Unexpected definition "${keyword.value}" at ${keyword.line}:${keyword.column}`);
      }
    }
    if (operations.length === 0) throw new Error('The document holds no operation');
    return { operations, fragments };
  }

  private parseOperation(operation: 'query' | 'mutation' | 'subscription'): OperationNode {
    let name: string | null = null;
    if (this.peek().kind === 'Name') name = this.next().value;
    const variableDefinitions = this.parseVariableDefinitions();
    const directives = this.parseDirectives();
    const selectionSet = this.parseSelectionSet();
    return { kind: 'Operation', operation, name, variableDefinitions, directives, selectionSet };
  }

  private parseFragment(): FragmentNode {
    const name = this.expectName('a fragment name').value;
    if (name === 'on') throw new Error('A fragment cannot be named "on"');
    const on = this.expectName('"on"');
    if (on.value !== 'on') throw new Error(`Expected "on" but found "${on.value}" at ${on.line}:${on.column}`);
    const typeCondition = this.expectName('a type condition').value;
    const directives = this.parseDirectives();
    const selectionSet = this.parseSelectionSet();
    return { kind: 'Fragment', name, typeCondition, directives, selectionSet };
  }

  private parseVariableDefinitions(): VariableDefinitionNode[] {
    if (!this.atPunct('(')) return [];
    this.next();
    const definitions: VariableDefinitionNode[] = [];
    while (!this.atPunct(')')) {
      this.expectPunct('$');
      const name = this.expectName('a variable name').value;
      this.expectPunct(':');
      const type = this.parseType();
      let defaultValue: ValueNode | null = null;
      if (this.skipPunct('=')) defaultValue = this.parseValue();
      definitions.push({ name, type, defaultValue });
    }
    this.expectPunct(')');
    return definitions;
  }

  private parseType(): TypeNode {
    let type: TypeNode;
    if (this.atPunct('[')) {
      this.next();
      const inner = this.parseType();
      this.expectPunct(']');
      type = { kind: 'List', ofType: inner };
    } else {
      type = { kind: 'Named', name: this.expectName('a type name').value };
    }
    if (this.skipPunct('!')) type = { kind: 'NonNull', ofType: type };
    return type;
  }

  private parseSelectionSet(): SelectionNode[] {
    this.expectPunct('{');
    const selections: SelectionNode[] = [];
    while (!this.atPunct('}')) {
      if (this.peek().kind === 'EOF') throw new Error('Unterminated selection set');
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): SelectionNode {
    if (this.atPunct('...')) {
      this.next();
      if (this.peek().kind === 'Name' && this.peek().value !== 'on') {
        const name = this.next().value;
        return { kind: 'FragmentSpread', name, directives: this.parseDirectives() };
      }
      let typeCondition: string | null = null;
      if (this.atName('on')) {
        this.next();
        typeCondition = this.expectName('a type condition').value;
      }
      const directives = this.parseDirectives();
      const selectionSet = this.parseSelectionSet();
      return { kind: 'InlineFragment', typeCondition, directives, selectionSet };
    }
    const first = this.expectName('a field name');
    let alias: string | null = null;
    let name = first.value;
    if (this.skipPunct(':')) {
      alias = name;
      name = this.expectName('a field name').value;
    }
    const args = this.parseArguments();
    const directives = this.parseDirectives();
    const selectionSet = this.atPunct('{') ? this.parseSelectionSet() : null;
    return { kind: 'Field', alias, name, args, directives, selectionSet };
  }

  private parseArguments(): ArgumentNode[] {
    if (!this.atPunct('(')) return [];
    this.next();
    const args: ArgumentNode[] = [];
    while (!this.atPunct(')')) {
      const name = this.expectName('an argument name').value;
      this.expectPunct(':');
      args.push({ name, value: this.parseValue() });
    }
    this.expectPunct(')');
    return args;
  }

  private parseDirectives(): DirectiveNode[] {
    const directives: DirectiveNode[] = [];
    while (this.atPunct('@')) {
      this.next();
      const name = this.expectName('a directive name').value;
      directives.push({ name, args: this.parseArguments() });
    }
    return directives;
  }

  private parseValue(): ValueNode {
    const token = this.next();
    if (token.kind === 'Punct' && token.value === '$') {
      return { kind: 'Variable', name: this.expectName('a variable name').value };
    }
    if (token.kind === 'Punct' && token.value === '[') {
      const values: ValueNode[] = [];
      while (!this.atPunct(']')) {
        if (this.peek().kind === 'EOF') throw new Error('Unterminated list value');
        values.push(this.parseValue());
      }
      this.expectPunct(']');
      return { kind: 'ListValue', values };
    }
    if (token.kind === 'Punct' && token.value === '{') {
      const fields: { name: string; value: ValueNode }[] = [];
      while (!this.atPunct('}')) {
        if (this.peek().kind === 'EOF') throw new Error('Unterminated object value');
        const name = this.expectName('an object field name').value;
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'ObjectValue', fields };
    }
    if (token.kind === 'Int') return { kind: 'IntValue', value: Number.parseInt(token.value, 10) };
    if (token.kind === 'Float') return { kind: 'FloatValue', value: Number.parseFloat(token.value) };
    if (token.kind === 'String') return { kind: 'StringValue', value: token.value };
    if (token.kind === 'Name') {
      if (token.value === 'true') return { kind: 'BooleanValue', value: true };
      if (token.value === 'false') return { kind: 'BooleanValue', value: false };
      if (token.value === 'null') return { kind: 'NullValue' };
      return { kind: 'EnumValue', value: token.value };
    }
    throw new Error(`Unexpected ${describeToken(token)} at ${token.line}:${token.column} where a value was expected`);
  }
}

function describeToken(token: Token): string {
  if (token.kind === 'EOF') return 'the end of the document';
  return `"${token.value}"`;
}

/** Parse one operation document; throws with a human-readable message on bad syntax. */
function parseDocument(source: string): DocumentNode {
  return new Parser(source).parseDocument();
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

interface ExecContext {
  forge: Forge;
  errors: GraphQLError[];
  fragments: Map<string, FragmentNode>;
  variables: Record<string, unknown>;
}

/** Evaluate a value node against the operation's variables. */
function valueFromAST(node: ValueNode, variables: Record<string, unknown>): unknown {
  switch (node.kind) {
    case 'Variable':
      return variables[node.name];
    case 'IntValue':
    case 'FloatValue':
    case 'StringValue':
    case 'BooleanValue':
      return node.value;
    case 'NullValue':
      return null;
    case 'EnumValue':
      return node.value;
    case 'ListValue':
      return node.values.map((child) => valueFromAST(child, variables));
    case 'ObjectValue': {
      const out: Record<string, unknown> = {};
      for (const field of node.fields) out[field.name] = valueFromAST(field.value, variables);
      return out;
    }
  }
}

function isNonNullType(type: TypeNode): boolean {
  return type.kind === 'NonNull';
}

/** Whether a field or fragment's @skip/@include directives let it run. */
function directivesAllow(directives: DirectiveNode[], ctx: ExecContext): boolean {
  for (const directive of directives) {
    const ifArg = directive.args.find((arg) => arg.name === 'if');
    if (ifArg === undefined) continue;
    const value = valueFromAST(ifArg.value, ctx.variables);
    if (directive.name === 'skip' && value === true) return false;
    if (directive.name === 'include' && value !== true) return false;
  }
  return true;
}

/** Whether a fragment's type condition covers a value of `parentType`. */
function fragmentApplies(condition: string, parentType: string): boolean {
  if (condition === parentType) return true;
  if (condition === 'Node') return NODE_TYPES.has(parentType);
  if (condition === 'GitObject') return parentType === 'Commit' || parentType === 'Tree' || parentType === 'Blob';
  if (condition === 'SearchResultItem') {
    return parentType === 'Issue' || parentType === 'PullRequest' || parentType === 'Repository' || parentType === 'User';
  }
  return false;
}

function fieldExists(parentType: string, field: string): boolean {
  const fields = SCHEMA_FIELDS[parentType];
  return fields !== undefined && fields.includes(field);
}

function buildArgs(args: ArgumentNode[], ctx: ExecContext): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of args) out[arg.name] = valueFromAST(arg.value, ctx.variables);
  return out;
}

/**
 * Execute one operation document. Returns the {data, errors?} envelope; a missing operation
 * name or an unprovided required variable is a GraphQL error with data null, not a throw.
 */
function executeDocument(
  doc: DocumentNode,
  variables: Record<string, unknown>,
  operationName: string | undefined,
  forge: Forge,
): { data: unknown; errors?: GraphQLError[] } {
  let operation: OperationNode | undefined;
  if (operationName !== undefined) {
    operation = doc.operations.find((candidate) => candidate.name === operationName);
    if (operation === undefined) {
      return { data: null, errors: [{ message: `Unknown operation named "${operationName}".` }] };
    }
  } else if (doc.operations.length === 1) {
    operation = doc.operations[0] as OperationNode;
  } else {
    return {
      data: null,
      errors: [{ message: 'Must provide operation name if query contains multiple operations.' }],
    };
  }
  if (operation.operation === 'subscription') {
    return { data: null, errors: [{ message: 'Subscriptions are not supported.' }] };
  }
  const ctx: ExecContext = { forge, errors: [], fragments: doc.fragments, variables: {} };
  for (const definition of operation.variableDefinitions) {
    const provided = Object.prototype.hasOwnProperty.call(variables, definition.name)
      ? variables[definition.name]
      : undefined;
    if (provided !== undefined) {
      ctx.variables[definition.name] = provided;
    } else if (definition.defaultValue !== null) {
      ctx.variables[definition.name] = valueFromAST(definition.defaultValue, variables);
    } else if (isNonNullType(definition.type)) {
      return {
        data: null,
        errors: [{ message: `Variable $${definition.name} of required type ${typeNameOf(definition.type)} was not provided.` }],
      };
    }
  }
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const root: Parent = { __typename: rootType };
  const data = executeSelectionSet(operation.selectionSet, root, rootType, [], ctx);
  return ctx.errors.length > 0 ? { data, errors: ctx.errors } : { data };
}

function typeNameOf(type: TypeNode): string {
  if (type.kind === 'Named') return type.name;
  if (type.kind === 'List') return `[${typeNameOf(type.ofType)}]`;
  return `${typeNameOf(type.ofType)}!`;
}

/** Resolve one selection set against a parent value of `parentType`. */
function executeSelectionSet(
  selections: SelectionNode[],
  parent: Parent,
  parentType: string,
  path: (string | number)[],
  ctx: ExecContext,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'Field') {
      if (!directivesAllow(selection.directives, ctx)) continue;
      const responseKey = selection.alias ?? selection.name;
      const fieldPath = [...path, responseKey];
      if (selection.name === '__typename') {
        out[responseKey] = parentType;
        continue;
      }
      if (!fieldExists(parentType, selection.name)) {
        ctx.errors.push({
          message: `Cannot query field "${selection.name}" on type "${parentType}".`,
          path: fieldPath,
        });
        continue;
      }
      const args = buildArgs(selection.args, ctx);
      let value: unknown;
      try {
        value = resolveField(parentType, selection.name, parent, args, ctx);
      } catch (err) {
        ctx.errors.push({ message: err instanceof Error ? err.message : String(err), path: fieldPath });
        out[responseKey] = null;
        continue;
      }
      out[responseKey] = completeValue(selection, value, fieldPath, ctx);
    } else if (selection.kind === 'FragmentSpread') {
      if (!directivesAllow(selection.directives, ctx)) continue;
      const fragment = ctx.fragments.get(selection.name);
      if (fragment === undefined) {
        ctx.errors.push({ message: `Unknown fragment "${selection.name}".`, path });
        continue;
      }
      if (!fragmentApplies(fragment.typeCondition, parentType)) continue;
      Object.assign(out, executeSelectionSet(fragment.selectionSet, parent, parentType, path, ctx));
    } else {
      if (!directivesAllow(selection.directives, ctx)) continue;
      if (selection.typeCondition !== null && !fragmentApplies(selection.typeCondition, parentType)) continue;
      Object.assign(out, executeSelectionSet(selection.selectionSet, parent, parentType, path, ctx));
    }
  }
  return out;
}

/** Finish a resolved field value: run sub-selections over objects and lists of objects. */
function completeValue(field: FieldNode, value: unknown, path: (string | number)[], ctx: ExecContext): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    return value.map((item, index) => completeValue(field, item, [...path, index], ctx));
  }
  if (isRecord(value) && typeof value.__typename === 'string') {
    const parent = value as Parent;
    if (field.selectionSet === null) {
      ctx.errors.push({
        message: `Field "${field.name}" of type "${parent.__typename}" must have a selection of subfields.`,
        path,
      });
      return null;
    }
    return executeSelectionSet(field.selectionSet, parent, parent.__typename, path, ctx);
  }
  if (field.selectionSet !== null) {
    ctx.errors.push({
      message: `Field "${field.name}" must not have a selection since type "${typeof value}" has no subfields.`,
      path,
    });
  }
  return value;
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/**
 * A Relay connection over `items`: `first`/`after` slice them, cursors name offsets, and
 * pageInfo reports whether more remain. Without `first` the whole remainder is returned.
 */
function connection<T>(
  typename: string,
  edgeTypename: string,
  items: readonly T[],
  args: Record<string, unknown>,
  toNode: (item: T) => unknown,
): Parent {
  const afterIndex = decodeCursor(args.after);
  const start = afterIndex === null ? 0 : afterIndex + 1;
  const first = typeof args.first === 'number' && Number.isFinite(args.first) ? Math.max(0, Math.trunc(args.first)) : items.length;
  const sliced = items.slice(start, start + first);
  const edges: Parent[] = sliced.map((item, index) => ({
    __typename: edgeTypename,
    node: toNode(item),
    cursor: encodeCursor(start + index),
  }));
  const end = start + sliced.length;
  const firstEdge = edges[0];
  const lastEdge = edges[edges.length - 1];
  const pageInfo: Parent = {
    __typename: 'PageInfo',
    hasNextPage: end < items.length,
    hasPreviousPage: start > 0,
    startCursor: firstEdge !== undefined ? (firstEdge.cursor as string) : null,
    endCursor: lastEdge !== undefined ? (lastEdge.cursor as string) : null,
  };
  return {
    __typename: typename,
    nodes: sliced.map(toNode),
    edges,
    pageInfo,
    totalCount: items.length,
  };
}

/** Issues ordered per orderBy (default: creation order); CREATED_AT DESC breaks ties by number. */
function orderedIssues(issues: Issue[], args: Record<string, unknown>): Issue[] {
  const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
  if (orderBy === null) return [...issues].sort((a, b) => a.number - b.number);
  const field = typeof orderBy.field === 'string' ? orderBy.field : 'CREATED_AT';
  const direction = orderBy.direction === 'ASC' ? 1 : -1;
  const keyOf = (issue: Issue): number | string => {
    if (field === 'UPDATED_AT') return issue.updatedAt;
    if (field === 'COMMENTS') return issue.comments.size;
    return issue.createdAt;
  };
  return [...issues].sort((a, b) => {
    const ka = keyOf(a);
    const kb = keyOf(b);
    const cmp = ka < kb ? -1 : ka > kb ? 1 : 0;
    if (cmp !== 0) return cmp * direction;
    return (a.number - b.number) * direction;
  });
}

/** Issues filtered by states and labels arguments. */
function filteredIssues(repo: RepoRecord, args: Record<string, unknown>): Issue[] {
  let issues = forgeListIssues(repo, args);
  if (Array.isArray(args.states) && args.states.length > 0) {
    const wanted = new Set(args.states.map((state) => String(state)));
    issues = issues.filter((issue) => wanted.has(issue.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  if (Array.isArray(args.labels) && args.labels.length > 0) {
    const wanted = args.labels.map((label) => String(label));
    issues = issues.filter((issue) => wanted.every((label) => issue.labels.includes(label)));
  }
  return orderedIssues(issues, args);
}

function forgeListIssues(repo: RepoRecord, _args: Record<string, unknown>): Issue[] {
  // The store's listIssues takes a state filter; the GraphQL states argument is handled above,
  // so read every issue here.
  return [...repo.issues.values()].sort((a, b) => a.number - b.number);
}

/** Pull requests filtered by a states argument (OPEN / CLOSED / MERGED). */
function filteredPulls(repo: RepoRecord, args: Record<string, unknown>): PullRequest[] {
  const pulls = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
  if (!Array.isArray(args.states) || args.states.length === 0) return pulls;
  const wanted = new Set(args.states.map((state) => String(state)));
  return pulls.filter((pull) => {
    const state = pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
    return wanted.has(state);
  });
}

// ---------------------------------------------------------------------------
// Git objects
// ---------------------------------------------------------------------------

/** The short name of a ref: "refs/heads/main" -> "main". */
function shortRefName(fullName: string): string {
  if (fullName.startsWith('refs/heads/')) return fullName.slice('refs/heads/'.length);
  if (fullName.startsWith('refs/tags/')) return fullName.slice('refs/tags/'.length);
  return fullName;
}

/** A git object as its GraphQL node (tag objects resolve through to their target). */
function gitObjectParent(forge: Forge, repo: RepoRecord, sha: string, type: string): Parent | null {
  if (type === 'commit') return commitParent(repo, sha);
  if (type === 'tree') return treeParent(repo, sha);
  if (type === 'blob') {
    const obj = forge.getObject(repo, sha);
    return obj === undefined ? null : blobParent(repo, sha, obj.data);
  }
  if (type === 'tag') {
    const obj = forge.getObject(repo, sha);
    if (obj === undefined) return null;
    const info = parseTag(obj.data);
    if (info === null) return null;
    const target = forge.resolveObjectSha(repo, info.object) ?? info.object;
    return gitObjectParent(forge, repo, target, info.type);
  }
  return null;
}

/**
 * Resolve a repository.object(expression): "main", "HEAD", "<sha>", "main:path/to/file".
 * A bare ref yields its commit; a path walks the commit's tree to a blob or subtree.
 */
function resolveGitObject(forge: Forge, repo: RepoRecord, expression: string): Parent | null {
  const colon = expression.indexOf(':');
  const refPart = colon >= 0 ? expression.slice(0, colon) : expression;
  const pathPart = colon >= 0 ? expression.slice(colon + 1) : null;
  const sha = refPart === '' ? forge.resolveRef(repo, 'HEAD') : forge.resolveRef(repo, refPart);
  if (sha === null) return null;
  const obj = forge.getObject(repo, sha);
  if (obj === undefined) return null;
  if (pathPart === null || pathPart === '') return gitObjectParent(forge, repo, sha, obj.type);
  let target: Parent | null = gitObjectParent(forge, repo, sha, obj.type);
  if (target === null || target.__typename !== 'Commit') return null;
  const info = parseCommit(obj.data);
  if (info === null) return null;
  let treeSha = info.tree;
  const parts = pathPart.split('/').filter((part) => part !== '');
  for (let i = 0; i < parts.length; i += 1) {
    const treeObj = forge.getObject(repo, treeSha);
    if (treeObj === undefined || treeObj.type !== 'tree') return null;
    const entries = parseTree(treeObj.data);
    if (entries === null) return null;
    const entry = entries.find((candidate) => candidate.name === parts[i]);
    if (entry === undefined) return null;
    if (i === parts.length - 1) {
      if (entry.type === 'blob') {
        const blob = forge.getObject(repo, entry.sha);
        return blob === undefined ? null : blobParent(repo, entry.sha, blob.data);
      }
      if (entry.type === 'tree') return treeParent(repo, entry.sha);
      return commitParent(repo, entry.sha);
    }
    if (entry.type !== 'tree') return null;
    treeSha = entry.sha;
  }
  return treeParent(repo, treeSha);
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/** Query.search: substring match over repositories, issues or users, as a connection. */
function doSearch(forge: Forge, args: Record<string, unknown>): Parent {
  const type = typeof args.type === 'string' ? args.type : 'ISSUE';
  const rawQuery = typeof args.query === 'string' ? args.query : '';
  const terms = rawQuery
    .split(/\s+/)
    .map((term) => term.trim())
    .filter((term) => term !== '' && !term.includes(':'))
    .map((term) => term.toLowerCase());
  const match = (haystack: string): boolean => {
    if (terms.length === 0) return true;
    const hay = haystack.toLowerCase();
    return terms.every((term) => hay.includes(term));
  };
  const repos = forge.listRepos().filter((repo) => match(`${repo.fullName} ${repo.description}`));
  const issues: { repo: RepoRecord; issue: Issue }[] = [];
  for (const repo of forge.listRepos()) {
    for (const issue of forge.listIssues(repo)) {
      if (match(`${issue.title} ${issue.body}`)) issues.push({ repo, issue });
    }
  }
  const users = [...forge.users.values()].filter((user) => match(`${user.login} ${user.name}`));
  let items: Parent[];
  if (type === 'REPOSITORY') items = repos.map((repo) => repoParent(repo));
  else if (type === 'USER') items = users.map((user) => userParent(user));
  else items = issues.map(({ repo, issue }) => issueParent(repo, issue));
  const conn = connection('SearchResultItemConnection', 'SearchResultItemEdge', items, args, (node) => node);
  return { ...conn, issueCount: issues.length, repositoryCount: repos.length };
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

function repoFromGid(forge: Forge, id: unknown): RepoRecord | null {
  if (typeof id !== 'string') return null;
  const parsed = parseGid(id);
  if (parsed === null || parsed.type !== 'Repository') return null;
  return findRepoById(forge, Number(parsed.key)) ?? null;
}

function issueFromGid(forge: Forge, id: unknown): { repo: RepoRecord; issue: Issue } {
  if (typeof id !== 'string') throw new Error(`Could not resolve to an Issue with the id of "${String(id)}".`);
  const parsed = parseGid(id);
  if (parsed === null || parsed.type !== 'Issue') throw new Error(`Could not resolve to an Issue with the id of "${id}".`);
  const [repoText, numberText] = splitOnce(parsed.key);
  const repo = findRepoById(forge, Number(repoText));
  const issue = repo === undefined ? undefined : forge.getIssue(repo, Number(numberText));
  if (repo === undefined || issue === undefined) throw new Error(`Could not resolve to an Issue with the id of "${id}".`);
  return { repo, issue };
}

function pullFromGid(forge: Forge, id: unknown): { repo: RepoRecord; pull: PullRequest } {
  if (typeof id !== 'string') throw new Error(`Could not resolve to a PullRequest with the id of "${String(id)}".`);
  const parsed = parseGid(id);
  if (parsed === null || parsed.type !== 'PullRequest') {
    throw new Error(`Could not resolve to a PullRequest with the id of "${id}".`);
  }
  const [repoText, numberText] = splitOnce(parsed.key);
  const repo = findRepoById(forge, Number(repoText));
  const pull = repo === undefined ? undefined : forge.getPull(repo, Number(numberText));
  if (repo === undefined || pull === undefined) throw new Error(`Could not resolve to a PullRequest with the id of "${id}".`);
  return { repo, pull };
}

function resolveMutation(field: string, args: Record<string, unknown>, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  const input = isRecord(args.input) ? args.input : {};
  const clientMutationId = typeof input.clientMutationId === 'string' ? input.clientMutationId : null;
  switch (field) {
    case 'createIssue': {
      const repo = repoFromGid(forge, input.repositoryId);
      if (repo === null) throw new Error(`Could not resolve to a Repository with the id of "${String(input.repositoryId)}".`);
      const title = typeof input.title === 'string' ? input.title : '';
      const body = typeof input.body === 'string' ? input.body : '';
      const labelNames: string[] = [];
      if (Array.isArray(input.labelIds)) {
        for (const labelId of input.labelIds) {
          if (typeof labelId !== 'string') continue;
          const parsed = parseGid(labelId);
          if (parsed !== null && parsed.type === 'Label') {
            const [, name] = splitOnce(parsed.key);
            if (name !== '') labelNames.push(name);
          }
        }
      }
      const issue = forge.createIssue(repo, title, body, labelNames, forge.viewer);
      return { __typename: 'CreateIssuePayload', issue: issueParent(repo, issue), clientMutationId };
    }
    case 'closeIssue': {
      const { repo, issue } = issueFromGid(forge, input.issueId);
      issue.state = 'closed';
      issue.closedAt = isoNow();
      issue.updatedAt = isoNow();
      return { __typename: 'CloseIssuePayload', issue: issueParent(repo, issue), clientMutationId };
    }
    case 'createPullRequest': {
      const repo = repoFromGid(forge, input.repositoryId);
      if (repo === null) throw new Error(`Could not resolve to a Repository with the id of "${String(input.repositoryId)}".`);
      const title = typeof input.title === 'string' ? input.title : '';
      const body = typeof input.body === 'string' ? input.body : '';
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const pull = forge.createPull(repo, title, body, head, base, forge.viewer);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullParent(repo, pull), clientMutationId };
    }
    case 'mergePullRequest': {
      const { repo, pull } = pullFromGid(forge, input.pullRequestId);
      const sha = forge.mergePull(repo, pull, forge.viewer);
      if (sha === null) throw new Error('Pull request is not mergeable.');
      return { __typename: 'MergePullRequestPayload', pullRequest: pullParent(repo, pull), clientMutationId };
    }
    case 'addComment': {
      const body = typeof input.body === 'string' ? input.body : '';
      const parsed = typeof input.subjectId === 'string' ? parseGid(input.subjectId) : null;
      if (parsed !== null && parsed.type === 'Issue') {
        const { repo, issue } = issueFromGid(forge, input.subjectId);
        const comment = forge.createComment(repo, issue, body, forge.viewer);
        return {
          __typename: 'AddCommentPayload',
          commentEdge: { __typename: 'IssueCommentEdge', node: commentParent(repo, issue, comment), cursor: encodeCursor(0) },
          clientMutationId,
        };
      }
      throw new Error(`Could not resolve to an Issue with the id of "${String(input.subjectId)}".`);
    }
    default:
      throw new Error(`Unknown mutation "${field}".`);
  }
}

// ---------------------------------------------------------------------------
// Introspection parents
// ---------------------------------------------------------------------------

/** An __Type parent for a named schema type, or null when the schema has no such type. */
function typeParent(name: string): Parent | null {
  if (!allTypeNames().includes(name)) return null;
  return { __typename: '__Type', typeName: name, kind: typeKind(name), ofType: null };
}

function fieldParent(typeName: string, fieldName: string): Parent {
  return {
    __typename: '__Field',
    typeName,
    fieldName,
    typeSpec: FIELD_SPECS[typeName]?.[fieldName] ?? 'String',
  };
}

function enumValueParent(name: string): Parent {
  return { __typename: '__EnumValue', name };
}

/** Expand a "String!", "[Issue!]!" shorthand into nested __Type parents. */
function typeRefParent(spec: string): Parent {
  if (spec.endsWith('!')) {
    return { __typename: '__Type', typeName: null, kind: 'NON_NULL', ofType: typeRefParent(spec.slice(0, -1)) };
  }
  if (spec.startsWith('[') && spec.endsWith(']')) {
    return { __typename: '__Type', typeName: null, kind: 'LIST', ofType: typeRefParent(spec.slice(1, -1)) };
  }
  return { __typename: '__Type', typeName: spec, kind: typeKind(spec), ofType: null };
}

// ---------------------------------------------------------------------------
// Field resolution
// ---------------------------------------------------------------------------

function resolveQuery(field: string, args: Record<string, unknown>, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  switch (field) {
    case 'viewer':
      return userParent(forge.viewer);
    case 'repository': {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const name = typeof args.name === 'string' ? args.name : '';
      const repo = forge.getRepo(owner, name);
      return repo === undefined ? null : repoParent(repo);
    }
    case 'node': {
      if (typeof args.id !== 'string') return null;
      return resolveNode(forge, args.id);
    }
    case 'nodes': {
      if (!Array.isArray(args.ids)) return [];
      return args.ids.map((id) => (typeof id === 'string' ? resolveNode(forge, id) : null));
    }
    case 'search':
      return doSearch(forge, args);
    case '__type': {
      if (typeof args.name !== 'string') return null;
      return typeParent(args.name);
    }
    case '__schema':
      return { __typename: '__Schema' };
    default:
      throw new Error(`Unknown query field "${field}".`);
  }
}

function resolveRepository(field: string, repo: RepoRecord, args: Record<string, unknown>, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  switch (field) {
    case 'id':
      return repoGid(repo);
    case 'databaseId':
      return repo.id;
    case 'name':
      return repo.name;
    case 'nameWithOwner':
      return repo.fullName;
    case 'owner':
      return userForLogin(forge, repo.owner);
    case 'description':
      return repo.description;
    case 'isPrivate':
      return repo.private;
    case 'defaultBranchRef': {
      const sha = repo.refs.get(forge.defaultRef(repo));
      return sha === undefined ? null : refParent(repo, repo.defaultBranch, sha);
    }
    case 'url':
      return `https://github.com/${repo.fullName}`;
    case 'createdAt':
      return repo.createdAt;
    case 'updatedAt':
      return repo.updatedAt;
    case 'viewerPermission':
      return 'ADMIN';
    case 'hasIssuesEnabled':
      return true;
    case 'issue': {
      if (typeof args.number !== 'number') return null;
      const issue = forge.getIssue(repo, args.number);
      return issue === undefined ? null : issueParent(repo, issue);
    }
    case 'issues':
      return connection('IssueConnection', 'IssueEdge', filteredIssues(repo, args), args, (issue) => issueParent(repo, issue));
    case 'pullRequest': {
      if (typeof args.number !== 'number') return null;
      const pull = forge.getPull(repo, args.number);
      return pull === undefined ? null : pullParent(repo, pull);
    }
    case 'pullRequests':
      return connection('PullRequestConnection', 'PullRequestEdge', filteredPulls(repo, args), args, (pull) => pullParent(repo, pull));
    case 'object': {
      if (typeof args.expression !== 'string') return null;
      return resolveGitObject(forge, repo, args.expression);
    }
    case 'ref': {
      if (typeof args.qualifiedName !== 'string') return null;
      const qualified = args.qualifiedName;
      for (const full of [qualified, `refs/heads/${qualified}`, `refs/tags/${qualified}`]) {
        const sha = repo.refs.get(full);
        if (sha !== undefined) return refParent(repo, shortRefName(full), sha);
      }
      return null;
    }
    case 'refs': {
      const prefix = typeof args.refPrefix === 'string' ? args.refPrefix : null;
      const refs = forge.listRefs(repo).filter((ref) => prefix === null || ref.name.startsWith(prefix));
      return connection('RefConnection', 'RefEdge', refs, args, (ref) => refParent(repo, shortRefName(ref.name), ref.sha));
    }
    case 'labels': {
      const labels = [...repo.labels.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      return connection('LabelConnection', 'LabelEdge', labels, args, (label) => labelParent(repo, label));
    }
    default:
      throw new Error(`Unknown Repository field "${field}".`);
  }
}

function resolveIssue(field: string, repo: RepoRecord, issue: Issue, args: Record<string, unknown>): unknown {
  switch (field) {
    case 'id':
      return issueGid(repo, issue);
    case 'number':
      return issue.number;
    case 'title':
      return issue.title;
    case 'body':
      return issue.body;
    case 'state':
      return issue.state === 'open' ? 'OPEN' : 'CLOSED';
    case 'author':
      return userParent(issue.user);
    case 'labels': {
      const labels = issue.labels.map((name) => repo.labels.get(name) ?? { name, color: '', description: '' });
      return connection('LabelConnection', 'LabelEdge', labels, args, (label) => labelParent(repo, label));
    }
    case 'comments': {
      const comments = [...issue.comments.values()].sort((a, b) => a.id - b.id);
      return connection('IssueCommentConnection', 'IssueCommentEdge', comments, args, (comment) => commentParent(repo, issue, comment));
    }
    case 'createdAt':
      return issue.createdAt;
    case 'updatedAt':
      return issue.updatedAt;
    case 'closedAt':
      return issue.closedAt;
    case 'url':
      return `https://github.com/${repo.fullName}/issues/${issue.number}`;
    case 'repository':
      return repoParent(repo);
    default:
      throw new Error(`Unknown Issue field "${field}".`);
  }
}

function resolvePull(field: string, repo: RepoRecord, pull: PullRequest, args: Record<string, unknown>, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  switch (field) {
    case 'id':
      return pullGid(repo, pull);
    case 'number':
      return pull.number;
    case 'title':
      return pull.title;
    case 'body':
      return pull.body;
    case 'state':
      return pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
    case 'author':
      return userParent(pull.user);
    case 'labels':
      return connection('LabelConnection', 'LabelEdge', [], args, (label) => label);
    case 'comments':
      return connection('IssueCommentConnection', 'IssueCommentEdge', [], args, (comment) => comment);
    case 'createdAt':
      return pull.createdAt;
    case 'updatedAt':
      return pull.updatedAt;
    case 'url':
      return `https://github.com/${repo.fullName}/pull/${pull.number}`;
    case 'repository':
      return repoParent(repo);
    case 'headRefName':
      return pull.head;
    case 'baseRefName':
      return pull.base;
    case 'headRefOid':
      return pull.headSha;
    case 'baseRefOid':
      return pull.baseSha;
    case 'headRef': {
      const sha = forge.resolveRef(repo, pull.head);
      return sha === null ? null : refParent(repo, pull.head, sha);
    }
    case 'baseRef': {
      const sha = forge.resolveRef(repo, pull.base);
      return sha === null ? null : refParent(repo, pull.base, sha);
    }
    case 'merged':
      return pull.merged;
    case 'mergeable':
      return pull.mergeable ? 'MERGEABLE' : 'UNKNOWN';
    case 'files': {
      const files = forge.pullFiles(repo, pull);
      return connection('PullRequestChangedFileConnection', 'PullRequestChangedFileEdge', files, args, (file) => ({
        __typename: 'PullRequestChangedFile',
        path: file.filename,
        status: file.status,
        sha: file.sha,
      }));
    }
    default:
      throw new Error(`Unknown PullRequest field "${field}".`);
  }
}

function resolveUser(field: string, user: ScenarioUser): unknown {
  switch (field) {
    case 'id':
      return userGid(user.login);
    case 'login':
      return user.login;
    case 'name':
      return user.name;
    case 'email':
      return user.email;
    case 'url':
      return `https://github.com/${user.login}`;
    default:
      throw new Error(`Unknown User field "${field}".`);
  }
}

function resolveLabel(field: string, repo: RepoRecord, label: Label): unknown {
  switch (field) {
    case 'id':
      return labelGid(repo, label);
    case 'name':
      return label.name;
    case 'color':
      return label.color;
    case 'description':
      return label.description;
    case 'url':
      return `https://github.com/${repo.fullName}/labels/${encodeURIComponent(label.name)}`;
    default:
      throw new Error(`Unknown Label field "${field}".`);
  }
}

function resolveComment(field: string, repo: RepoRecord, issue: Issue, comment: IssueComment): unknown {
  switch (field) {
    case 'id':
      return commentGid(repo, issue, comment);
    case 'body':
      return comment.body;
    case 'author':
      return userParent(comment.user);
    case 'createdAt':
      return comment.createdAt;
    case 'updatedAt':
      return comment.updatedAt;
    case 'url':
      return `https://github.com/${repo.fullName}/issues/${issue.number}#issuecomment-${comment.id}`;
    default:
      throw new Error(`Unknown IssueComment field "${field}".`);
  }
}

function resolveCommit(field: string, repo: RepoRecord, sha: string, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  const obj = forge.getObject(repo, sha);
  const info = obj !== undefined && obj.type === 'commit' ? parseCommit(obj.data) : null;
  switch (field) {
    case 'id':
    case 'oid':
      return sha;
    case 'message':
      return info?.message ?? '';
    case 'messageHeadline':
      return (info?.message ?? '').split('\n')[0] ?? '';
    case 'author':
      return info === null ? null : gitActorParent(info.authorName, info.authorEmail, info.authorTs);
    case 'committer':
      return info === null ? null : gitActorParent(info.committerName, info.committerEmail, info.committerTs);
    case 'tree':
      return info === null ? null : treeParent(repo, info.tree);
    case 'parents':
      return info === null ? [] : info.parents.filter((parent) => forge.hasObject(repo, parent)).map((parent) => commitParent(repo, parent));
    case 'url':
      return `https://github.com/${repo.fullName}/commit/${sha}`;
    default:
      throw new Error(`Unknown Commit field "${field}".`);
  }
}

function resolveTree(field: string, repo: RepoRecord, sha: string, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  switch (field) {
    case 'id':
    case 'oid':
      return sha;
    case 'entries': {
      const obj = forge.getObject(repo, sha);
      if (obj === undefined || obj.type !== 'tree') return [];
      const entries = parseTree(obj.data);
      if (entries === null) return [];
      return entries.map((entry) => ({ __typename: 'TreeEntry', repo, entry }));
    }
    default:
      throw new Error(`Unknown Tree field "${field}".`);
  }
}

function resolveTreeEntry(field: string, repo: RepoRecord, entry: { mode: string; name: string; sha: string; type: string }, ctx: ExecContext): unknown {
  const forge = ctx.forge;
  switch (field) {
    case 'name':
      return entry.name;
    case 'mode':
      return entry.mode;
    case 'type':
      return entry.type;
    case 'oid':
      return entry.sha;
    case 'object': {
      if (entry.type === 'blob') {
        const obj = forge.getObject(repo, entry.sha);
        return obj === undefined ? null : blobParent(repo, entry.sha, obj.data);
      }
      if (entry.type === 'tree') return treeParent(repo, entry.sha);
      return commitParent(repo, entry.sha);
    }
    default:
      throw new Error(`Unknown TreeEntry field "${field}".`);
  }
}

function resolveBlob(field: string, sha: string, data: Buffer): unknown {
  switch (field) {
    case 'id':
    case 'oid':
      return sha;
    case 'text':
      return data.toString('utf8');
    case 'byteSize':
      return data.length;
    case 'isBinary':
      return data.includes(0);
    default:
      throw new Error(`Unknown Blob field "${field}".`);
  }
}

function resolveRef(field: string, repo: RepoRecord, name: string, sha: string, ctx: ExecContext): unknown {
  switch (field) {
    case 'id':
      return refGid(repo, name);
    case 'name':
      return name;
    case 'target': {
      const obj = ctx.forge.getObject(repo, sha);
      return obj === undefined ? null : gitObjectParent(ctx.forge, repo, sha, obj.type);
    }
    default:
      throw new Error(`Unknown Ref field "${field}".`);
  }
}

function resolveGitActor(field: string, parent: Parent, ctx: ExecContext): unknown {
  switch (field) {
    case 'name':
      return parent.name ?? null;
    case 'email':
      return parent.email ?? null;
    case 'date':
      return parent.date ?? null;
    case 'user': {
      const email = typeof parent.email === 'string' ? parent.email : '';
      for (const user of ctx.forge.users.values()) {
        if (user.email === email) return userParent(user);
      }
      return null;
    }
    default:
      throw new Error(`Unknown GitActor field "${field}".`);
  }
}

function resolveIntrospection(field: string, parentType: string, parent: Parent): unknown {
  switch (parentType) {
    case '__Schema':
      switch (field) {
        case 'queryType':
          return typeParent('Query');
        case 'mutationType':
          return typeParent('Mutation');
        case 'subscriptionType':
          return null;
        case 'types':
          return allTypeNames().map((name) => typeParent(name) as Parent);
        case 'directives':
          return [];
        default:
          throw new Error(`Unknown __Schema field "${field}".`);
      }
    case '__Type': {
      const typeName = typeof parent.typeName === 'string' ? parent.typeName : null;
      const kind = typeof parent.kind === 'string' ? parent.kind : 'OBJECT';
      switch (field) {
        case 'name':
          return typeName;
        case 'kind':
          return kind;
        case 'description':
          return null;
        case 'fields':
          if (typeName === null || (kind !== 'OBJECT' && kind !== 'INTERFACE')) return null;
          return (SCHEMA_FIELDS[typeName] ?? []).map((name) => fieldParent(typeName, name));
        case 'enumValues':
          if (typeName === null || kind !== 'ENUM') return null;
          return (ENUM_VALUES[typeName] ?? []).map((name) => enumValueParent(name));
        case 'ofType':
          return (parent.ofType as Parent | null) ?? null;
        case 'possibleTypes':
          return null;
        default:
          throw new Error(`Unknown __Type field "${field}".`);
      }
    }
    case '__Field':
      switch (field) {
        case 'name':
          return parent.fieldName ?? null;
        case 'description':
          return null;
        case 'args':
          return [];
        case 'type':
          return typeRefParent(typeof parent.typeSpec === 'string' ? parent.typeSpec : 'String');
        case 'isDeprecated':
          return false;
        case 'deprecationReason':
          return null;
        default:
          throw new Error(`Unknown __Field field "${field}".`);
      }
    case '__EnumValue':
      switch (field) {
        case 'name':
          return parent.name ?? null;
        case 'description':
          return null;
        case 'isDeprecated':
          return false;
        case 'deprecationReason':
          return null;
        default:
          throw new Error(`Unknown __EnumValue field "${field}".`);
      }
    default:
      throw new Error(`Unknown introspection type "${parentType}".`);
  }
}

/** Dispatch one field on one parent value to its resolver. */
function resolveField(parentType: string, field: string, parent: Parent, args: Record<string, unknown>, ctx: ExecContext): unknown {
  switch (parentType) {
    case 'Query':
      return resolveQuery(field, args, ctx);
    case 'Mutation':
      return resolveMutation(field, args, ctx);
    case 'Repository':
      return resolveRepository(field, parent.repo as RepoRecord, args, ctx);
    case 'Issue':
      return resolveIssue(field, parent.repo as RepoRecord, parent.issue as Issue, args);
    case 'PullRequest':
      return resolvePull(field, parent.repo as RepoRecord, parent.pull as PullRequest, args, ctx);
    case 'User':
      return resolveUser(field, parent.user as ScenarioUser);
    case 'Label':
      return resolveLabel(field, parent.repo as RepoRecord, parent.label as Label);
    case 'IssueComment':
      return resolveComment(field, parent.repo as RepoRecord, parent.issue as Issue, parent.comment as IssueComment);
    case 'Commit':
      return resolveCommit(field, parent.repo as RepoRecord, parent.sha as string, ctx);
    case 'Tree':
      return resolveTree(field, parent.repo as RepoRecord, parent.sha as string, ctx);
    case 'TreeEntry':
      return resolveTreeEntry(
        field,
        parent.repo as RepoRecord,
        parent.entry as { mode: string; name: string; sha: string; type: string },
        ctx,
      );
    case 'Blob':
      return resolveBlob(field, parent.sha as string, parent.data as Buffer);
    case 'Ref':
      return resolveRef(field, parent.repo as RepoRecord, parent.name as string, parent.sha as string, ctx);
    case 'GitActor':
      return resolveGitActor(field, parent, ctx);
    case 'PullRequestChangedFile':
      switch (field) {
        case 'path':
          return parent.path ?? null;
        case 'additions':
          return 0;
        case 'deletions':
          return 0;
        case 'changeType': {
          const status = parent.status as string | undefined;
          if (status === 'added') return 'ADDED';
          if (status === 'removed') return 'REMOVED';
          return 'MODIFIED';
        }
        default:
          throw new Error(`Unknown PullRequestChangedFile field "${field}".`);
      }
    case '__Schema':
    case '__Type':
    case '__Field':
    case '__EnumValue':
    case '__InputValue':
    case '__Directive':
      if (parentType === '__InputValue' || parentType === '__Directive') return null;
      return resolveIntrospection(field, parentType, parent);
    default: {
      if (parentType.endsWith('Connection')) {
        if (field === 'issueCount' || field === 'repositoryCount') return (parent[field] as number | undefined) ?? 0;
        return parent[field] ?? null;
      }
      if (parentType.endsWith('Edge')) return parent[field] ?? null;
      if (parentType.endsWith('Payload')) return parent[field] ?? null;
      if (parentType === 'PageInfo') return parent[field] ?? null;
      throw new Error(`Unknown type "${parentType}".`);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP entry point
// ---------------------------------------------------------------------------

/** Run one operation body ({query, variables, operationName}) to a status and payload. */
function runOperation(entry: unknown, forge: Forge): { status: number; payload: unknown } {
  if (!isRecord(entry) || typeof entry.query !== 'string') {
    return { status: 400, payload: { errors: [{ message: 'A GraphQL operation needs a string "query".' }] } };
  }
  const variables = isRecord(entry.variables) ? (entry.variables as Record<string, unknown>) : {};
  const operationName = typeof entry.operationName === 'string' ? entry.operationName : undefined;
  let doc: DocumentNode;
  try {
    doc = parseDocument(entry.query);
  } catch (err) {
    return { status: 400, payload: { errors: [{ message: err instanceof Error ? err.message : String(err) }] } };
  }
  return { status: 200, payload: executeDocument(doc, variables, operationName, forge) };
}

/**
 * Serve POST /api/graphql. Returns true when the request was ours (handled, even on error),
 * false for any other method or path so the router can fall through.
 */
export async function handleGraphQL(req: IncomingMessage, res: ServerResponse, forge: Forge): Promise<boolean> {
  if ((req.method ?? '').toUpperCase() !== 'POST' || pathOf(req) !== '/api/graphql') return false;
  if (!isAuthorized(req)) {
    sendUnauthorized(res);
    return true;
  }
  let body: unknown;
  try {
    body = await readJsonBody(req);
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Request body is not valid JSON.' }] });
    return true;
  }
  if (Array.isArray(body)) {
    sendJson(res, 200, body.map((entry) => runOperation(entry, forge).payload));
    return true;
  }
  const result = runOperation(body, forge);
  sendJson(res, result.status, result.payload);
  return true;
}

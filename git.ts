// Git smart HTTP, implemented from scratch on node:zlib / node:crypto:
// pkt-lines, packfiles (full objects + ofs/ref deltas), protocol v0 and v2
// upload-pack, v0 receive-pack.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { Store, VIEWER_LOGIN, type Repo } from './store.ts';
import { sendRaw, errMessage, readBody, queryOf, isAuthed } from './util.ts';

const ZERO_OID = '0'.repeat(40);
const AGENT = 'github-core-clone/1.0.0';
const UPLOAD_CAPS = `symref=HEAD:refs/heads/main multi_ack thin-pack side-band-64k side-band ofs-delta shallow agent=${AGENT} object-format=sha1`;
const RECEIVE_CAPS = `report-status delete-refs side-band-64k ofs-delta agent=${AGENT} object-format=sha1`;

// ---------------------------------------------------------------- pkt-lines

function pktLine(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const header = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type Packet = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' };

function decodePktLines(buf: Buffer): Packet[] {
  const out: Packet[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (head === '0000') {
      out.push({ kind: 'flush' });
      off += 4;
      continue;
    }
    if (head === '0001') {
      out.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    const len = parseInt(head, 16);
    if (!Number.isFinite(len) || len < 4 || off + len > buf.length) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    out.push({ kind: 'data', payload: Buffer.from(buf.subarray(off + 4, off + len)) });
    off += len;
  }
  return out;
}

/** Split pack bytes into sideband (band 1) pkt-lines, then a flush. */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const MAX = 65515;
  for (let off = 0; off < pack.length; off += MAX) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + MAX));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (pack.length === 0) parts.push(pktLine(Buffer.from([1])));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- packfiles

const TYPE_NAMES = ['', 'commit', 'tree', 'blob', 'tag', '', 'ofs-delta', 'ref-delta'] as const;
const TYPE_IDS: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

function encodeObjHeader(typeId: number, size: number): Buffer {
  const bytes: number[] = [];
  let b = (typeId << 4) | (size & 0x0f);
  size >>>= 4;
  const first = bytes.length === 0;
  void first;
  if (size > 0) b |= 0x80;
  bytes.push(b);
  while (size > 0) {
    let next = size & 0x7f;
    size >>>= 7;
    if (size > 0) next |= 0x80;
    bytes.push(next);
  }
  return Buffer.from(bytes);
}

export function buildPack(objects: { sha: string; type: string; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK'), Buffer.from([0, 0, 0, 2])];
  const count = Buffer.alloc(4);
  count.writeUInt32BE(objects.length, 0);
  parts.push(count);
  for (const obj of objects) {
    parts.push(encodeObjHeader(TYPE_IDS[obj.type]!, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

function readVarint(buf: Buffer, pos: number): [number, number] {
  let value = buf[pos]!;
  let out = value & 0x7f;
  let shift = 7;
  while (value & 0x80) {
    pos += 1;
    value = buf[pos]!;
    out |= (value & 0x7f) << shift;
    shift += 7;
  }
  return [out, pos + 1];
}

function readOffsetVarint(buf: Buffer, pos: number): [number, number] {
  let value = buf[pos]!;
  let out = value & 0x7f;
  while (value & 0x80) {
    pos += 1;
    value = buf[pos]!;
    out = ((out + 1) << 7) | (value & 0x7f);
  }
  return [out, pos + 1];
}

/** Inflate the deflate stream starting at `start`; returns [data, bytesConsumed]. */
function inflateAt(buf: Buffer, start: number): [Buffer, number] {
  // Binary search the smallest prefix length that inflates cleanly.
  let lo = 1;
  let hi = buf.length - start;
  // First verify the whole remainder inflates (it must, for a well-formed pack).
  const full = inflateSync(buf.subarray(start));
  // Find minimal length via binary search on success.
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    try {
      const out = inflateSync(buf.subarray(start, start + mid));
      if (out.equals(full)) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    } catch {
      lo = mid + 1;
    }
  }
  return [full, lo];
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const [srcSize, p1] = readVarint(delta, pos);
  pos = p1;
  const [tgtSize, p2] = readVarint(delta, pos);
  pos = p2;
  if (srcSize !== base.length) throw new Error(`delta base size ${srcSize} != ${base.length}`);
  const parts: Buffer[] = [];
  let outLen = 0;
  while (pos < delta.length) {
    const op = delta[pos]!;
    pos += 1;
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) {
        offset |= delta[pos]! << (8 * i);
        pos += 1;
      }
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) {
        size |= delta[pos]! << (8 * i);
        pos += 1;
      }
      if (size === 0) size = 0x10000;
      if (offset + size > base.length) throw new Error('delta copy out of range');
      parts.push(base.subarray(offset, offset + size));
      outLen += size;
    } else if (op !== 0) {
      if (pos + op > delta.length) throw new Error('delta insert out of range');
      parts.push(delta.subarray(pos, pos + op));
      outLen += op;
      pos += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (outLen !== tgtSize) throw new Error(`delta result size ${outLen} != ${tgtSize}`);
  return Buffer.concat(parts);
}

export interface PackEntry {
  sha: string;
  type: 'commit' | 'tree' | 'blob' | 'tag';
  data: Buffer;
}

/** Parse a packfile, resolving deltas against the pack itself and `external` objects. */
export function parsePack(buf: Buffer, external: (sha: string) => { type: string; data: Buffer } | undefined): Map<string, PackEntry> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = buf.readUInt32BE(4);
  if (version !== 2) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  interface Raw {
    offset: number;
    typeId: number;
    size: number;
    dataStart: number;
    dataEnd: number;
    baseOffset?: number;
    baseSha?: string;
    data: Buffer;
  }
  const raws: Raw[] = [];
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryStart = off;
    let b = buf[off]!;
    const typeId = (b >> 4) & 7;
    let size = b & 0x0f;
    let shift = 4;
    off += 1;
    while (b & 0x80) {
      b = buf[off]!;
      size |= (b & 0x7f) << shift;
      shift += 7;
      off += 1;
    }
    let baseOffset: number | undefined;
    let baseSha: string | undefined;
    if (typeId === 6) {
      const [deltaOff, p] = readOffsetVarint(buf, off);
      baseOffset = entryStart - deltaOff;
      off = p;
    } else if (typeId === 7) {
      baseSha = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const [data, consumed] = inflateAt(buf, off);
    if (data.length !== size) throw new Error(`pack object size ${data.length} != header ${size}`);
    raws.push({ offset: entryStart, typeId, size, dataStart: off, dataEnd: off + consumed, baseOffset, baseSha, data });
    off += consumed;
  }
  // Verify trailer checksum.
  const trailer = buf.subarray(buf.length - 20);
  const actual = createHash('sha1').update(buf.subarray(0, buf.length - 20)).digest();
  if (!trailer.equals(actual)) throw new Error('pack trailer checksum mismatch');

  const byOffset = new Map<number, Raw>();
  for (const r of raws) byOffset.set(r.offset, r);
  const resolved = new Map<string, PackEntry>();
  const resolving = new Set<number>();

  const objectId = (typeId: number, data: Buffer): string => {
    const header = Buffer.from(`${TYPE_NAMES[typeId]} ${data.length}\0`, 'ascii');
    return createHash('sha1').update(Buffer.concat([header, data])).digest('hex');
  };

  const resolve = (raw: Raw): PackEntry => {
    if (raw.typeId === 6 || raw.typeId === 7) {
      if (resolving.has(raw.offset)) throw new Error('delta cycle');
      resolving.add(raw.offset);
      let base: PackEntry;
      if (raw.baseOffset !== undefined) {
        const baseRaw = byOffset.get(raw.baseOffset);
        if (!baseRaw) throw new Error('ofs-delta base not in pack');
        base = resolve(baseRaw);
      } else {
        const sha = raw.baseSha!;
        // Base may be in the pack (find by computed id) or external.
        let found: PackEntry | undefined;
        for (const r of raws) {
          if (r.typeId === 6 || r.typeId === 7) continue;
          if (objectId(r.typeId, r.data) === sha) {
            found = { sha, type: TYPE_NAMES[r.typeId] as PackEntry['type'], data: r.data };
            break;
          }
        }
        if (!found) {
          const ext = external(sha);
          if (!ext) throw new Error(`ref-delta base ${sha} not found`);
          found = { sha, type: ext.type as PackEntry['type'], data: ext.data };
        }
        base = found;
      }
      const data = applyDelta(base.data, raw.data);
      const entry: PackEntry = { sha: objectId(TYPE_IDS[base.type]!, data), type: base.type, data };
      resolving.delete(raw.offset);
      return entry;
    }
    return { sha: objectId(raw.typeId, raw.data), type: TYPE_NAMES[raw.typeId] as PackEntry['type'], data: raw.data };
  };

  for (const raw of raws) {
    const entry = resolve(raw);
    resolved.set(entry.sha, entry);
  }
  return resolved;
}

// ---------------------------------------------------------------- object closure

/** All objects reachable from `tips`, minus objects reachable from `excludes`. */
function closure(
  store: Store,
  tips: string[],
  excludes: string[],
  maxDepth: number | null,
  shallowBoundaries: string[] = [],
): { objects: PackEntry[]; shallow: string[]; unshallow: string[] } {
  const stopAt = new Set(shallowBoundaries);
  const excluded = new Set<string>();
  const collectExcluded = (tip: string): void => {
    const queue = [tip];
    while (queue.length > 0) {
      const sha = queue.pop()!;
      if (excluded.has(sha)) continue;
      excluded.add(sha);
      const obj = store.objects.get(sha);
      if (!obj) continue;
      if (obj.type === 'commit') {
        // A shallow boundary is a wall: the client has this commit and its tree, but
        // NOT its parents (deepening must deliver them).
        if (!stopAt.has(sha)) {
          for (const p of store.parentsOfCommit(sha)) queue.push(p);
        }
        const tree = store.treeShaOfCommit(sha);
        if (tree) queue.push(tree);
      } else if (obj.type === 'tree') {
        for (const [, blobSha] of store.flattenTree(sha)) excluded.add(blobSha);
        const data = obj.data;
        let off = 0;
        while (off < data.length) {
          const sp = data.indexOf(0x20, off);
          const nul = data.indexOf(0x00, sp);
          const mode = data.subarray(off, sp).toString('ascii');
          const sub = data.subarray(nul + 1, nul + 21).toString('hex');
          off = nul + 21;
          if (mode === '40000') queue.push(sub);
          else excluded.add(sub);
        }
      }
    }
  };
  for (const e of excludes) collectExcluded(e);

  const included = new Map<string, PackEntry>();
  const shallow = new Set<string>();
  const visitedTrees = new Set<string>();
  const addObject = (sha: string): void => {
    if (included.has(sha) || excluded.has(sha)) return;
    const obj = store.objects.get(sha);
    if (!obj) return;
    included.set(sha, { sha, type: obj.type, data: obj.data });
  };
  const addTree = (treeSha: string): void => {
    if (visitedTrees.has(treeSha)) return;
    visitedTrees.add(treeSha);
    const obj = store.objects.get(treeSha);
    if (!obj || obj.type !== 'tree') return;
    if (!excluded.has(treeSha)) included.set(treeSha, { sha: treeSha, type: 'tree', data: obj.data });
    const data = obj.data;
    let off = 0;
    while (off < data.length) {
      const sp = data.indexOf(0x20, off);
      const nul = data.indexOf(0x00, sp);
      const mode = data.subarray(off, sp).toString('ascii');
      const sub = data.subarray(nul + 1, nul + 21).toString('hex');
      off = nul + 21;
      if (mode === '40000') addTree(sub);
      else addObject(sub);
    }
  };

  // BFS over commits with depth tracking. With maxDepth set (shallow fetch), commits at
  // depth 0..maxDepth-1 are included with their trees; a commit at depth maxDepth-1 that
  // has parents is shallow (its parents are excluded, never packed). The walk passes
  // THROUGH excluded (already-held) commits so deepening past a shallow boundary can
  // still reach the ancestors the client does not have.
  const queue: { sha: string; depth: number }[] = tips.map((sha) => ({ sha, depth: 0 }));
  const seenCommits = new Set<string>();
  while (queue.length > 0) {
    const { sha, depth } = queue.shift()!;
    if (seenCommits.has(sha)) continue;
    seenCommits.add(sha);
    const obj = store.objects.get(sha);
    if (!obj) continue;
    // A wanted tag object: include the tag and follow its target commit.
    if (obj.type === 'tag') {
      addObject(sha);
      const target = tagTargetSha(obj.data);
      if (target) queue.push({ sha: target, depth });
      continue;
    }
    if (obj.type !== 'commit') continue;
    if (maxDepth !== null && depth >= maxDepth) continue;
    const parents = store.parentsOfCommit(sha);
    if (!excluded.has(sha)) {
      addObject(sha);
      const tree = store.treeShaOfCommit(sha);
      if (tree) addTree(tree);
      if (maxDepth !== null && parents.length > 0 && depth + 1 >= maxDepth) shallow.add(sha);
    }
    if (maxDepth === null || depth + 1 < maxDepth) {
      for (const p of parents) queue.push({ sha: p, depth: depth + 1 });
    }
  }

  // Emit commits first (newest first), then tags, trees, then blobs.
  const commits = [...included.values()].filter((o) => o.type === 'commit').sort((a, b) => store.commitTime(b.sha) - store.commitTime(a.sha));
  const tags = [...included.values()].filter((o) => o.type === 'tag');
  const trees = [...included.values()].filter((o) => o.type === 'tree');
  const blobs = [...included.values()].filter((o) => o.type === 'blob');
  // Unshallow: the client's old shallow boundaries that are now fully included.
  const unshallow = shallowBoundaries.filter((s) => {
    const obj = store.objects.get(s);
    return obj?.type === 'commit' && !shallow.has(s) && included.has(s);
  });
  return { objects: [...commits, ...tags, ...trees, ...blobs], shallow: [...shallow], unshallow };
}

// ---------------------------------------------------------------- advertisements

function refLines(repo: Repo): { name: string; sha: string }[] {
  const out: { name: string; sha: string }[] = [];
  const defaultTip = repo.branches.get(repo.defaultBranch);
  if (defaultTip) out.push({ name: 'HEAD', sha: defaultTip });
  const branches = [...repo.branches.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [branch, sha] of branches) out.push({ name: `refs/heads/${branch}`, sha });
  const tags = [...repo.tags.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [tag, sha] of tags) out.push({ name: `refs/tags/${tag}`, sha });
  return out;
}

/** The commit an annotated tag object points at, or null. */
function tagTarget(store: Store, tagSha: string): string | null {
  const obj = store.objects.get(tagSha);
  if (!obj || obj.type !== 'tag') return null;
  return tagTargetSha(obj.data);
}

/** The `object` line of a tag object's bytes. */
function tagTargetSha(data: Buffer): string | null {
  const m = data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
  return m ? m[1]! : null;
}

function advertisementV0(store: Store, repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? UPLOAD_CAPS : RECEIVE_CAPS;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = refLines(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    refs.forEach((ref, i) => {
      parts.push(pktLine(i === 0 ? `${ref.sha} ${ref.name}\0${caps}\n` : `${ref.sha} ${ref.name}\n`));
      // Annotated tags advertise their peeled target on a `^{}` line.
      if (ref.name.startsWith('refs/tags/')) {
        const peeled = tagTarget(store, ref.sha);
        if (peeled) parts.push(pktLine(`${peeled} ${ref.name}^{}\n`));
      }
    });
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function advertisementV2(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    pktLine(`agent=${AGENT}\n`),
    PKT_FLUSH,
  ]);
}

// ---------------------------------------------------------------- upload-pack

interface FetchParams {
  wants: string[];
  haves: string[];
  shallowLines: string[];
  depth: number | null;
}

function parseV0Fetch(buf: Buffer): FetchParams {
  const packets = decodePktLines(buf);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowLines: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5, 45));
    else if (line.startsWith('have ')) haves.push(line.slice(5, 45));
    else if (line.startsWith('shallow ')) shallowLines.push(line.slice(8, 48));
    else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isSafeInteger(n) && n >= 0) depth = n;
    } else if (line === 'done' || line.startsWith('deepen-') || line.startsWith('filter ')) {
      // Accepted and ignored.
    } else {
      throw new Error(`unexpected upload-pack line ${JSON.stringify(line.slice(0, 40))}`);
    }
  }
  return { wants, haves, shallowLines, depth };
}

function parseV2Fetch(buf: Buffer): { command: string; params: FetchParams } {
  const packets = decodePktLines(buf);
  const params: FetchParams = { wants: [], haves: [], shallowLines: [], depth: null };
  let command = '';
  let afterDelim = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind === 'delim') {
      afterDelim = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (!afterDelim) {
      if (line.startsWith('command=')) command = line.slice(8);
      continue;
    }
    if (line.startsWith('want ')) params.wants.push(line.slice(5, 45));
    else if (line.startsWith('have ')) params.haves.push(line.slice(5, 45));
    else if (line.startsWith('shallow ')) params.shallowLines.push(line.slice(8, 48));
    else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isSafeInteger(n) && n >= 0) params.depth = n;
    } else if (
      line === 'done' || line === 'thin-pack' || line === 'no-progress' || line === 'ofs-delta' ||
      line === 'peel' || line === 'symrefs' || line === 'unborn' || line === 'include-tag' ||
      line.startsWith('filter ') || line.startsWith('deepen-') || line.startsWith('ref-prefix ') ||
      line.startsWith('agent=') || line.startsWith('object-format=')
    ) {
      // Accepted and ignored (ls-refs arguments and capability echoes).
    } else {
      throw new Error(`unexpected v2 fetch line ${JSON.stringify(line.slice(0, 40))}`);
    }
  }
  return { command, params };
}

function serveFetch(store: Store, repo: Repo, params: FetchParams, v2: boolean): Buffer {
  const excludes = [...params.haves, ...params.shallowLines];
  const { objects, shallow, unshallow } = closure(store, params.wants, excludes, params.depth, params.shallowLines);
  const pack = buildPack(objects);
  if (!v2) {
    const parts: Buffer[] = [];
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(pktLine('NAK\n'));
    parts.push(sidebandPack(pack));
    return Buffer.concat(parts);
  }
  const parts: Buffer[] = [];
  // Real git expects no acknowledgments section when the request carried no haves
  // (it errors "expected 'packfile', received 'acknowledgments'"); send it only
  // when negotiation actually happened.
  if (params.haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'));
    parts.push(pktLine('NAK\n'));
    parts.push(PKT_DELIM);
  }
  if (shallow.length > 0 || unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}

function serveLsRefs(store: Store, repo: Repo, buf: Buffer): Buffer {
  // Honour ref-prefix filtering: only refs whose name starts with a requested prefix
  // are listed (an unmatched prefix lists nothing); HEAD only matches '' or 'HEAD'.
  const prefixes: string[] = [];
  try {
    for (const packet of decodePktLines(buf)) {
      if (packet.kind !== 'data') continue;
      const line = packet.payload.toString('utf8').replace(/\n$/, '');
      if (line.startsWith('ref-prefix ')) prefixes.push(line.slice(11));
    }
  } catch {
    // A malformed request lists everything rather than failing the call.
  }
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const refs = refLines(repo).filter((r) => keep(r.name));
  const parts: Buffer[] = [];
  if (refs.length === 0) {
    // No refs at all (or no prefix match): an unborn HEAD is only advertised when the
    // repo truly has no refs and the prefix allows HEAD.
    if (repo.branches.size === 0 && repo.tags.size === 0 && keep('HEAD')) {
      parts.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    }
  } else {
    for (const ref of refs) {
      if (ref.name === 'HEAD') parts.push(pktLine(`${ref.sha} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
      else if (ref.name.startsWith('refs/tags/')) {
        const peeled = tagTarget(store, ref.sha);
        parts.push(pktLine(peeled ? `${ref.sha} ${ref.name} peeled:${peeled}\n` : `${ref.sha} ${ref.name}\n`));
      } else parts.push(pktLine(`${ref.sha} ${ref.name}\n`));
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- receive-pack

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function parseReceivePack(buf: Buffer): { commands: PushCommand[]; sideband: boolean; packStart: number } {
  // Command lines are pkt-lines up to the first flush; the rest is the packfile.
  let off = 0;
  const commands: PushCommand[] = [];
  let sideband = false;
  let first = true;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (head === '0000') {
      off += 4;
      break;
    }
    const len = parseInt(head, 16);
    if (!Number.isFinite(len) || len < 4 || off + len > buf.length) throw new Error('bad pkt-line length in receive-pack');
    let line = buf.subarray(off + 4, off + len).toString('utf8').replace(/\n$/, '');
    off += len;
    let caps = '';
    const nul = line.indexOf('\0');
    if (nul >= 0) {
      caps = line.slice(nul + 1);
      line = line.slice(0, nul);
    }
    if (first) {
      sideband = caps.split(' ').includes('side-band-64k');
      first = false;
    }
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line);
    if (!m) throw new Error(`bad receive-pack command ${JSON.stringify(line.slice(0, 60))}`);
    commands.push({ oldOid: m[1]!, newOid: m[2]!, ref: m[3]! });
  }
  return { commands, sideband, packStart: off };
}

function receivePackReport(results: { ref: string; ok: boolean; reason: string }[], unpackOk: boolean, unpackDetail: string, sideband: boolean): Buffer {
  const lines: Buffer[] = [pktLine(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`)];
  for (const r of results) {
    lines.push(r.ok ? pktLine(`ok ${r.ref}\n`) : pktLine(`ng ${r.ref} ${r.reason}\n`));
  }
  lines.push(PKT_FLUSH);
  const body = Buffer.concat(lines);
  if (!sideband) return body;
  // Sideband-wrap the whole report as band-1 packets.
  const parts: Buffer[] = [];
  const MAX = 65515;
  for (let off = 0; off < body.length; off += MAX) {
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), body.subarray(off, Math.min(body.length, off + MAX))])));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- HTTP entry

export async function handleGit(req: IncomingMessage, res: ServerResponse, store: Store, owner: string, repoName: string, rest: string): Promise<boolean> {
  const method = req.method ?? 'GET';
  const query = queryOf(req);
  const repo = store.getRepo(owner, repoName);

  if (!isAuthed(req)) {
    errMessage(res, 401, 'Requires authentication');
    return true;
  }
  if (!repo) {
    errMessage(res, 404, 'Not Found');
    return true;
  }

  // GET info/refs
  if (method === 'GET' && rest === '/info/refs') {
    const service = query.get('service');
    if (service === 'git-upload-pack') {
      const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      const body = wantsV2 ? advertisementV2() : advertisementV0(store, repo, 'git-upload-pack');
      sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', body);
      return true;
    }
    if (service === 'git-receive-pack') {
      sendRaw(res, 200, 'application/x-git-receive-pack-advertisement', advertisementV0(store, repo, 'git-receive-pack'));
      return true;
    }
    errMessage(res, 400, 'Unknown service');
    return true;
  }

  // POST git-upload-pack
  if (method === 'POST' && rest === '/git-upload-pack') {
    const buf = await readBody(req);
    if (buf === null) {
      res.writeHead(400);
      res.end();
      return true;
    }
    const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    try {
      let body: Buffer;
      if (wantsV2) {
        const { command, params } = parseV2Fetch(buf);
        if (command === 'ls-refs') body = serveLsRefs(store, repo, buf);
        else if (command === 'fetch') body = serveFetch(store, repo, params, true);
        else throw new Error(`unknown v2 command ${JSON.stringify(command)}`);
      } else {
        const params = parseV0Fetch(buf);
        body = serveFetch(store, repo, params, false);
      }
      sendRaw(res, 200, 'application/x-git-upload-pack-result', body);
    } catch {
      res.writeHead(400);
      res.end();
    }
    return true;
  }

  // POST git-receive-pack (v0 only)
  if (method === 'POST' && rest === '/git-receive-pack') {
    const buf = await readBody(req);
    if (buf === null) {
      res.writeHead(400);
      res.end();
      return true;
    }
    let parsed: { commands: PushCommand[]; sideband: boolean; packStart: number };
    try {
      parsed = parseReceivePack(buf);
    } catch {
      res.writeHead(400);
      res.end();
      return true;
    }
    const { commands, sideband, packStart } = parsed;
    const hasUpdates = commands.some((c) => c.newOid !== ZERO_OID);
    // A create/update command list always carries a pack, even an empty one: a bare
    // command list is an unpack error (a delete-only list carries no pack at all).
    if (hasUpdates && packStart >= buf.length) {
      sendRaw(res, 200, 'application/x-git-receive-pack-result', receivePackReport(
        commands.map((c) => ({ ref: c.ref, ok: false, reason: 'unpacker error' })),
        false,
        'unpacker error',
        sideband,
      ));
      return true;
    }
    let entries = new Map<string, PackEntry>();
    if (hasUpdates && packStart < buf.length) {
      try {
        entries = parsePack(buf.subarray(packStart), (sha) => {
          const obj = store.objects.get(sha);
          return obj ? { type: obj.type, data: obj.data } : undefined;
        });
      } catch (e) {
        const reason = e instanceof Error ? e.message : 'unpack error';
        sendRaw(res, 200, 'application/x-git-receive-pack-result', receivePackReport(
          commands.map((c) => ({ ref: c.ref, ok: false, reason })),
          false,
          reason,
          sideband,
        ));
        return true;
      }
    }
    const results: { ref: string; ok: boolean; reason: string }[] = [];
    // Git unpacks first, then checks refs: write the pack objects into the store
    // BEFORE ancestry validation, or every fast-forward looks non-fast-forward.
    for (const entry of entries.values()) {
      store.objects.set(entry.sha, { type: entry.type, data: entry.data });
    }
    // Validate everything, then apply ref updates.
    const pending: { cmd: PushCommand; target: 'heads' | 'tags'; branch: string }[] = [];
    let valid = true;
    for (const cmd of commands) {
      const headMatch = /^refs\/heads\/(.+)$/.exec(cmd.ref);
      const tagMatch = /^refs\/tags\/(.+)$/.exec(cmd.ref);
      if (!headMatch && !tagMatch) {
        results.push({ ref: cmd.ref, ok: false, reason: 'invalid ref' });
        valid = false;
        continue;
      }
      const target = headMatch ? 'heads' : 'tags';
      const branch = (headMatch?.[1] ?? tagMatch?.[1])!;
      const current = target === 'heads' ? repo.branches.get(branch) : repo.tags.get(branch);
      if (cmd.oldOid !== ZERO_OID && cmd.oldOid.toLowerCase() !== (current ?? ZERO_OID).toLowerCase()) {
        results.push({ ref: cmd.ref, ok: false, reason: 'old value does not match current ref' });
        valid = false;
        continue;
      }
      if (cmd.newOid === ZERO_OID) {
        if (!current) {
          results.push({ ref: cmd.ref, ok: false, reason: 'ref does not exist' });
          valid = false;
          continue;
        }
        pending.push({ cmd, target, branch });
        results.push({ ref: cmd.ref, ok: true, reason: '' });
        continue;
      }
      const obj = entries.get(cmd.newOid.toLowerCase()) ?? store.objects.get(cmd.newOid.toLowerCase());
      const wantType = target === 'heads' ? 'commit' : null; // tags accept a commit or an annotated tag object
      if (!obj || (wantType !== null && obj.type !== wantType) || (wantType === null && obj.type !== 'commit' && obj.type !== 'tag')) {
        results.push({ ref: cmd.ref, ok: false, reason: 'new object is not a commit' });
        valid = false;
        continue;
      }
      if (current && current !== ZERO_OID && !store.isAncestor(current, cmd.newOid.toLowerCase())) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        valid = false;
        continue;
      }
      pending.push({ cmd, target, branch });
      results.push({ ref: cmd.ref, ok: true, reason: '' });
    }
    if (!valid) {
      // A mixed report still advances the accepted refs; only the refused ones stay.
      for (const p of pending) applyRefUpdate(repo, p);
      sendRaw(res, 200, 'application/x-git-receive-pack-result', receivePackReport(results, true, 'ok', sideband));
      return true;
    }
    // Apply ref updates.
    for (const p of pending) applyRefUpdate(repo, p);
    sendRaw(res, 200, 'application/x-git-receive-pack-result', receivePackReport(results, true, 'ok', sideband));
    return true;
  }

  return false;
}

function applyRefUpdate(repo: Repo, p: { cmd: PushCommand; target: 'heads' | 'tags'; branch: string }): void {
  if (p.cmd.newOid === ZERO_OID) {
    if (p.target === 'heads') repo.branches.delete(p.branch);
    else repo.tags.delete(p.branch);
  } else if (p.target === 'heads') {
    repo.branches.set(p.branch, p.cmd.newOid.toLowerCase());
  } else {
    repo.tags.set(p.branch, p.cmd.newOid.toLowerCase());
  }
}

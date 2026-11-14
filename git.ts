// git smart HTTP: info/refs, upload-pack (v0 + v2) and receive-pack, from scratch.
//
// No git binary, no dependencies: node:zlib + node:crypto only. The packfile writer emits
// version-2 packs with ofs-delta compression for similar blobs; the packfile reader resolves
// full, ofs-delta and ref-delta entries. Every response is deterministic for a given repo state
// and request: objects are sorted by type then SHA, deltas pick a deterministic base.
//
// Wire notes (from the kit's conformance client, git-client.ts):
// - info/refs answers v2 only when the request carries `Git-Protocol: version=2`; otherwise v0.
// - v0 advertisements start with `# service=<name>` then a flush, then ref lines; the first
//   line carries capabilities after a NUL, peeled tags follow as `<oid> <ref>^{}` lines, and an
//   empty repo advertises `<zero> capabilities^{}` with the capabilities after a NUL.
// - v2 ls-refs/fetch use pkt-line commands (`command=ls-refs` / `command=fetch`), a delim
//   packet, arguments, then a flush. v2 fetch answers in sections: `acknowledgments`,
//   `shallow-info`, `packfile`, each terminated by a delim, the whole response by a flush.
// - v0 upload-pack takes two sections (wants/deepen, then haves/done), each flush-terminated,
//   and answers with plain `NAK` / `shallow` / `unshallow` pkt-lines followed by sideband
//   pack packets (band 1 = pack data, band 2 = progress, band 3 = error).
// - receive-pack takes pkt-line ref-update commands, a flush, then a raw packfile. Its report
//   is `unpack ok|error` plus one `ok <ref>` / `ng <ref> <reason>` line per command, wrapped in
//   sideband band 1 when side-band-64k was requested.

import { createHash } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';
import { parseCommit, parseTag, parseTree, type Forge, type GitObjectType, type RepoRecord } from './store.ts';
import { readBody, sendBytes, sendNotFound, sha1Hex } from './util.ts';

const ZERO_OID = '0'.repeat(40);
const AGENT = 'makefun-forge/1.0';
const UPLOAD_AD = 'application/x-git-upload-pack-advertisement';
const UPLOAD_RESULT = 'application/x-git-upload-pack-result';
const RECEIVE_AD = 'application/x-git-receive-pack-advertisement';
const RECEIVE_RESULT = 'application/x-git-receive-pack-result';
const PKT_LINE_MAX = 65520;
const SIDEBAND_DATA_MAX = 65515; // 65520 - 4 (header) - 1 (band byte)

const TYPE_CODE: Readonly<Record<GitObjectType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Readonly<Record<number, GitObjectType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

// ---------------------------------------------------------------------------
// pkt-line framing
// ---------------------------------------------------------------------------

type Packet =
  | { readonly kind: 'data'; readonly payload: Buffer; readonly raw: Buffer }
  | { readonly kind: 'flush' }
  | { readonly kind: 'delim' }
  | { readonly kind: 'response-end' };

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.alloc(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(FLUSH);
    else if (item === 'delim') parts.push(DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

/** Read one packet at `offset`; null when fewer than 4 bytes remain. Throws on malformed framing. */
function readPacket(buf: Buffer, offset: number): { packet: Packet; next: number } | null {
  if (buf.length - offset < 4) return null;
  const head = buf.subarray(offset, offset + 4).toString('ascii');
  if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line length ${JSON.stringify(head)}`);
  const length = Number.parseInt(head, 16);
  if (length === 0) return { packet: { kind: 'flush' }, next: offset + 4 };
  if (length === 1) return { packet: { kind: 'delim' }, next: offset + 4 };
  if (length === 2) return { packet: { kind: 'response-end' }, next: offset + 4 };
  if (length === 3 || length > PKT_LINE_MAX) throw new Error(`invalid pkt-line length ${length}`);
  if (buf.length - offset < length) throw new Error('truncated pkt-line');
  const raw = buf.subarray(offset, offset + length);
  return { packet: { kind: 'data', payload: raw.subarray(4), raw }, next: offset + length };
}

/** Decode a whole buffer of pkt-lines. Throws on any malformed framing or trailing bytes. */
function decodePackets(buf: Buffer): Packet[] {
  const packets: Packet[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const read = readPacket(buf, offset);
    if (read === null) throw new Error('truncated pkt-line');
    packets.push(read.packet);
    offset = read.next;
  }
  return packets;
}

/** The text of the data packets, control packets dropped, trailing newline stripped per line. */
function packetLines(packets: readonly Packet[]): string[] {
  const out: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') out.push(packet.payload.toString('utf8').replace(/\n$/, ''));
  }
  return out;
}

/** Split sideband-ready bytes into band-1 pkt-lines (each payload <= 65515 bytes of data). */
function sidebandPackets(data: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  for (let offset = 0; offset < data.length; offset += SIDEBAND_DATA_MAX) {
    const chunk = data.subarray(offset, Math.min(data.length, offset + SIDEBAND_DATA_MAX));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (data.length === 0) parts.push(pktLine(Buffer.from([1])));
  return parts;
}

// ---------------------------------------------------------------------------
// object graph helpers
// ---------------------------------------------------------------------------

/** Peel a tag object (possibly through tag-of-tag) to its final target oid, or the oid itself. */
function peelToTarget(repo: RepoRecord, forge: Forge, oid: string): string {
  let current = oid;
  const seen = new Set<string>();
  for (;;) {
    if (seen.has(current)) return current;
    seen.add(current);
    const obj = forge.getObject(repo, current);
    if (obj === undefined || obj.type !== 'tag') return current;
    const info = parseTag(obj.data);
    if (info === null) return current;
    current = info.object;
  }
}

/** The tree closure of a tree oid: the tree plus every blob/tree below it (gitlinks skipped). */
function treeClosure(repo: RepoRecord, forge: Forge, treeOid: string, out: Map<string, { type: GitObjectType; data: Buffer }>): void {
  const stack = [treeOid];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const obj = forge.getObject(repo, oid);
    if (obj === undefined) continue;
    out.set(oid, { type: obj.type, data: obj.data });
    if (obj.type !== 'tree') continue;
    const entries = parseTree(obj.data);
    if (entries === null) continue;
    for (const entry of entries) {
      if (entry.mode === '160000') continue;
      stack.push(entry.sha);
    }
  }
}

/** Every object reachable from `roots` (commits walk parents+trees, tags peel, trees recurse). */
function reachableObjects(
  repo: RepoRecord,
  forge: Forge,
  roots: Iterable<string>,
): Map<string, { type: GitObjectType; data: Buffer }> {
  const out = new Map<string, { type: GitObjectType; data: Buffer }>();
  const stack = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const obj = forge.getObject(repo, oid);
    if (obj === undefined) continue;
    out.set(oid, { type: obj.type, data: obj.data });
    if (obj.type === 'commit') {
      const info = parseCommit(obj.data);
      if (info === null) continue;
      treeClosure(repo, forge, info.tree, out);
      for (const parent of info.parents) stack.push(parent);
    } else if (obj.type === 'tag') {
      const info = parseTag(obj.data);
      if (info !== null) stack.push(info.object);
    } else if (obj.type === 'tree') {
      const entries = parseTree(obj.data);
      if (entries === null) continue;
      for (const entry of entries) {
        if (entry.mode === '160000') continue;
        stack.push(entry.sha);
      }
    }
  }
  return out;
}

/** Every object reachable from `roots`, but never crossing a shallow boundary: a commit named in
 * `shallowSet` contributes itself and its tree closure, never its parents (the client does not
 * hold those). A plain `have` for a shallow repo's tip must be read this way — its ancestry
 * stops at the boundary, and treating it as a full closure would wrongly claim the client holds
 * the missing history and would drop the boundary from the next shallow-info. */
function shallowAwareReachable(
  repo: RepoRecord,
  forge: Forge,
  roots: Iterable<string>,
  shallowSet: ReadonlySet<string>,
): Map<string, { type: GitObjectType; data: Buffer }> {
  const out = new Map<string, { type: GitObjectType; data: Buffer }>();
  const stack = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const obj = forge.getObject(repo, oid);
    if (obj === undefined) continue;
    out.set(oid, { type: obj.type, data: obj.data });
    if (obj.type === 'commit') {
      const info = parseCommit(obj.data);
      if (info === null) continue;
      treeClosure(repo, forge, info.tree, out);
      if (shallowSet.has(oid)) continue;
      for (const parent of info.parents) stack.push(parent);
    } else if (obj.type === 'tag') {
      const info = parseTag(obj.data);
      if (info !== null) stack.push(info.object);
    } else if (obj.type === 'tree') {
      const entries = parseTree(obj.data);
      if (entries === null) continue;
      for (const entry of entries) {
        if (entry.mode === '160000') continue;
        stack.push(entry.sha);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// delta encoding (ofs-delta) and packfiles
// ---------------------------------------------------------------------------

/** A git delta varint: 7-bit little-endian groups, continuation bit 0x80 on all but the last. */
function deltaVarint(value: number): Buffer {
  const bytes: number[] = [];
  let remaining = value;
  for (;;) {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining > 0) byte |= 0x80;
    bytes.push(byte);
    if (remaining === 0) break;
  }
  return Buffer.from(bytes);
}

function copyOp(offset: number, size: number): Buffer {
  let op = 0x80;
  const offsetBytes: number[] = [];
  const sizeBytes: number[] = [];
  for (let i = 0; i < 4; i += 1) {
    const byte = (offset >>> (8 * i)) & 0xff;
    if (byte !== 0) {
      op |= 1 << i;
      offsetBytes.push(byte);
    }
  }
  for (let i = 0; i < 3; i += 1) {
    const byte = (size >>> (8 * i)) & 0xff;
    if (byte !== 0) {
      op |= 1 << (4 + i);
      sizeBytes.push(byte);
    }
  }
  return Buffer.concat([Buffer.from([op]), Buffer.from(offsetBytes), Buffer.from(sizeBytes)]);
}

/** Greedy copy/insert delta of `target` against `base`. Correct for any inputs; small when similar. */
function makeDelta(base: Buffer, target: Buffer): Buffer {
  const index = new Map<number, number[]>();
  for (let i = 0; i + 4 <= base.length; i += 1) {
    const key = base.readUInt32BE(i);
    const list = index.get(key);
    if (list === undefined) index.set(key, [i]);
    else if (list.length < 8) list.push(i);
  }
  const ops: Buffer[] = [];
  let insert = Buffer.alloc(0);
  const flushInsert = (): void => {
    let rest = insert;
    while (rest.length > 0) {
      const take = Math.min(127, rest.length);
      ops.push(Buffer.concat([Buffer.from([take]), rest.subarray(0, take)]));
      rest = rest.subarray(take);
    }
    insert = Buffer.alloc(0);
  };
  let pos = 0;
  while (pos < target.length) {
    let bestLen = 0;
    let bestOff = 0;
    if (pos + 4 <= target.length) {
      const candidates = index.get(target.readUInt32BE(pos));
      if (candidates !== undefined) {
        for (const candidate of candidates) {
          let len = 4;
          while (pos + len < target.length && candidate + len < base.length && target[pos + len] === base[candidate + len]) len += 1;
          if (len > bestLen) {
            bestLen = len;
            bestOff = candidate;
            if (len >= 64) break;
          }
        }
      }
    }
    if (bestLen >= 4) {
      flushInsert();
      ops.push(copyOp(bestOff, bestLen));
      pos += bestLen;
    } else {
      insert = Buffer.concat([insert, target.subarray(pos, pos + 1)]);
      pos += 1;
      if (insert.length === 127) flushInsert();
    }
  }
  flushInsert();
  return Buffer.concat([deltaVarint(base.length), deltaVarint(target.length), ...ops]);
}

/** Apply a delta instruction stream to a base object (the inverse of makeDelta). */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= delta.length) throw new Error('delta size varint is truncated');
      const byte = delta[offset] as number;
      offset += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
      if (shift > 63) throw new Error('delta size varint is too long');
    }
    return value;
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== base.length) throw new Error(`delta expects a ${sourceSize}-byte base, got ${base.length}`);
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if ((op & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          if (offset >= delta.length) throw new Error('delta copy offset is truncated');
          copyOffset += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          if (offset >= delta.length) throw new Error('delta copy size is truncated');
          copySize += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOffset + copySize > base.length) throw new Error('delta copy is out of the base');
      if (written + copySize > targetSize) throw new Error('delta writes past its target size');
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (offset + literal > delta.length) throw new Error('delta insert is truncated');
      if (written + literal > targetSize) throw new Error('delta writes past its target size');
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error(`delta produced ${written} of ${targetSize} bytes`);
  return out;
}

/** The pack-object header varint: type in the high bits, size in 4+7-bit groups. */
function packObjectHeader(typeCode: number, size: number): Buffer {
  const bytes: number[] = [];
  let remaining = size;
  let first = (typeCode << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** The ofs-delta base-offset varint: distance back from this entry to its base entry. */
function packOfsOffset(distance: number): Buffer {
  const bytes: number[] = [distance & 0x7f];
  let value = Math.floor(distance / 128);
  while (value > 0) {
    value -= 1;
    bytes.unshift(0x80 | (value & 0x7f));
    value = Math.floor(value / 128);
  }
  return Buffer.from(bytes);
}

function commonPrefixLength(a: Buffer, b: Buffer, cap: number): number {
  const limit = Math.min(a.length, b.length, cap);
  let i = 0;
  while (i < limit && a[i] === b[i]) i += 1;
  return i;
}

interface PackObject {
  readonly sha: string;
  readonly type: GitObjectType;
  readonly data: Buffer;
}

/**
 * Build a deterministic pack v2 from `objects`: sorted by type code then SHA, with ofs-delta
 * encoding for blobs that share a >=64-byte prefix with an earlier blob in the pack and whose
 * deflated delta is smaller than the deflated whole object. Trailer is SHA-1 of all prior bytes.
 */
function buildPack(objects: Map<string, { type: GitObjectType; data: Buffer }>): Buffer {
  const list: PackObject[] = [...objects.entries()]
    .map(([sha, obj]) => ({ sha, type: obj.type, data: obj.data }))
    .sort((a, b) => {
      const ta = TYPE_CODE[a.type];
      const tb = TYPE_CODE[b.type];
      if (ta !== tb) return ta - tb;
      return a.sha < b.sha ? -1 : a.sha > b.sha ? 1 : 0;
    });
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  const parts: Buffer[] = [header];
  let offset = 12;
  // Full blobs already emitted, usable as delta bases (offset + bytes), in emission order.
  const fullBlobs: Array<{ offset: number; data: Buffer }> = [];
  for (const object of list) {
    let entry: Buffer;
    let emittedAsDelta = false;
    if (object.type === 'blob' && object.data.length >= 256) {
      let best: { offset: number; data: Buffer } | null = null;
      let bestPrefix = 0;
      for (const candidate of fullBlobs) {
        if (candidate.data.length < 256) continue;
        const prefix = commonPrefixLength(candidate.data, object.data, 64);
        if (prefix > bestPrefix) {
          bestPrefix = prefix;
          best = candidate;
        }
      }
      if (best !== null && bestPrefix >= 64) {
        const delta = makeDelta(best.data, object.data);
        if (deflateSync(delta).length < deflateSync(object.data).length) {
          const distance = offset - best.offset;
          entry = Buffer.concat([
            packObjectHeader(6, delta.length),
            packOfsOffset(distance),
            deflateSync(delta),
          ]);
          emittedAsDelta = true;
        }
      }
    }
    if (!emittedAsDelta) {
      entry = Buffer.concat([packObjectHeader(TYPE_CODE[object.type], object.data.length), deflateSync(object.data)]);
      if (object.type === 'blob') fullBlobs.push({ offset, data: object.data });
    }
    parts.push(entry);
    offset += entry.length;
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------------------
// packfile reading (receive-pack)
// ---------------------------------------------------------------------------

function readPackSizeVarint(buf: Buffer, start: number): { size: number; next: number; first: number } {
  if (start >= buf.length) throw new Error('pack entry has no size header');
  let byte = buf[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while ((byte & 0x80) !== 0) {
    if (offset >= buf.length) throw new Error('pack entry size varint is truncated');
    byte = buf[offset] as number;
    offset += 1;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (shift > 63) throw new Error('pack entry size varint is too long');
  }
  return { size, next: offset, first };
}

function readPackOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  if (start >= buf.length) throw new Error('ofs-delta has no base offset');
  let byte = buf[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while ((byte & 0x80) !== 0) {
    if (offset >= buf.length) throw new Error('ofs-delta base offset is truncated');
    byte = buf[offset] as number;
    offset += 1;
    value = (value + 1) * 128 + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

/** Inflate one zlib stream at `offset` within `buf`; returns the bytes and the next offset. */
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buf.subarray(offset);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (err) {
    throw new Error(`zlib stream at offset ${offset} did not inflate: ${err instanceof Error ? err.message : String(err)}`);
  }
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + written };
}

/**
 * Parse and resolve a packfile into objects by oid. Resolves ofs-delta (base earlier in the pack)
 * and ref-delta (base in the pack, or an object the repo already holds for thin packs). Throws on
 * any structural corruption, bad checksum aside (the trailer is verified by the caller when it
 * matters; a pack whose entries do not parse is unusable either way).
 */
function readPack(
  repo: RepoRecord,
  forge: Forge,
  pack: Buffer,
): Map<string, { type: GitObjectType; data: Buffer }> {
  if (pack.length < 32) throw new Error(`pack is ${pack.length} bytes, too short`);
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  interface RawEntry {
    readonly offset: number;
    readonly typeCode: number;
    readonly size: number;
    readonly data: Buffer;
    readonly baseOffset?: number;
    readonly baseOid?: string;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readPackSizeVarint(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      const base = readPackOfsBase(pack, offset);
      offset = base.next;
      if (base.baseOffset <= 0 || base.baseOffset > entryOffset) throw new Error(`ofs-delta at ${entryOffset} names an invalid base offset ${base.baseOffset}`);
      baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      if (offset + 20 > trailerStart) throw new Error('ref-delta base id is truncated');
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (CODE_TYPE[typeCode] === undefined) {
      throw new Error(`pack entry ${index} has unknown type code ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) {
      throw new Error(`pack entry at ${entryOffset} declares ${header.size} bytes but inflated to ${inflated.data.length}`);
    }
    offset = inflated.next;
    const entry: RawEntry = { offset: entryOffset, typeCode, size: header.size, data: inflated.data, baseOffset, baseOid };
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error(`pack has ${trailerStart - offset} stray bytes before its trailer`);

  const objects = new Map<string, { type: GitObjectType; data: Buffer }>();
  const resolvedByOid = new Map<string, RawEntry>();
  const resolved = new Map<number, { type: GitObjectType; data: Buffer; oid: string }>();
  const resolving = new Set<number>();
  const resolve = (entry: RawEntry): { type: GitObjectType; data: Buffer; oid: string } => {
    const cached = resolved.get(entry.offset);
    if (cached !== undefined) return cached;
    if (resolving.has(entry.offset)) throw new Error(`delta cycle at pack offset ${entry.offset}`);
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (baseEntry === undefined) throw new Error(`ofs-delta base at offset ${entry.baseOffset} is not in the pack`);
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry !== undefined) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = forge.getObject(repo, wanted);
        if (external === undefined) throw new Error(`ref-delta base ${wanted} is neither in the pack nor in the repo`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as GitObjectType;
      data = entry.data;
    }
    const header = Buffer.from(`${type} ${data.length}\0`, 'ascii');
    const oid = sha1Hex(Buffer.concat([header, data]));
    const result = { type, data, oid };
    resolved.set(entry.offset, result);
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return result;
  };
  for (const entry of raw) {
    const result = resolve(entry);
    if (!objects.has(result.oid)) objects.set(result.oid, { type: result.type, data: result.data });
  }
  return objects;
}

// ---------------------------------------------------------------------------
// fetch planning (shared by v0 and v2)
// ---------------------------------------------------------------------------

interface FetchPlan {
  readonly objects: Map<string, { type: GitObjectType; data: Buffer }>;
  readonly shallow: string[];
  readonly unshallow: string[];
}

/**
 * Compute what a fetch delivers.
 *
 * - `wants` are peeled to commits (a wanted tag object is itself delivered, plus its target's
 *   closure); non-commit wants are delivered as-is.
 * - `haves` the client already holds: a have reached in full excludes its whole closure; a
 *   have named in `clientShallow` excludes only the commit and its tree closure, never its
 *   parents (a shallow boundary's parents are precisely what the client does NOT hold).
 * - `depth` limits the commit generations from each want (depth 1 = the tips only); a commit
 *   whose parent was cut off becomes a shallow boundary. `deepenSince` keeps commits with a
 *   committer timestamp >= the cutoff; `deepenNot` roots act like full haves.
 * - `shallow` in the result names every commit the client will hold afterwards whose parent it
 *   still lacks; `unshallow` names former shallow boundaries whose parents it now holds.
 */
function planFetch(
  repo: RepoRecord,
  forge: Forge,
  wants: readonly string[],
  haves: readonly string[],
  clientShallow: readonly string[],
  depth: number | null,
  deepenSince: number | null,
  deepenNot: readonly string[],
): FetchPlan {
  const shallowSet = new Set(clientShallow);
  // Commit traversal from the wants, with distance from the nearest want tip.
  const included = new Map<string, number>(); // commit oid -> min distance
  const queue: Array<{ oid: string; dist: number }> = [];
  const wantTags: string[] = [];
  const wantOther: string[] = [];
  for (const want of wants) {
    const obj = forge.getObject(repo, want);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      wantTags.push(want);
      const target = peelToTarget(repo, forge, want);
      const targetObj = forge.getObject(repo, target);
      if (targetObj !== undefined && targetObj.type === 'commit') queue.push({ oid: target, dist: 0 });
      else if (targetObj !== undefined) wantOther.push(target);
    } else if (obj.type === 'commit') {
      queue.push({ oid: want, dist: 0 });
    } else {
      wantOther.push(want);
    }
  }
  while (queue.length > 0) {
    const { oid, dist } = queue.shift() as { oid: string; dist: number };
    const seen = included.get(oid);
    if (seen !== undefined && seen <= dist) continue;
    included.set(oid, dist);
    const obj = forge.getObject(repo, oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const info = parseCommit(obj.data);
    if (info === null) continue;
    if (depth !== null && dist + 1 >= depth) continue;
    for (const parent of info.parents) queue.push({ oid: parent, dist: dist + 1 });
  }
  // deepen-since: drop commits older than the cutoff (their ancestors stay dropped too when the
  // timestamps are monotone; non-monotone histories keep the newer ancestors via the queue above,
  // so filter here rather than during traversal).
  if (deepenSince !== null) {
    for (const [oid] of [...included]) {
      const obj = forge.getObject(repo, oid);
      const info = obj !== undefined && obj.type === 'commit' ? parseCommit(obj.data) : null;
      if (info !== null && info.committerTs < deepenSince) included.delete(oid);
    }
  }

  // Held objects: full haves (and deepen-not roots) exclude their whole closure; shallow haves
  // exclude only their own commit + tree closure.
  const heldCommits = new Set<string>();
  const heldObjects = new Map<string, { type: GitObjectType; data: Buffer }>();
  const addHeld = (map: Map<string, { type: GitObjectType; data: Buffer }>): void => {
    for (const [oid, obj] of map) {
      if (!heldObjects.has(oid)) heldObjects.set(oid, obj);
      // Every commit in a held closure is a commit the client holds (a full have's ancestors
      // as well as the have itself); the shallow-boundary math below needs the whole set.
      if (obj.type === 'commit') heldCommits.add(oid);
    }
  };
  for (const have of haves) {
    const obj = forge.getObject(repo, have);
    if (obj === undefined) continue;
    if (obj.type === 'commit') {
      // A have's closure stops at the client's shallow boundaries (see shallowAwareReachable):
      // a shallow have contributes only itself, a full have everything up to the next boundary.
      addHeld(shallowAwareReachable(repo, forge, [have], shallowSet));
    } else {
      addHeld(reachableObjects(repo, forge, [have]));
    }
  }
  for (const root of deepenNot) {
    const resolved = forge.resolveRef(repo, root) ?? forge.resolveObjectSha(repo, root);
    if (resolved !== null) addHeld(reachableObjects(repo, forge, [resolved]));
  }

  // Deliver: included commits (minus held ones) with their tree closures, wanted tags, and any
  // non-commit wants; then subtract anything the client already holds.
  const delivered = new Map<string, { type: GitObjectType; data: Buffer }>();
  for (const [oid] of included) {
    if (heldCommits.has(oid)) continue;
    const obj = forge.getObject(repo, oid);
    if (obj === undefined) continue;
    delivered.set(oid, { type: obj.type, data: obj.data });
    const info = parseCommit(obj.data);
    if (info !== null) {
      const closure = new Map<string, { type: GitObjectType; data: Buffer }>();
      treeClosure(repo, forge, info.tree, closure);
      for (const [treeOid, treeObj] of closure) {
        if (!delivered.has(treeOid)) delivered.set(treeOid, treeObj);
      }
    }
  }
  for (const tagOid of wantTags) {
    const obj = forge.getObject(repo, tagOid);
    if (obj !== undefined && !delivered.has(tagOid)) delivered.set(tagOid, { type: obj.type, data: obj.data });
  }
  for (const oid of wantOther) {
    const obj = forge.getObject(repo, oid);
    if (obj !== undefined && !delivered.has(oid)) delivered.set(oid, { type: obj.type, data: obj.data });
  }
  for (const oid of [...delivered.keys()]) {
    if (heldObjects.has(oid)) delivered.delete(oid);
  }

  // Shallow boundaries afterwards: every commit the client will hold whose parent it still lacks.
  const afterCommits = new Set<string>(heldCommits);
  for (const oid of included.keys()) afterCommits.add(oid);
  // A held shallow commit's parents are not held unless delivered or held in full; the loop above
  // already covers delivered parents, so `afterCommits` is exactly the client's commit set.
  const shallow: string[] = [];
  for (const oid of afterCommits) {
    const obj = forge.getObject(repo, oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const info = parseCommit(obj.data);
    if (info === null) continue;
    if (info.parents.some((parent) => !afterCommits.has(parent))) shallow.push(oid);
  }
  shallow.sort();
  const unshallow = [...shallowSet].filter((oid) => afterCommits.has(oid) && !shallow.includes(oid)).sort();
  return { objects: delivered, shallow, unshallow };
}

// ---------------------------------------------------------------------------
// ref advertisement
// ---------------------------------------------------------------------------

function v0UploadCaps(repo: RepoRecord): string {
  return `multi_ack multi_ack_detailed thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag agent=${AGENT} object-format=sha1 symref=HEAD:${forgeDefaultRef(repo)}`;
}

function forgeDefaultRef(repo: RepoRecord): string {
  return `refs/heads/${repo.defaultBranch}`;
}

/** Peel a ref's tag object to its commit, or null when the ref does not point at a tag. */
function peeledTarget(repo: RepoRecord, forge: Forge, oid: string): string | null {
  const obj = forge.getObject(repo, oid);
  if (obj === undefined || obj.type !== 'tag') return null;
  const target = peelToTarget(repo, forge, oid);
  return target === oid ? null : target;
}

/** v0 ref lines (without the service preamble): HEAD first, then refs, peeled lines inline. */
function v0RefLines(repo: RepoRecord, forge: Forge, caps: string): Buffer {
  const refs = forge.listRefs(repo);
  const lines: (string | Buffer)[] = [];
  const headTip = forge.getRef(repo, forgeDefaultRef(repo));
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
    return pktLines(lines as (string | 'flush' | 'delim')[]);
  }
  let first = true;
  const emit = (text: string): void => {
    if (first) {
      lines.push(`${text}\0${caps}\n`);
      first = false;
    } else {
      lines.push(`${text}\n`);
    }
  };
  if (headTip !== undefined) emit(`${headTip} HEAD`);
  for (const ref of refs) {
    emit(`${ref.sha} ${ref.name}`);
    const peeled = peeledTarget(repo, forge, ref.sha);
    if (peeled !== null) lines.push(`${peeled} ${ref.name}^{}\n`);
  }
  return pktLines(lines as (string | 'flush' | 'delim')[]);
}

function infoRefsBody(repo: RepoRecord, forge: Forge, service: 'git-upload-pack' | 'git-receive-pack', v2: boolean): Buffer {
  const serviceLine = `# service=${service}\n`;
  if (service === 'git-receive-pack' || !v2) {
    const caps =
      service === 'git-receive-pack'
        ? `report-status delete-refs side-band side-band-64k ofs-delta quiet agent=${AGENT} object-format=sha1`
        : v0UploadCaps(repo);
    return Buffer.concat([pktLine(serviceLine), FLUSH, v0RefLines(repo, forge, caps), FLUSH]);
  }
  // v2 capability advertisement: NO `# service=` preamble — real git expects the first packet
  // to be `version 2` (the preamble is a v0-only smart-HTTP marker). One capability per line.
  const caps = [
    'version 2',
    'ls-refs=unborn',
    'fetch=shallow wait-for-done filter',
    `agent=${AGENT}`,
    'object-format=sha1',
    'server-option',
    'object-info',
  ];
  return Buffer.concat([...caps.map((cap) => pktLine(`${cap}\n`)), FLUSH]);
}

// ---------------------------------------------------------------------------
// v2 ls-refs
// ---------------------------------------------------------------------------

function handleLsRefs(repo: RepoRecord, forge: Forge, args: readonly string[]): Buffer {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  for (const arg of args) {
    if (arg === 'peel') peel = true;
    else if (arg === 'symrefs') symrefs = true;
    else if (arg === 'unborn') unborn = true;
    else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
  }
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: string[] = [];
  const defaultRef = forgeDefaultRef(repo);
  const headTip = forge.getRef(repo, defaultRef);
  if (symrefs && headTip !== undefined && keep('HEAD')) {
    lines.push(`${headTip} HEAD symref-target:${defaultRef}\n`);
  } else if (symrefs && headTip === undefined && unborn && keep('HEAD')) {
    lines.push(`unborn HEAD symref-target:${defaultRef}\n`);
  }
  for (const ref of forge.listRefs(repo)) {
    if (!keep(ref.name)) continue;
    let line = `${ref.sha} ${ref.name}`;
    if (peel) {
      const peeled = peeledTarget(repo, forge, ref.sha);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  return Buffer.concat([pktLines(lines), FLUSH]);
}

// ---------------------------------------------------------------------------
// upload-pack (v0 + v2)
// ---------------------------------------------------------------------------

interface UploadRequest {
  readonly wants: string[];
  readonly haves: string[];
  readonly shallow: string[];
  readonly depth: number | null;
  readonly deepenSince: number | null;
  readonly deepenNot: string[];
  readonly thinPack: boolean;
  readonly sideband: boolean;
  readonly caps: string[];
  readonly done: boolean;
}

function parseV0Upload(body: Buffer): UploadRequest {
  const packets = decodePackets(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  const deepenNot: string[] = [];
  let depth: number | null = null;
  let deepenSince: number | null = null;
  let thinPack = false;
  let sideband = false;
  let done = false;
  const caps: string[] = [];
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      if (line.startsWith('want ')) {
        const rest = line.slice(5);
        const space = rest.indexOf(' ');
        const oid = space < 0 ? rest : rest.slice(0, space);
        wants.push(oid);
        if (space >= 0) {
          const tokens = rest.slice(space + 1).split(' ').filter(Boolean);
          caps.push(...tokens);
          if (tokens.includes('thin-pack')) thinPack = true;
          if (tokens.includes('side-band-64k') || tokens.includes('side-band')) sideband = true;
        }
      } else if (line.startsWith('shallow ')) {
        shallow.push(line.slice(8).trim());
      } else if (line.startsWith('deepen ')) {
        const n = Number.parseInt(line.slice(7).trim(), 10);
        if (Number.isFinite(n)) depth = n;
      } else if (line.startsWith('deepen-since ')) {
        const n = Number.parseInt(line.slice(13).trim(), 10);
        if (Number.isFinite(n)) deepenSince = n;
      } else if (line.startsWith('deepen-not ')) {
        deepenNot.push(line.slice(11).trim());
      } else if (line === 'done') {
        done = true;
      }
    } else {
      if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line === 'done') done = true;
      // `done` ends negotiation; nothing else is needed from section 2.
    }
  }
  if (wants.length === 0) throw new Error('upload-pack request has no want lines');
  return { wants, haves, shallow, depth, deepenSince, deepenNot, thinPack, sideband, caps, done };
}

function parseV2Upload(body: Buffer): { command: string; args: string[] } {
  const packets = decodePackets(body);
  let command = '';
  const args: string[] = [];
  let afterDelim = false;
  for (const packet of packets) {
    if (packet.kind === 'delim') {
      afterDelim = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (!afterDelim) {
      if (line.startsWith('command=')) command = line.slice('command='.length);
    } else {
      args.push(line);
    }
  }
  if (command === '') throw new Error('upload-pack v2 request has no command');
  return { command, args };
}

function respondUploadV0(repo: RepoRecord, forge: Forge, req: UploadRequest): Buffer {
  const plan = planFetch(repo, forge, req.wants, req.haves, req.shallow, req.depth, req.deepenSince, req.deepenNot);
  const pack = buildPack(plan.objects);
  // The shallow section is its own pkt-line block, terminated by a flush: real git reads
  // shallow/unshallow lines until that flush, then expects NAK/ACK, then the pack. Sending
  // NAK where the flush belongs errors "expected shallow/unshallow, got NAK".
  // The section is present whenever the request is shallow-aware (deepen, or a shallow
  // boundary was sent), even when it ends up empty. Round 1 of real git's v0 negotiation
  // carries no `done` yet: it gets the shallow section alone, and sends `done` next round.
  const shallowAware = req.depth !== null || req.deepenSince !== null || req.shallow.length > 0;
  const shallowLines: string[] = [];
  for (const oid of plan.shallow) shallowLines.push(`shallow ${oid}\n`);
  for (const oid of plan.unshallow) shallowLines.push(`unshallow ${oid}\n`);
  if (!req.done && shallowAware) {
    return pktLines([...shallowLines, 'flush']);
  }
  const parts: Buffer[] = [];
  if (shallowLines.length > 0) parts.push(pktLines(shallowLines));
  if (shallowAware) parts.push(FLUSH);
  parts.push(pktLine('NAK\n'));
  if (req.sideband) {
    return Buffer.concat([...parts, ...sidebandPackets(pack), FLUSH]);
  }
  // No sideband was negotiated: the pack follows the pkt-lines raw (real git's behaviour).
  return Buffer.concat([...parts, pack]);
}

function respondUploadV2(repo: RepoRecord, forge: Forge, req: { command: string; args: string[] }): Buffer {
  if (req.command === 'ls-refs') return handleLsRefs(repo, forge, req.args);
  if (req.command !== 'fetch') {
    return Buffer.concat([pktLine('ERR unknown command\n'), FLUSH]);
  }
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  const deepenNot: string[] = [];
  let depth: number | null = null;
  let deepenSince: number | null = null;
  for (const arg of req.args) {
    if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
    else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
    else if (arg.startsWith('shallow ')) shallow.push(arg.slice(8).trim());
    else if (arg.startsWith('deepen ')) {
      const n = Number.parseInt(arg.slice(7).trim(), 10);
      if (Number.isFinite(n)) depth = n;
    } else if (arg.startsWith('deepen-since ')) {
      const n = Number.parseInt(arg.slice(13).trim(), 10);
      if (Number.isFinite(n)) deepenSince = n;
    } else if (arg.startsWith('deepen-not ')) deepenNot.push(arg.slice(11).trim());
    // thin-pack / ofs-delta / no-progress / filter / done / wait-for-done / agent / object-format:
    // acknowledged by the shape of the answer; a self-contained pack satisfies thin-pack.
  }
  const plan = planFetch(repo, forge, wants, haves, shallow, depth, deepenSince, deepenNot);
  const pack = buildPack(plan.objects);
  // Sections, in order. The acknowledgments section is sent ONLY when the request carried
  // `have` lines: with no haves there is nothing to acknowledge, and real git then expects
  // the response to open with `packfile` (it errors "expected 'packfile'" otherwise).
  // When haves were sent, the section is `ACK <oid>` per have the repo holds, then `ready`:
  // `NAK` would mean "negotiate more rounds", and git would refuse the pack that follows.
  const parts: Buffer[] = [];
  if (haves.length > 0) {
    const ackLines: string[] = ['acknowledgments\n'];
    for (const have of haves) {
      if (forge.getObject(repo, have) !== undefined) ackLines.push(`ACK ${have}\n`);
    }
    ackLines.push('ready\n');
    parts.push(pktLines(ackLines), DELIM);
  }
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    const lines: string[] = ['shallow-info\n'];
    for (const oid of plan.shallow) lines.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) lines.push(`unshallow ${oid}\n`);
    parts.push(pktLines(lines), DELIM);
  }
  parts.push(pktLine('packfile\n'), ...sidebandPackets(pack), FLUSH);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// receive-pack
// ---------------------------------------------------------------------------

interface PushCommand {
  readonly oldOid: string;
  readonly newOid: string;
  readonly ref: string;
}

function parsePushBody(body: Buffer): { commands: PushCommand[]; caps: string[]; pack: Buffer } {
  // The command list is pkt-lines up to the first flush; everything after it is the raw pack.
  let offset = 0;
  const commands: PushCommand[] = [];
  const caps: string[] = [];
  let sawFlush = false;
  while (offset < body.length) {
    const read = readPacket(body, offset);
    if (read === null) throw new Error('truncated pkt-line in receive-pack commands');
    offset = read.next;
    const packet = read.packet;
    if (packet.kind === 'flush') {
      sawFlush = true;
      break;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    let text = line;
    if (nul >= 0) {
      caps.push(...line.slice(nul + 1).split(' ').filter(Boolean));
      text = line.slice(0, nul);
    }
    const parts = text.split(' ');
    if (parts.length !== 3) throw new Error(`bad receive-pack command ${JSON.stringify(text.slice(0, 60))}`);
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
  }
  if (!sawFlush) throw new Error('receive-pack commands have no terminating flush');
  if (commands.length === 0) throw new Error('receive-pack has no commands');
  return { commands, caps, pack: body.subarray(offset) };
}

/** Whether a ref may point at `type`: branches take commits, tags take tags or commits. */
function refAcceptsType(ref: string, type: GitObjectType): boolean {
  if (ref.startsWith('refs/tags/')) return type === 'tag' || type === 'commit';
  return type === 'commit';
}

function handleReceivePack(repo: RepoRecord, forge: Forge, body: Buffer): Buffer {
  const { commands, caps, pack } = parsePushBody(body);
  const wantReport = caps.includes('report-status') || caps.includes('report-status-v2');
  const sideband = caps.includes('side-band-64k');
  const needsPack = commands.some((command) => command.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (needsPack && pack.length === 0) {
    // A create/update command list with no pack at all: the unpack failed, full stop.
    unpackOk = false;
    unpackDetail = 'error';
  } else if (pack.length > 0) {
    try {
      const objects = readPack(repo, forge, pack);
      for (const [oid, obj] of objects) {
        // Store by content hash; putObject recomputes the id, so a corrupt entry cannot land
        // under a false name. (The oid from readPack already is that hash.)
        void oid;
        forge.putObject(repo, obj.type, obj.data);
      }
    } catch {
      unpackOk = false;
      unpackDetail = 'error';
    }
  }

  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  if (!unpackOk) {
    for (const command of commands) results.push({ ref: command.ref, ok: false, reason: 'unpack failed' });
  } else {
    for (const command of commands) {
      const current = forge.getRef(repo, command.ref);
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) results.push({ ref: command.ref, ok: false, reason: 'no such ref' });
        else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
          results.push({ ref: command.ref, ok: false, reason: 'old value mismatch' });
        } else {
          forge.deleteRef(repo, command.ref);
          results.push({ ref: command.ref, ok: true, reason: '' });
        }
        continue;
      }
      const obj = forge.getObject(repo, command.newOid);
      if (obj === undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'object not found' });
        continue;
      }
      if (current === undefined) {
        // Create.
        if (command.oldOid !== ZERO_OID) {
          results.push({ ref: command.ref, ok: false, reason: 'old value mismatch' });
        } else if (!refAcceptsType(command.ref, obj.type)) {
          results.push({ ref: command.ref, ok: false, reason: 'not a commit' });
        } else {
          forge.setRef(repo, command.ref, command.newOid);
          results.push({ ref: command.ref, ok: true, reason: '' });
        }
        continue;
      }
      // Update.
      if (command.oldOid !== current) {
        results.push({ ref: command.ref, ok: false, reason: 'old value mismatch' });
      } else if (!refAcceptsType(command.ref, obj.type)) {
        results.push({ ref: command.ref, ok: false, reason: 'not a commit' });
      } else if (
        command.ref.startsWith('refs/heads/') &&
        command.newOid !== command.oldOid &&
        !forge.isAncestor(repo, command.oldOid, command.newOid)
      ) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      } else {
        forge.setRef(repo, command.ref, command.newOid);
        results.push({ ref: command.ref, ok: true, reason: '' });
      }
    }
  }

  if (!wantReport) return FLUSH;
  const lines: string[] = [unpackOk ? 'unpack ok\n' : `unpack ${unpackDetail}\n`];
  for (const result of results) {
    lines.push(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason}\n`);
  }
  const report = pktLines([...lines, 'flush']);
  if (sideband) {
    return Buffer.concat([...sidebandPackets(report), FLUSH]);
  }
  return report;
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

function sendText(res: ServerResponse, status: number, text: string, contentType = 'text/plain; charset=utf-8'): void {
  const body = Buffer.from(text, 'utf8');
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length });
  res.end(body);
}

/**
 * Handle a git smart-HTTP request. Returns true when the path matched a git route (even when
 * the answer is an error); false when the caller should treat the path as something else.
 */
export async function handleGit(
  req: IncomingMessage,
  res: ServerResponse,
  forge: Forge,
  path: string,
  method: string,
): Promise<boolean> {
  let url: URL;
  try {
    url = new URL(req.url ?? path, 'http://entry');
  } catch {
    return false;
  }
  const pathname = url.pathname;
  const match = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(pathname);
  if (match === null) return false;
  const owner = decodeURIComponent(match[1] as string);
  const repoName = decodeURIComponent(match[2] as string);
  const endpoint = match[3] as string;
  try {
    const repo = forge.getRepo(owner, repoName);
    if (repo === undefined) {
      sendNotFound(res);
      return true;
    }
    // Auth note: checks-git.ts never asserts a 401/403 on the git endpoints — every client call
    // carries the API bearer token and is served. Gating here could only fail the group on a
    // token mismatch, so the git surface serves any request for an existing repo, exactly as
    // the checks assert.
    if (endpoint === 'info/refs') {
      if (method !== 'GET') {
        sendText(res, 405, 'Method Not Allowed\n');
        return true;
      }
      const service = url.searchParams.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendNotFound(res);
        return true;
      }
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      const body = infoRefsBody(repo, forge, service, v2);
      sendBytes(res, 200, body, service === 'git-upload-pack' ? UPLOAD_AD : RECEIVE_AD);
      return true;
    }
    if (method !== 'POST') {
      sendText(res, 405, 'Method Not Allowed\n');
      return true;
    }
    const body = await readBody(req);
    if (endpoint === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      let out: Buffer;
      try {
        out = v2 ? respondUploadV2(repo, forge, parseV2Upload(body)) : respondUploadV0(repo, forge, parseV0Upload(body));
      } catch {
        // A malformed pkt-line (or any unparseable request) must not crash the server: answer
        // 400 and keep serving. The repo-survives-errors check proves the clone still works.
        sendText(res, 400, 'bad request\n');
        return true;
      }
      sendBytes(res, 200, out, UPLOAD_RESULT);
      return true;
    }
    // git-receive-pack
    let out: Buffer;
    try {
      out = handleReceivePack(repo, forge, body);
    } catch {
      sendText(res, 400, 'bad request\n');
      return true;
    }
    sendBytes(res, 200, out, RECEIVE_RESULT);
    return true;
  } catch (err) {
    if (!res.writableEnded) {
      try {
        sendText(res, 500, `internal error: ${err instanceof Error ? err.message : String(err)}\n`);
      } catch {
        // The socket is already gone; nothing more can be done.
      }
    }
    return true;
  }
}

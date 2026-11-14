// Shared HTTP and data helpers for the forge: JSON bodies, auth, pagination, hashing, base64.
// Every module in this entry imports from here; nothing here knows about any one surface.

import { createHash } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

export const JSON_TYPE = 'application/json; charset=utf-8';

/** The bearer token the entry expects, from the environment (MAKEFUN_SHOP_TOKEN in a trial). */
export function expectedToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

/** The Authorization header's bearer token, or null when absent or not a Bearer token. */
export function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/.exec(header.trim());
  return match === null ? null : (match[1] ?? '').trim();
}

/**
 * Whether the request carries the token the suite presents. When MAKEFUN_SHOP_TOKEN is set the token
 * must match it exactly; when it is unset any non-empty Bearer token is accepted (local practice).
 * A missing token is never accepted.
 */
export function isAuthorized(req: IncomingMessage): boolean {
  const token = bearerToken(req);
  if (token === null || token === '') return false;
  const expected = expectedToken();
  if (expected === '') return true;
  return token === expected;
}

/** The path of a request URL, or '/' when it does not parse (never a throw from a request). */
export function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

/** The query of a request URL as URLSearchParams, or an empty one when it does not parse. */
export function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

/** Read a request's whole body as bytes (no size cap here; the callers that need one enforce it). */
export function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Read a request's body and parse it as JSON; null when the body is empty, an Error when malformed. */
export async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const raw = await readBody(req);
  if (raw.length === 0) return null;
  return JSON.parse(raw.toString('utf8')) as unknown;
}

/** Answer one request with a JSON body; `headers` go beside the JSON ones. */
export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...headers });
  res.end(text);
}

/** Answer one request with raw bytes and a content type. */
export function sendBytes(res: ServerResponse, status: number, body: Buffer, contentType: string, headers: Readonly<Record<string, string>> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, ...headers });
  res.end(body);
}

/** GitHub's 404 body for an unknown route or resource. */
export function sendNotFound(res: ServerResponse, message = 'Not Found'): void {
  sendJson(res, 404, { message });
}

/** GitHub's 401 body for a missing or wrong token. */
export function sendUnauthorized(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Bad credentials' });
}

/** SHA-1 of bytes, lowercase hex. */
export function sha1Hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

/** The git object id of `type` with `data`: sha1("<type> <len>\0" + data). */
export function gitObjectId(type: string, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([header, data]));
}

/** Standard base64 of bytes. */
export function toBase64(bytes: Buffer | Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/** Bytes from standard base64 (tolerates whitespace); null when the text is not valid base64. */
export function fromBase64(text: string): Buffer | null {
  const clean = text.replace(/\s+/g, '');
  if (clean === '') return Buffer.alloc(0);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) return null;
  try {
    return Buffer.from(clean, 'base64');
  } catch {
    return null;
  }
}

/** The current time as an ISO 8601 string (API created_at/updated_at fields). */
export function isoNow(): string {
  return new Date().toISOString();
}

/** A parsed page/per_page pair: page >= 1, per_page clamped to 1..100 (GitHub's default 30). */
export function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const rawPage = Number.parseInt(query.get('page') ?? '1', 10);
  const rawPer = Number.parseInt(query.get('per_page') ?? '30', 10);
  const page = Number.isFinite(rawPage) && rawPage >= 1 ? Math.trunc(rawPage) : 1;
  const perPage = Number.isFinite(rawPer) ? Math.min(100, Math.max(1, Math.trunc(rawPer))) : 30;
  return { page, perPage };
}

/** Slice `items` to one page and build GitHub's Link header (first/prev/next/last as present). */
export function paginate<T>(items: readonly T[], page: number, perPage: number, baseUrl: string, query: URLSearchParams): { pageItems: T[]; link: string } {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);
  const linkParts: string[] = [];
  const urlFor = (p: number): string => {
    const q = new URLSearchParams(query);
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    return `${baseUrl}?${q.toString()}`;
  };
  linkParts.push(`<${urlFor(1)}>; rel="first"`);
  if (safePage > 1) linkParts.push(`<${urlFor(safePage - 1)}>; rel="prev"`);
  if (safePage < totalPages) linkParts.push(`<${urlFor(safePage + 1)}>; rel="next"`);
  linkParts.push(`<${urlFor(totalPages)}>; rel="last"`);
  return { pageItems, link: linkParts.join(', ') };
}

/** Split a path into its segments, dropping empty ones (a leading slash is ignored). */
export function splitPath(path: string): string[] {
  return path.split('/').filter((part) => part !== '');
}

/** Whether `value` is a plain JSON object (not null, not an array). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

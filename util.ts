// Shared HTTP helpers: JSON replies, body reading, auth, pagination links.
import type { IncomingMessage, ServerResponse } from 'node:http';

export const JSON_TYPE = 'application/json; charset=utf-8';

let requestCounter = 0;

export function requestId(): string {
  requestCounter += 1;
  return `${Date.now().toString(36)}-${requestCounter.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Base headers every reply carries. */
export function baseHeaders(): Record<string, string> {
  return { 'x-github-request-id': requestId(), 'x-oauth-scopes': 'repo, read:org' };
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...baseHeaders(), ...headers });
  res.end(text);
}

export function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, ...baseHeaders(), ...headers });
  res.end(body);
}

export function notFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

export function errMessage(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

/** Read the whole request body (cap 16 MiB). Returns null on stream error. */
export function readBody(req: IncomingMessage, limit = 16 * 1024 * 1024): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    req.on('data', (c: Buffer) => {
      if (done) return;
      total += c.length;
      if (total > limit) {
        done = true;
        resolve(null);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!done) resolve(Buffer.concat(chunks));
    });
    req.on('error', () => {
      if (!done) resolve(null);
    });
  });
}

/** Parse a JSON body; on malformed JSON returns { error: true }. Empty body => {}. */
export function parseJsonBody(buf: Buffer): { value: unknown; error: boolean } {
  const text = buf.toString('utf8').trim();
  if (text === '') return { value: {}, error: false };
  try {
    return { value: JSON.parse(text), error: false };
  } catch {
    return { value: null, error: true };
  }
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

export function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

/** Bearer token from the request, or null. */
export function bearerToken(req: IncomingMessage): string | null {
  const h = req.headers.authorization;
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/.exec(h.trim());
  return m ? m[1]!.trim() : null;
}

const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

/** True when the request carries the env's bearer token (any bearer when unset). */
export function isAuthed(req: IncomingMessage): boolean {
  const token = bearerToken(req);
  if (token === null) return false;
  if (EXPECTED_TOKEN === '') return true;
  return token === EXPECTED_TOKEN;
}

/** Pagination: slice `items` by page/per_page and build a GitHub-style Link header. */
export function paginate<T>(items: T[], query: URLSearchParams, baseUrl: string, path: string): { page: T[]; link: string | null } {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30;
  const pageRaw = Number(query.get('page') ?? '1');
  const pageNum = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (pageNum - 1) * perPage;
  const page = items.slice(start, start + perPage);
  const urlFor = (p: number): string => {
    const q = new URLSearchParams(query);
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    return `${baseUrl}${path}?${q.toString()}`;
  };
  const links: string[] = [];
  if (pageNum < totalPages) links.push(`<${urlFor(pageNum + 1)}>; rel="next"`);
  if (pageNum > 1) links.push(`<${urlFor(pageNum - 1)}>; rel="prev"`);
  links.push(`<${urlFor(1)}>; rel="first"`);
  links.push(`<${urlFor(totalPages)}>; rel="last"`);
  return { page, link: links.length > 0 ? links.join(', ') : null };
}

/** Absolute base URL of this request (scheme/host from headers, loopback fallback). */
export function requestBase(req: IncomingMessage): string {
  const host = req.headers.host ?? 'localhost';
  return `http://${host}`;
}

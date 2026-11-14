// HTTP router: healthz, API root, REST v3, GraphQL v4, MCP, git smart HTTP, JSON 404.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Store } from './store.ts';
import { sendJson, notFound, pathOf } from './util.ts';
import { handleRest } from './rest.ts';
import { handleGraphQL } from './graphql.ts';
import { handleMcp } from './mcp.ts';
import { handleGit } from './git.ts';

export function createApp(): Server {
  const store = new Store();
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const path = pathOf(req);
      const method = req.method ?? 'GET';

      // Boot probe: no auth.
      if (method === 'GET' && path === '/healthz') {
        sendJson(res, 200, { ok: true });
        return;
      }

      // API root: 200 with the token's scopes.
      if (method === 'GET' && (path === '/api/v3' || path === '/api/v3/')) {
        sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
        return;
      }

      // GraphQL v4.
      if (path === '/api/graphql') {
        if (await handleGraphQL(req, res, store)) return;
        notFound(res);
        return;
      }

      // MCP.
      if (path === '/mcp') {
        if (await handleMcp(req, res, store)) return;
        notFound(res);
        return;
      }

      // REST v3.
      if (path === '/api/v3' || path.startsWith('/api/v3/')) {
        const segments = path.split('/').filter((s) => s !== '');
        // segments[0] is 'api', segments[1] is 'v3'
        if (await handleRest(req, res, store, segments.slice(2))) return;
        notFound(res);
        return;
      }

      // Git smart HTTP: /<owner>/<repo>.git/...
      const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
      if (gitMatch) {
        if (await handleGit(req, res, store, gitMatch[1]!, gitMatch[2]!, gitMatch[3] ?? '/')) return;
        notFound(res);
        return;
      }

      notFound(res);
    } catch (err) {
      // Never leak a stack or HTML: a JSON 500.
      try {
        sendJson(res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
      } catch {
        // Response already gone; nothing more to do.
      }
    }
  });
}

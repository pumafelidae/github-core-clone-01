// The HTTP router. One Forge per process; every request is tried against the modules in order
// (healthz, GraphQL, MCP, REST, git) and falls through to a JSON 404 when nothing matches.

import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { Forge } from './store.ts';
import { handleRest } from './rest.ts';
import { handleGraphQL } from './graphql.ts';
import { handleMcp } from './mcp.ts';
import { handleGit } from './git.ts';
import { pathOf, queryOf, sendJson, sendNotFound } from './util.ts';

/** Create the server (not yet listening). main.ts binds it to an ephemeral port. */
export function createApp(): Server {
  const forge = new Forge();
  return createServer((req, res) => {
    void dispatch(req, res, forge);
  });
}

async function dispatch(req: IncomingMessage, res: ServerResponse, forge: Forge): Promise<void> {
  try {
    const path = pathOf(req);
    const method = (req.method ?? 'GET').toUpperCase();
    const query = queryOf(req);

    // The harness's readiness probe: no auth, plain "ok".
    if (method === 'GET' && path === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }

    if (method === 'POST' && path === '/api/graphql') {
      if (await handleGraphQL(req, res, forge)) return;
    }

    if (method === 'POST' && path === '/mcp') {
      if (await handleMcp(req, res, forge)) return;
    }

    if (path === '/api/v3' || path.startsWith('/api/v3/')) {
      if (await handleRest(req, res, forge, path, method, query)) return;
    }

    if (/^\/[^/]+\/[^/]+\.git\//.test(path)) {
      if (await handleGit(req, res, forge, path, method)) return;
    }

    sendNotFound(res, 'Not Found');
  } catch (err) {
    process.stderr.write(`[entry] ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    if (!res.headersSent) {
      sendJson(res, 500, { message: 'Internal Server Error' });
    } else {
      res.destroy();
    }
  }
}

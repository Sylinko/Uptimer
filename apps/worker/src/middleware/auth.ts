import { createMiddleware } from 'hono/factory';

import type { Env } from '../env';
import { AppError } from './errors';

function readBearerToken(authHeader: string | undefined | null): string | null {
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}

/** Constant-time string comparison to prevent timing attacks. */
function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBuf = encoder.encode(a);
  const bBuf = encoder.encode(b);
  if (aBuf.byteLength !== bBuf.byteLength) return false;
  let result = 0;
  for (let i = 0; i < aBuf.length; i++) {
    result |= aBuf[i]! ^ bBuf[i]!;
  }
  return result === 0;
}

export function hasValidAdminTokenRequest(input: {
  env: Pick<Env, 'ADMIN_TOKEN'>;
  req: { header(name: string): string | undefined };
}): boolean {
  const token = input.env.ADMIN_TOKEN;
  if (!token) return false;
  const provided = readBearerToken(input.req.header('authorization'));
  if (!provided) return false;
  return timingSafeEqual(provided, token);
}

export const requireAdmin = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  const token = c.env.ADMIN_TOKEN;
  if (!token) {
    throw new AppError(500, 'INTERNAL', 'Admin token not configured');
  }

  if (!hasValidAdminTokenRequest(c)) {
    throw new AppError(401, 'UNAUTHORIZED', 'Unauthorized');
  }

  await next();
});

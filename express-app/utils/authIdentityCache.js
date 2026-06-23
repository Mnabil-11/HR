/**
 * Auth identity cache
 *
 * The `authenticate` middleware validates the caller against the database on EVERY
 * request (one `SELECT` per request, for every account type). On a scale-to-zero
 * Postgres that per-request round-trip is the single largest contributor to DB load
 * across the app.
 *
 * This wraps the identity lookup in a very short-lived in-memory cache so a warm
 * instance reuses the result for a few seconds instead of re-querying on every call.
 * Staleness is bounded two ways:
 *   1. A short TTL (default 30s, override with AUTH_IDENTITY_CACHE_TTL_MS).
 *   2. Explicit invalidation whenever an account is updated/deactivated
 *      (see users routes and the Branch model), so admin-driven changes apply at once.
 *
 * Keyed by role + id: a `branch_manager` token carries the branch id, which can
 * numerically collide with a `users` row id, so the role keeps the two namespaces apart.
 */
import { getCache, setCache, delCache } from './simpleCache.js';

const TTL_MS = parseInt(process.env.AUTH_IDENTITY_CACHE_TTL_MS || '30000', 10);

// All roles an id could be cached under — used for invalidation, which only knows the id.
const ROLES = ['main_manager', 'branch_operations_manager', 'branch_manager'];

const key = (role, id) => `auth:identity:${role || 'unknown'}:${id}`;

/** Returns the cached identity object, or null on miss/expiry. */
export function getIdentity(role, id) {
  if (id == null) return null;
  return getCache(key(role, id));
}

/** Cache a resolved (non-null) identity object for the short TTL. */
export function setIdentity(role, id, value) {
  if (id == null || !value) return;
  setCache(key(role, id), value, TTL_MS);
}

/** Drop any cached identity for an id across all roles (call after account mutations). */
export function invalidateIdentity(id) {
  if (id == null) return;
  for (const role of ROLES) {
    delCache(key(role, id));
  }
}

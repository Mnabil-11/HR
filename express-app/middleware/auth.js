/**
 * Authentication Middleware
 * JWT-based authentication
 */

import { verifyToken } from '../utils/jwt.js';
import sql from '../config/database.js';
import { log } from '../utils/logger.js';
import { attachRequestScope } from './requestScope.js';
import { withDbRetry } from '../utils/dbRetry.js';
import { getIdentity, setIdentity } from '../utils/authIdentityCache.js';

/**
 * Resolve the caller's identity row from the database.
 * Users live in the `users` table; branch managers live in `branches`.
 * Returns the identity object or null (not found). Throws on DB/connection errors.
 */
async function loadIdentityFromDb(decoded) {
  const [dbUser] = await sql`
    SELECT id, username, role, branch_id, is_active
    FROM users
    WHERE id = ${decoded.id}
  `;
  if (dbUser) return dbUser;

  // Branch managers are stored in the branches table, not users
  if (decoded.role === 'branch_manager') {
    const [branch] = await sql`
      SELECT id, username, is_active
      FROM branches
      WHERE id = ${decoded.id}
    `;
    if (branch) {
      return { id: branch.id, username: branch.username, role: 'branch_manager', branch_id: branch.id, is_active: branch.is_active };
    }
  }

  return null;
}

/**
 * Authenticate user via JWT token
 * Sets req.user with decoded token data
 * Validates user exists in database (even if inactive)
 */
export const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      log.warn('Authentication failed: No Bearer token provided', { path: req.path });
      return res.status(401).json({
        success: false,
        message: 'Authentication required. Please provide a Bearer token.'
      });
    }

    const token = authHeader.replace('Bearer ', '');

    // Verify token
    const decoded = verifyToken(token);

    // Validate the caller still exists (even if inactive).
    // Served from a short-lived per-instance cache to avoid a DB round-trip on every
    // request; a transient connection failure (common on cold start) is retried before
    // we give up. Cache is invalidated when an account is updated/deactivated.
    let user = getIdentity(decoded.role, decoded.id);
    if (!user) {
      try {
        user = await withDbRetry(() => loadIdentityFromDb(decoded), { label: 'auth-identity' });
      } catch (identityError) {
        log.error('Error checking identity during authentication', {
          error: identityError.message,
          actor_id: decoded.id
        });
        // DB unreachable — cannot verify identity, reject safely
        return res.status(503).json({
          success: false,
          message: 'Service temporarily unavailable. Please try again.'
        });
      }
      if (user) {
        setIdentity(decoded.role, decoded.id, user);
      }
    }

    if (!user) {
      log.warn('Authentication failed: User no longer exists in database', { user_id: decoded.id });
      return res.status(401).json({
        success: false,
        message: 'User account not found. Please login again.'
      });
    }

    // Attach user info to request
    // existsInDb reflects whether this actor has a row in the users table.
    // Branch managers are stored in branches, not users — so their ID cannot
    // be used as a FK referencing users(id).
    req.user = {
      id: decoded.id,
      username: decoded.username,
      role: decoded.role,
      branch_id: decoded.branch_id,
      existsInDb: decoded.role !== 'branch_manager'
    };

    await attachRequestScope(req);

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      log.warn('Authentication failed: Token expired', { path: req.path });
      return res.status(401).json({
        success: false,
        message: 'Token has expired. Please login again.'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      log.warn('Authentication failed: Invalid token', { path: req.path });
      return res.status(401).json({
        success: false,
        message: 'Invalid token. Please login again.'
      });
    }

    log.error('Authentication failed', { error: error.message, path: req.path, stack: error.stack });
    return res.status(401).json({
      success: false,
      message: 'Authentication failed',
      error: error.message
    });
  }
};

/**
 * Optional authentication - doesn't fail if no token
 * Sets req.user if valid token is provided
 */
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.replace('Bearer ', '');

      try {
        const decoded = verifyToken(token);
        req.user = {
          id: decoded.id,
          username: decoded.username,
          role: decoded.role,
          branch_id: decoded.branch_id
        };
      } catch (error) {
        // Invalid token, but continue without user (optional auth)
      }
    }

    await attachRequestScope(req);

    next();
  } catch (error) {
    // Continue even if there's an error (optional auth)
    next();
  }
};


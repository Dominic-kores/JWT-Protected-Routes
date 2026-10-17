
import jwt from "jsonwebtoken";

import { verifyToken } from "../utils/tokens.js";
import { tokenBlacklist } from "../utils/tokenStore.js";

// ======================================================
// TASK 2: JWT AUTHENTICATION MIDDLEWARE
// ======================================================

// This function is placed before protected routes.
// It allows only requests with valid JWT access tokens.
export function authenticateToken(req, res, next) {
  // STEP 1: Read the Authorization header.
  const authHeader = req.headers.authorization;

  // Expected format: Authorization: Bearer <token>
  if (
    !authHeader ||
    !/^Bearer\s+\S+$/i.test(authHeader)
  ) {
    return res.status(401).json({
      error: "Access denied. No token provided.",
    });
  }

  // STEP 2: Extract the JWT string.
  const token = authHeader.split(/\s+/)[1];

  // STEP 3: Check the token blacklist (bonus).
  // Revoked access tokens must not be accepted.
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({
      error: "Token has been revoked.",
    });
  }

  try {
    // STEP 4: Verify JWT signature and expiration.
    const decoded = verifyToken(token);

    // STEP 5: Save the decoded payload on req.user.
    // Later route handlers can access req.user.userId.
    req.user = decoded;

    // Save the token for optional logout handling.
    req.token = token;

    // STEP 6: Continue to the protected route.
    next();
  } catch (error) {
    // An expired token has a specific JWT error type.
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({
        error: "Token has expired. Please log in again.",
      });
    }

    // All other invalid tokens return a generic error.
    return res.status(401).json({
      error: "Invalid token.",
    });
  }
}

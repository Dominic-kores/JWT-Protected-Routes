

import { randomUUID } from "node:crypto";

import jwt from "jsonwebtoken";
import { createHmac } from "node:crypto";

// ======================================================
// JWT TOKEN UTILITIES
// ======================================================

// Read the JWT secret from environment variables.
const JWT_SECRET = process.env.JWT_SECRET;

// Stop the application if the secret is missing.
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error(
    "JWT_SECRET must contain at least 32 characters."
  );
}

// Use a distinct derived key for refresh tokens.
// This prevents access tokens from being accepted
// as refresh tokens.
const REFRESH_SECRET = createHmac(
  "sha256",
  JWT_SECRET
)
  .update("refresh-token-signing-key-v1")
  .digest("hex");

// ------------------------------------------------------
// TASK 1: GENERATE ACCESS TOKEN
// ------------------------------------------------------

// Create a signed token containing the user's identity.
export function generateToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role || "user",
    },
    JWT_SECRET,
    {
      expiresIn: "24h",
      algorithm: "HS256",
    }
  );
}

// ------------------------------------------------------
// VERIFY ACCESS TOKEN
// ------------------------------------------------------

// Verify both the token's signature and expiration.
export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256"],
  });
}

// ------------------------------------------------------
// BONUS: SHORT-LIVED ACCESS TOKEN
// ------------------------------------------------------

// The bonus specifies a 15-minute access token.
export function generateShortAccessToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role || "user",
    },
    JWT_SECRET,
    {
      expiresIn: "15m",
      algorithm: "HS256",
    }
  );
}

// ------------------------------------------------------
// BONUS: REFRESH TOKEN GENERATION
// ------------------------------------------------------

// Refresh tokens last for seven days and contain
// only the information needed for identifying the user.

// Create a unique seven-day refresh token.
export function generateRefreshToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      tokenType: "refresh",
    },
    REFRESH_SECRET,
    {
      expiresIn: "7d",
      algorithm: "HS256",

      // A fresh identifier prevents token reuse
      // during refresh-token rotation.
      jwtid: randomUUID(),
    }
  );
}


// Verify that the supplied token is a refresh token.
export function verifyRefreshToken(token) {
  const decoded = jwt.verify(token, REFRESH_SECRET, {
    algorithms: ["HS256"],
  });

  if (decoded.tokenType !== "refresh") {
    throw new jwt.JsonWebTokenError(
      "Invalid refresh token type"
    );
  }

  return decoded;
}

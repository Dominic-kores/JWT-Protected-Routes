
// ======================================================
// BONUS: IN-MEMORY TOKEN REVOCATION STORAGE
// ======================================================

// Tokens added to this Set can no longer be used.
export const tokenBlacklist = new Set();

// Track active refresh tokens for rotation and logout.
export const activeRefreshTokens = new Set();

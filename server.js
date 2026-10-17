
import "dotenv/config";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { authenticateToken } from "./middleware/auth.js";

import {
  generateToken,
  generateShortAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  verifyToken,
} from "./utils/tokens.js";

import {
  tokenBlacklist,
  activeRefreshTokens,
} from "./utils/tokenStore.js";

// ======================================================
// WEEK 7 - DAY 2: JWT AUTHENTICATION PROJECT
// ======================================================

// Initialize Express.
const app = express();

// Server settings.
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Parse JSON request bodies.
app.use(express.json());

// ======================================================
// SECTION 1: IN-MEMORY DATABASE
// ======================================================

// Store users without needing an external database.
const users = [];

// Automatically assign numeric user IDs.
let nextUserId = 1;

// ======================================================
// SECTION 2: HELPER FUNCTIONS
// ======================================================

// Normalize email addresses for case-insensitive lookup.
function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// Validate basic email format.
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Validate password strength from Day 1.
function isValidPassword(password) {
  return (
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password)
  );
}

// Return user information without password hashes.
function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };
}

// Issue short-lived access and refresh tokens.
// This implements the optional bonus challenge.
function issueAuthTokens(user) {
  const accessToken = generateShortAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // Keep refresh tokens in the current server memory.
  activeRefreshTokens.add(refreshToken);

  return { accessToken, refreshToken };
}

// ======================================================
// SECTION 3: SERVER STATUS ROUTE
// ======================================================

app.get("/", (req, res) => {
  res.status(200).json({
    message: "JWT Authentication API is running",
    endpoints: {
      register: "POST /api/auth/register",
      login: "POST /api/auth/login",
      profile: "GET /api/profile",
      testToken: "GET /api/test-token",
      refresh: "POST /api/auth/refresh",
      logout: "POST /api/auth/logout",
    },
  });
});

// ======================================================
// SECTION 4: USER REGISTRATION
// POST /api/auth/register
// ======================================================

app.post("/api/auth/register", async (req, res) => {
  try {
    // Read input supplied by the client.
    const { name, email, password } = req.body ?? {};

    // Validate the required input types.
    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Name, email and password are required.",
      });
    }

    const cleanName = name.trim();
    const cleanEmail = normalizeEmail(email);

    // Check user's name.
    if (cleanName.length < 2) {
      return res.status(400).json({
        error: "Name must have at least 2 characters.",
      });
    }

    // Check email format.
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({
        error: "Invalid email address.",
      });
    }

    // Validate the password.
    if (!isValidPassword(password)) {
      return res.status(400).json({
        error:
          "Password must have at least 8 characters, one uppercase letter and one number.",
      });
    }

    // Prevent duplicate email registration.
    const existingUser = users.find(
      (user) => user.email === cleanEmail
    );

    if (existingUser) {
      return res.status(409).json({
        error: "Email already registered.",
      });
    }

    // Hash the password before saving it.
    const passwordHash = await bcrypt.hash(
      password,
      SALT_ROUNDS
    );

    // Store a new user with the default "user" role.
    // Never accept a privileged role from the request.
    const newUser = {
      id: nextUserId++,
      name: cleanName,
      email: cleanEmail,
      passwordHash,
      role: "user",
    };

    users.push(newUser);

    // Create tokens immediately after registration.
    const { accessToken, refreshToken } =
      issueAuthTokens(newUser);

    // Return access token, refresh token and safe user.
    return res.status(201).json({
      message: "User registered successfully.",
      token: accessToken,
      refreshToken,
      user: safeUser(newUser),
    });
  } catch (error) {
    console.error("Registration error:", error.message);

    return res.status(500).json({
      error: "Internal server error.",
    });
  }
});

// ======================================================
// SECTION 5: USER LOGIN
// POST /api/auth/login
// ======================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    // Check required fields.
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    // Find registered user.
    const cleanEmail = normalizeEmail(email);

    const user = users.find(
      (item) => item.email === cleanEmail
    );

    // The same generic message is used whether
    // the email does not exist or password is wrong.
    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    // Verify supplied password against stored hash.
    const isMatch = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!isMatch) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    // Create new JWT tokens.
    const { accessToken, refreshToken } =
      issueAuthTokens(user);

    // Return authentication success.
    return res.status(200).json({
      message: "Login successful.",
      token: accessToken,
      refreshToken,
      user: safeUser(user),
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Internal server error.",
    });
  }
});

// ======================================================
// SECTION 6: PROTECTED PROFILE ROUTE
// GET /api/profile
// ======================================================

// authenticateToken runs before the route handler.
app.get("/api/profile", authenticateToken, (req, res) => {
  // Retrieve the user using the verified JWT payload.
  const user = users.find(
    (item) => item.id === req.user.userId
  );

  if (!user) {
    return res.status(404).json({
      error: "User not found.",
    });
  }

  // Return the authenticated user's public profile.
  return res.status(200).json({
    user: safeUser(user),
  });
});

// ======================================================
// SECTION 7: JWT TEST ROUTE
// GET /api/test-token
// ======================================================

// Useful for demonstrating Task 1 from the API.
app.get("/api/test-token", (req, res) => {
  const sampleUser = {
    id: 1,
    email: "wanjiku@mail.com",
    role: "user",
  };

  // Generate the standard 24-hour JWT.
  const token = generateToken(sampleUser);

  // Verify and decode the generated token.
  const decoded = verifyToken(token);

  return res.status(200).json({
    message: "JWT generated and verified successfully.",
    token,
    decoded,
  });
});

// ======================================================
// SECTION 8: BONUS - REFRESH TOKENS
// POST /api/auth/refresh
// ======================================================

app.post("/api/auth/refresh", (req, res) => {
  const { refreshToken } = req.body ?? {};

  // Confirm refresh token is supplied.
  if (
    typeof refreshToken !== "string" ||
    !refreshToken
  ) {
    return res.status(400).json({
      error: "Refresh token is required.",
    });
  }

  // Reject any revoked or previously rotated token.
  if (!activeRefreshTokens.has(refreshToken)) {
    return res.status(401).json({
      error: "Invalid or revoked refresh token.",
    });
  }

  try {
    // Check the refresh token's signature and expiry.
    const decoded = verifyRefreshToken(refreshToken);

    // Find the user attached to this refresh token.
    const user = users.find(
      (item) => item.id === decoded.userId
    );

    if (!user) {
      return res.status(401).json({
        error: "Invalid refresh token.",
      });
    }

    // Rotate refresh tokens: invalidate the old one.
    activeRefreshTokens.delete(refreshToken);

    // Generate a new access token.
    const accessToken = generateShortAccessToken(user);

    // Generate a new refresh token.
    const newRefreshToken = generateRefreshToken(user);

    activeRefreshTokens.add(newRefreshToken);

    return res.status(200).json({
      message: "Token refreshed successfully.",
      token: accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    // Remove expired or otherwise unusable tokens.
    activeRefreshTokens.delete(refreshToken);

    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({
        error: "Refresh token has expired.",
      });
    }

    return res.status(401).json({
      error: "Invalid refresh token.",
    });
  }
});

// ======================================================
// SECTION 9: BONUS - LOGOUT
// POST /api/auth/logout
// ======================================================

// Users must present a valid access token to log out.
app.post(
  "/api/auth/logout",
  authenticateToken,
  (req, res) => {
    const { refreshToken } = req.body ?? {};

    // Optional refresh token must be valid and belong
    // to the same account as the access token.
    if (refreshToken !== undefined) {
      if (
        typeof refreshToken !== "string" ||
        !activeRefreshTokens.has(refreshToken)
      ) {
        return res.status(400).json({
          error: "Invalid refresh token.",
        });
      }

      try {
        const decoded = verifyRefreshToken(refreshToken);

        if (decoded.userId !== req.user.userId) {
          return res.status(403).json({
            error: "Refresh token belongs to another user.",
          });
        }
      } catch {
        return res.status(400).json({
          error: "Invalid refresh token.",
        });
      }
    }

    // Add current access token to blacklist.
    tokenBlacklist.add(req.token);

    // Revoke refresh token, when provided.
    if (refreshToken) {
      activeRefreshTokens.delete(refreshToken);
    }

    return res.status(200).json({
      message: "Logged out successfully.",
    });
  }
);

// ======================================================
// SECTION 10: UNKNOWN ROUTES
// ======================================================

app.use((req, res) => {
  return res.status(404).json({
    error: "Route not found.",
  });
});

// ======================================================
// SECTION 11: START SERVER
// ======================================================

app.listen(PORT, () => {
  console.log("===================================");
  console.log(" JWT AUTHENTICATION API");
  console.log("===================================");
  console.log(`Server: http://localhost:${PORT}`);
  console.log("POST /api/auth/register");
  console.log("POST /api/auth/login");
  console.log("GET  /api/profile");
  console.log("GET  /api/test-token");
  console.log("POST /api/auth/refresh");
  console.log("POST /api/auth/logout");
  console.log("===================================");
});

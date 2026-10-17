
import "dotenv/config";
import jwt from "jsonwebtoken";

import {
  generateToken,
  verifyToken,
} from "./utils/tokens.js";

// ======================================================
// TASK 1: JWT GENERATION AND VERIFICATION DEMO
// ======================================================

// Sample user data for the demonstration.
const sampleUser = {
  id: 1,
  email: "wanjiku@mail.com",
  role: "user",
};

// Small helper to pause execution for a given duration.
function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// Execute all JWT demonstration tests.
async function runJwtTests() {
  console.log("\n=================================");
  console.log(" JWT GENERATION & VERIFICATION");
  console.log("=================================\n");

  // --------------------------------------------------
  // TEST 1: VALID JWT TOKEN
  // --------------------------------------------------

  console.log("--- Test 1: Valid Token ---");

  // Generate an access token that expires in 24 hours.
  const validToken = generateToken(sampleUser);

  console.log("Token:", validToken);

  // Verify the token and inspect its payload.
  const decoded = verifyToken(validToken);

  console.log("Decoded:", decoded);
  console.log("Verification successful!\n");

  // --------------------------------------------------
  // TEST 2: EXPIRED JWT TOKEN
  // --------------------------------------------------

  console.log("--- Test 2: Expired Token ---");

  // Generate a temporary token lasting one second.
  const expiredToken = jwt.sign(
    {
      userId: sampleUser.id,
      email: sampleUser.email,
      role: sampleUser.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "1s",
      algorithm: "HS256",
    }
  );

  // Wait until the token has expired.
  await sleep(2200);

  try {
    jwt.verify(
      expiredToken,
      process.env.JWT_SECRET,
      { algorithms: ["HS256"] }
    );
  } catch (error) {
    console.log(
      `Error: ${error.name} - ${error.message}\n`
    );
  }

  // --------------------------------------------------
  // TEST 3: TAMPERED JWT TOKEN
  // --------------------------------------------------

  console.log("--- Test 3: Tampered Token ---");

  // JWT format: header.payload.signature
  const tokenParts = validToken.split(".");

  // Modify the payload while preserving the old
  // signature so that signature verification fails.
  const originalPayload = JSON.parse(
    Buffer.from(tokenParts[1], "base64url").toString(
      "utf8"
    )
  );

  // Change a signed claim without re-signing.
  const modifiedPayload = {
    ...originalPayload,
    role: "admin",
  };

  tokenParts[1] = Buffer.from(
    JSON.stringify(modifiedPayload)
  ).toString("base64url");

  const tamperedToken = tokenParts.join(".");

  try {
    verifyToken(tamperedToken);
  } catch (error) {
    console.log(
      `Error: ${error.name} - ${error.message}`
    );
  }

  console.log("\nJWT tests completed!\n");
}

// Run the tests and report unexpected failures.
runJwtTests().catch((error) => {
  console.error("JWT demonstration failed:", error);
  process.exitCode = 1;
});

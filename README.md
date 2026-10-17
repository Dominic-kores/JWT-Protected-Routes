
# JWT Authentication & Protected Routes API

A secure REST API developed with Node.js and Express,
demonstrating JSON Web Token (JWT) authentication,
token verification, protected routes, refresh tokens,
and logout functionality.

## Project Overview

This project builds on the password-hashing concepts
covered in the previous assignment.

It demonstrates how JWTs can be generated, verified
and used to authenticate users when accessing
protected REST API endpoints.

The API includes bcrypt password hashing, authentication
middleware, JWT expiration handling and optional token
refresh and revocation features.

## Project Objectives

1. Understand the structure and purpose of JWTs.
2. Generate signed JWTs using jsonwebtoken.
3. Securely store JWT secrets in environment variables.
4. Verify valid, expired and tampered tokens.
5. Implement reusable authentication middleware.
6. Extract JWTs from Bearer Authorization headers.
7. Protect routes from unauthorized access.
8. Implement registration and login endpoints.
9. Authenticate users using bcrypt.
10. Implement token refresh and logout functionality.


## Live Pages
[https://dominic-kores.github.io/JWT-Protected-Routes/]

## Technologies Used

- JavaScript (ES Modules)
- Node.js
- Express.js
- jsonwebtoken
- bcryptjs
- dotenv
- REST API
- Thunder Client / curl
- Git and GitHub

## Project Structure

week-7-day-2-jwt-auth/
├── middleware/
│   └── auth.js
├── utils/
│   ├── tokens.js
│   └── tokenStore.js
├── server.js
├── jwt-demo.js
├── package.json
├── package-lock.json
├── .env
├── .env.example
├── .gitignore
└── README.md


## Running the Application

Run the JWT demonstration:

    npm run jwt

Start the development server:

    npm run dev

Or start normally:

    npm start

The API runs at:

    http://localhost:3000

## Task 1: JWT Generation and Verification

File: jwt-demo.js

Features:

- Generate JWTs containing userId, email and role.
- Sign standard tokens using a secret from .env.
- Set token expiry to 24 hours.
- Verify valid JWT signatures.
- Detect expired tokens.
- Detect tampered tokens.

### Expected Results

Valid Token:
- Token verification succeeds.
- Decoded payload is displayed.

Expired Token:
- TokenExpiredError: jwt expired

Tampered Token:
- JsonWebTokenError: invalid signature

## Task 2: Authentication Middleware

File: middleware/auth.js

The middleware:

- Reads the Authorization header.
- Extracts the Bearer token.
- Verifies the JWT signature and expiry.
- Attaches decoded user information to req.user.
- Rejects missing, invalid and expired tokens.
- Checks revoked tokens against a blacklist.

## Task 3: Authentication Endpoints

### POST /api/auth/register

Creates a user, hashes their password and returns
their public details with authentication tokens.

Success: HTTP 201

### POST /api/auth/login

Authenticates an existing user using bcrypt.compare().

Success: HTTP 200

Invalid credentials: HTTP 401

### GET /api/profile

A protected endpoint that returns the authenticated
user's public profile information.

Valid token: HTTP 200

Missing or invalid token: HTTP 401

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Health check |
| GET | /api/test-token | JWT demonstration |
| POST | /api/auth/register | User registration |
| POST | /api/auth/login | User login |
| GET | /api/profile | Protected profile |
| POST | /api/auth/refresh | Refresh access token |
| POST | /api/auth/logout | Revoke tokens |

## Bonus Features

### Token Refresh

The bonus-enabled authentication endpoints issue:

- Access token: expires after 15 minutes.
- Refresh token: expires after 7 days.

POST /api/auth/refresh accepts a valid refresh token,
verifies it and returns new tokens.

The previous refresh token is revoked when rotated.

### Logout

POST /api/auth/logout requires a valid access token.

The current access token is added to an in-memory
blacklist.

A supplied matching refresh token is revoked.

Protected routes reject revoked tokens.

## HTTP Response Codes

| Code | Meaning |
|------|---------|
| 200 | Successful request |
| 201 | User created |
| 400 | Invalid input |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Resource not found |
| 409 | Duplicate email |
| 500 | Server error |

## Testing

Use Thunder Client, or curl.

Recommended tests:

1. Generate and verify a valid JWT.
2. Verify an expired JWT.
3. Detect a tampered JWT.
4. Register a valid user.
5. Log in with correct credentials.
6. Log in with incorrect credentials.
7. Access a protected route without a token.
8. Access a protected route using an invalid token.
9. Access a protected route using a valid token.
10. Refresh an access token.
11. Attempt to reuse a rotated refresh token.
12. Log out and verify token revocation.


## Security Features

- bcrypt password hashing.
- JWT signature verification.
- Token expiration handling.
- Environment-based JWT signing secrets.
- Protected routes with authentication middleware.
- Generic invalid-credential responses.
- No password hashes returned in API responses.
- Refresh-token rotation.
- In-memory token revocation.


## Learning Outcomes

Through this project, I developed practical knowledge
of JWT-based authentication, token signing, verification,
authorization middleware and protected REST APIs.

The assignment also strengthened my understanding of
server-side security, API testing and session management.





## Author

**Dominic Kores Kisioya**

Full-Stack Software & AI Engineer



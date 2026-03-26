/**
 * ============================================================================
 * OAUTH 2.0 AUTHENTICATION (Google OAuth2 with Passport.js)
 * ============================================================================
 *
 * What is OAuth 2.0?
 * ------------------
 * OAuth 2.0 (RFC 6749) is an authorization framework that allows third-party
 * applications to obtain limited access to a user's resources on another
 * service (e.g., Google, GitHub, Facebook) WITHOUT exposing the user's
 * credentials to the third-party app.
 *
 * How the Authorization Code flow works (used here):
 * 1. User clicks "Login with Google" on your app.
 * 2. Your app redirects the user to Google's authorization server with:
 *    - client_id (identifies your app)
 *    - redirect_uri (where Google sends the user back)
 *    - scope (what data you're requesting, e.g., profile, email)
 *    - response_type=code (requesting an authorization code)
 * 3. User logs into Google and consents to sharing their data.
 * 4. Google redirects back to your redirect_uri with an authorization code.
 * 5. Your server exchanges the authorization code for an access token by
 *    calling Google's token endpoint with the code + client_secret.
 * 6. Your server uses the access token to fetch user data from Google's API.
 * 7. Your server creates a local session for the user.
 *
 * Key OAuth 2.0 concepts:
 * - Resource Owner: The user who owns the data (e.g., Google account holder)
 * - Client: Your application requesting access
 * - Authorization Server: Google's auth server that issues tokens
 * - Resource Server: Google's API that holds user data
 * - Authorization Code: Short-lived code exchanged for access token
 * - Access Token: Token used to access the resource server
 * - Scope: Limits what the access token can do
 *
 * Passport.js:
 * - A popular Node.js authentication middleware.
 * - Supports 500+ "strategies" (Google, Facebook, GitHub, etc.)
 * - Handles the OAuth dance, token exchange, and profile parsing.
 *
 * Setup required:
 * 1. Go to https://console.cloud.google.com/
 * 2. Create a project and enable the Google+ API.
 * 3. Create OAuth 2.0 credentials (Web application).
 * 4. Set authorized redirect URI to http://localhost:3004/auth/google/callback
 * 5. Copy Client ID and Client Secret to .env file.
 *
 * Run: npm run oauth2
 * ============================================================================
 */

require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = 3004;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const CALLBACK_URL = process.env.CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'oauth2-demo-secret-change-in-production';

// ---------------------------------------------------------------------------
// In-memory user store
// In production, use a database. This maps Google profile ID to user data.
// ---------------------------------------------------------------------------
const userStore = new Map();

// ---------------------------------------------------------------------------
// Passport Configuration
// ---------------------------------------------------------------------------

/**
 * Serialize user to session.
 * We only store the user ID in the session to keep the session small.
 * On each request, deserializeUser retrieves the full user from the store.
 */
passport.serializeUser((user, done) => {
  console.log(`[PASSPORT] Serializing user ${user.id} to session`);
  done(null, user.id);
});

/**
 * Deserialize user from session.
 * Retrieves the full user object from the store using the ID in the session.
 */
passport.deserializeUser((id, done) => {
  console.log(`[PASSPORT] Deserializing user ${id} from session`);
  const user = userStore.get(id);
  if (user) {
    done(null, user);
  } else {
    done(new Error('User not found'), null);
  }
});

/**
 * Google OAuth 2.0 Strategy.
 *
 * When Passport handles the callback from Google, it:
 * 1. Exchanges the authorization code for an access token.
 * 2. Uses the access token to fetch the user's Google profile.
 * 3. Calls this verify callback with the tokens and profile.
 * 4. We find or create the user in our store and return it.
 */
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      console.log('\n[OAUTH2] Google callback received');
      console.log(`[OAUTH2] Access Token: ${accessToken.substring(0, 20)}...`);
      console.log(`[OAUTH2] Profile ID: ${profile.id}`);
      console.log(`[OAUTH2] Display Name: ${profile.displayName}`);

      // Find or create user in our store
      let user = userStore.get(profile.id);

      if (user) {
        console.log(`[OAUTH2] Existing user found: ${user.displayName}`);
        // Update last login
        user.lastLogin = new Date().toISOString();
      } else {
        // Create new user from Google profile
        user = {
          id: profile.id,
          displayName: profile.displayName,
          email: profile.emails && profile.emails[0] ? profile.emails[0].value : 'N/A',
          photo: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
          provider: 'google',
          createdAt: new Date().toISOString(),
          lastLogin: new Date().toISOString(),
        };
        userStore.set(profile.id, user);
        console.log(`[OAUTH2] New user created: ${user.displayName}`);
      }

      // The second argument becomes req.user after serialization/deserialization
      return done(null, user);
    }
  )
);

// ---------------------------------------------------------------------------
// Middleware Setup
// ---------------------------------------------------------------------------

// Session middleware -- required for Passport to maintain login state
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true, // Prevents client-side JS from reading the cookie
      secure: false, // Set to true in production with HTTPS
    },
  })
);

// Initialize Passport and restore session
app.use(passport.initialize());
app.use(passport.session());

// ---------------------------------------------------------------------------
// Authentication check middleware
// ---------------------------------------------------------------------------
function isAuthenticated(req, res, next) {
  // req.isAuthenticated() is provided by Passport -- returns true if the
  // user has been serialized into the session
  if (req.isAuthenticated()) {
    console.log(`[AUTH] Authenticated user: ${req.user.displayName}`);
    return next();
  }
  console.log('[AUTH] Unauthenticated request, redirecting to login');
  res.status(401).json({
    error: 'Not authenticated',
    message: 'Please login via /auth/google',
    loginUrl: '/auth/google',
  });
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Home page with login info
app.get('/', (req, res) => {
  const isLoggedIn = req.isAuthenticated();
  res.json({
    message: 'Welcome to the OAuth 2.0 (Google) demo server',
    loggedIn: isLoggedIn,
    user: isLoggedIn ? req.user.displayName : null,
    endpoints: {
      'GET /auth/google': 'Start Google OAuth2 login flow',
      'GET /auth/google/callback': 'Google redirects here after consent',
      'GET /profile': 'View your profile (requires login)',
      'GET /logout': 'Logout and destroy session',
    },
    oauthFlow: [
      '1. Visit /auth/google',
      '2. You are redirected to Google login',
      '3. After consent, Google redirects to /auth/google/callback',
      '4. Server exchanges code for token and fetches your profile',
      '5. You are now logged in with a session cookie',
    ],
  });
});

/**
 * Step 1: Initiate Google OAuth2 login.
 *
 * passport.authenticate('google', { scope: [...] }) redirects the user
 * to Google's consent screen. The scope determines what data we request.
 *
 * Common scopes:
 * - 'profile': Basic profile info (name, photo)
 * - 'email': Email address
 * - 'openid': OpenID Connect identifier
 */
app.get(
  '/auth/google',
  (req, res, next) => {
    console.log('\n[OAUTH2] Starting Google OAuth2 flow');
    console.log('[OAUTH2] Redirecting user to Google consent screen...');
    next();
  },
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    // prompt: 'select_account', // Uncomment to force account selection
  })
);

/**
 * Step 2: Google redirects here after user consents.
 *
 * Google sends an authorization code to this URL. Passport's
 * authenticate middleware:
 * - Extracts the authorization code from the query string
 * - Exchanges it for an access token (POST to Google's token endpoint)
 * - Uses the access token to fetch the user's profile
 * - Calls the verify callback defined in the strategy
 * - Serializes the user into the session
 */
app.get(
  '/auth/google/callback',
  (req, res, next) => {
    console.log('\n[OAUTH2] Received callback from Google');
    console.log(`[OAUTH2] Authorization code: ${req.query.code ? req.query.code.substring(0, 20) + '...' : 'N/A'}`);
    next();
  },
  passport.authenticate('google', {
    failureRedirect: '/auth/failure',
  }),
  (req, res) => {
    console.log(`[OAUTH2] Login successful for: ${req.user.displayName}`);
    // After successful auth, redirect to profile
    res.redirect('/profile');
  }
);

// Auth failure handler
app.get('/auth/failure', (req, res) => {
  console.log('[OAUTH2] Authentication failed');
  res.status(401).json({
    error: 'Authentication failed',
    message: 'Google OAuth2 login failed. Please try again.',
    retryUrl: '/auth/google',
  });
});

/**
 * Profile route -- protected, requires Google login.
 * Displays the user information obtained from Google.
 */
app.get('/profile', isAuthenticated, (req, res) => {
  console.log(`[PROFILE] Displaying profile for ${req.user.displayName}`);
  res.json({
    message: 'Your profile (from Google OAuth2)',
    profile: {
      id: req.user.id,
      displayName: req.user.displayName,
      email: req.user.email,
      photo: req.user.photo,
      provider: req.user.provider,
      createdAt: req.user.createdAt,
      lastLogin: req.user.lastLogin,
    },
    session: {
      id: req.sessionID,
      cookie: {
        maxAge: req.session.cookie.maxAge,
        httpOnly: req.session.cookie.httpOnly,
      },
    },
  });
});

/**
 * Logout route.
 * Destroys the session and logs the user out of Passport.
 */
app.get('/logout', (req, res) => {
  const username = req.user ? req.user.displayName : 'Unknown';
  console.log(`\n[LOGOUT] Logging out user: ${username}`);

  req.logout((err) => {
    if (err) {
      console.error('[LOGOUT] Error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }

    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        console.error('[LOGOUT] Session destruction error:', err);
      }
      console.log('[LOGOUT] Session destroyed successfully');
      res.json({
        message: 'Logged out successfully',
        info: 'Your session has been destroyed',
        loginUrl: '/auth/google',
      });
    });
  });
});

// ---------------------------------------------------------------------------
// Error handling middleware
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`  OAuth2 (Google) Server running on port ${PORT}`);
  console.log(`========================================`);

  if (GOOGLE_CLIENT_ID === 'YOUR_GOOGLE_CLIENT_ID') {
    console.log(`\n  WARNING: Google OAuth2 credentials not configured!`);
    console.log(`  Copy .env.example to .env and add your credentials.`);
    console.log(`  See: https://console.cloud.google.com/`);
  }

  console.log(`\nTo login, visit:`);
  console.log(`  http://localhost:${PORT}/auth/google`);
  console.log(`\nEndpoints:`);
  console.log(`  GET /auth/google          - Start OAuth2 login`);
  console.log(`  GET /auth/google/callback  - OAuth2 callback`);
  console.log(`  GET /profile              - View profile (requires login)`);
  console.log(`  GET /logout               - Logout`);
});

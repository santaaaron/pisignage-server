'use strict';

const settingsController = require('./licenses'); // Controller to get settings/credentials
const crypto = require('crypto'); // Needed for session secret

// Middleware to check if the user is authenticated
exports.isAuthenticated = function(req, res, next) {
    // Log session and cookies for debugging subsequent requests
    console.log('isAuthenticated Check for:', req.originalUrl);
    console.log('  Headers Cookie:', req.headers.cookie);
    console.log('  Session Object:', req.session);
    // console.log('  Session User:', req.session ? req.session.user : 'N/A'); // More specific log

    if (req.session && req.session.user) {
        console.log('  Authenticated. Proceeding.');
        return next(); // User is authenticated, proceed
    } else {
        // Check if the request is for an API endpoint (Accepts JSON)
        // or if it's specifically an XHR request
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json'))) {
             // For API requests (XHR or accepts JSON), send 401 status
            console.log('  Unauthenticated API request. Sending 401.');
            res.status(401).json({ error: 'Unauthorized' });
        } else {
             // For regular browser requests, redirect to login page
            console.log('  Unauthenticated browser request. Redirecting to /login.');
            // Store the original URL they were trying to access
            req.session.returnTo = req.originalUrl;
            res.redirect('/login');
        }
    }
};

// Renders the login page
exports.renderLoginPage = function(req, res) {
    // If already logged in, redirect to home
    if (req.session && req.session.user) {
      return res.redirect('/');
    }
    res.render('login', { title: 'Login', error: req.query.error }); // Pass error query param to view
};

// Handles the login form submission
exports.login = function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    settingsController.getSettingsModel(function(err, settings) {
        if (err) {
            console.error("Error getting settings for login:", err);
            return res.redirect('/login?error=An error occurred.');
        }

        const authCreds = settings.authCredentials;

        // Check if credentials are set and match
        if (authCreds && authCreds.user && authCreds.password &&
            username === authCreds.user && password === authCreds.password) {

            console.log(`Login successful for user: ${username}. Regenerating session.`);
            // Credentials match, create session
            req.session.regenerate(function(err) {
                if (err) {
                    console.error("Error regenerating session:", err);
                    return res.redirect('/login?error=Session error.');
                }
                console.log(`  Session regenerated. New Session ID: ${req.sessionID}`);
                req.session.user = username; // Store username in session

                // Log the session object right after setting the user
                console.log('  Session object after setting user:', req.session);

                // Explicitly save the session before redirecting (helps ensure data is written)
                req.session.save(function(saveErr) {
                    if (saveErr) {
                        console.error("Error saving session:", saveErr);
                        return res.redirect('/login?error=Session save error.');
                    }
                    console.log('  Session saved. Redirecting...');
                    // Redirect to the original requested URL or home
                    const returnTo = req.session.returnTo || '/';
                    delete req.session.returnTo; // Clear the stored URL
                    res.redirect(returnTo);
                });
            });
        } else {
            console.log(`Login failed for user: ${username}. Invalid credentials.`);
            // Credentials don't match or aren't set
            res.redirect('/login?error=Invalid credentials.');
        }
    });
};

// Handles logout
exports.logout = function(req, res) {
    req.session.destroy(function(err) {
        if(err) {
            console.error("Error destroying session:", err);
        }
        res.redirect('/login'); // Redirect to login page after logout
    });
};

// Function to generate a secure random secret for the session
exports.generateSessionSecret = function() {
    return crypto.randomBytes(64).toString('hex');
}; 
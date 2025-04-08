'use strict';

var express = require('express'),
    path = require('path'),
    fs = require('fs'),
    config = require('./config'),
    serveIndex = require('serve-index');

var favicon = require('serve-favicon'),             //express middleware
    errorHandler = require('errorhandler'),
    logger = require('morgan'),
    methodOverride = require('method-override'),
    bodyParser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    session = require('express-session');

const authController = require('../app/controllers/auth');

//CORS middleware  , add more controls for security like site names, timeout etc.
var allowCrossDomain = function (req, res, next) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Vary', "Origin");   //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
    res.header('Access-Control-Expose-Headers', 'Content-Length');
    res.header('Access-Control-Allow-Methods', 'HEAD,GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Content-Length,Response-Type, X-Requested-With,origin,accept,Authorization,x-access-token,Last-Modified');

    if (req.method == 'OPTIONS') {
        res.sendStatus(200);
    }
    else {
        next();
    }
}

var basicHttpAuth = function(req,res,next) {
    // ... Keep this function definition, but we won't apply it globally anymore
    // ... existing code ...
}

module.exports = function (app) {

    //CORS related  http://stackoverflow.com/questions/7067966/how-to-allow-cors-in-express-nodejs
    app.use(allowCrossDomain);

    // Session configuration BEFORE routes and protected middleware
    app.use(cookieParser()); // Cookie parser needed for sessions
    app.use(session({
        secret: authController.generateSessionSecret(), // Use a generated secret
        resave: false,
        saveUninitialized: false, // Don't save sessions until something is stored
        cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 24 * 60 * 60 * 1000 } // Configure cookie options (secure in prod)
    }));

    if (process.env.NODE_ENV == 'development') {

        // Disable caching of scripts for easier testing
        app.use(function noCache(req, res, next) {
            if (req.url.indexOf('/scripts/') === 0) {
                res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
                res.header('Pragma', 'no-cache');
                res.header('Expires', 0);
            }
            next();
        });
        app.use(errorHandler());
        app.locals.pretty = true;
        app.locals.compileDebug = true;
    }

    if (process.env.NODE_ENV == 'production') {
        app.use(favicon(path.join(config.root, 'public/app/img', 'favicon.ico')));
    };

    //app.use(auth.connect(digest));      //can specify specific routes for auth also
    // app.use(basicHttpAuth); // <-- Removed global basic auth middleware

    // Apply basic auth specifically if needed for pi players later
    // Example: app.use('/sync_folders', basicHttpAuth);
    // Example: app.use('/releases', basicHttpAuth);

    //app.use('/sync_folders',serveIndex(config.syncDir));
    app.use('/sync_folders',function(req, res, next){
            // Player uses --no-cache header in wget to download assets. The --no-cache flag sends the following headers
            // Cache-Control: no-cache , Pragma: no-cache
            // This causes 200 OK response for all requests. Hence remove this header to minimise data-transfer costs.
            delete req.headers['cache-control'];  // delete header
            delete req.headers['pragma'];  // delete header
            fs.stat(path.join(config.syncDir,req.path), function(err, stat){
                if (!err && stat.isDirectory()) {
                    res.setHeader('Last-Modified', (new Date()).toUTCString());
                }
                next();
            })
        },
        serveIndex(config.syncDir)
    );
    app.use('/sync_folders',express.static(config.syncDir));
    app.use('/releases',express.static(config.releasesDir));
    app.use('/licenses',express.static(config.licenseDir));

    app.use('/media', express.static(path.join(config.mediaDir)));
    app.use(express.static(path.join(config.root, 'public')));

    app.set('view engine', 'pug');
    app.locals.basedir = config.viewDir; //for jade root

    app.set('views', config.viewDir);

    //app.use(logger('dev'));
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(methodOverride());

    // Routes need to be after session middleware
    app.use(require('./routes'));

    // custom error handler
    app.use(function (err, req, res, next) {
        if (err.message.indexOf('not found') >= 0)
            return next();
        //ignore range error as well
        if (err.message.indexOf('Range Not Satisfiable') >=0 )
            return res.send();
        console.error(err.stack)
        res.status(500).render('500')
    })

    app.use(function (req, res, next) {
        //res.redirect('/');
        res.status(404).render('404', {url: req.originalUrl})
    })
};

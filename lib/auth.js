var everyauth = require('everyauth');
var log = require('./log');

function makeUserChecker(proxyMiddleware, conf) {
  function userCanAccess(req) {
    var auth = req.session && req.session.auth;
    if(!auth) {
      log.info("User rejected because they haven't authenticated.");
      return false;
    }

    for(var authType in auth) {
      if(everyauth[authType] && everyauth[authType].authorize(auth)) {
        everyauth[authType].decorate(req, auth);
        return true;
      }
    }

    return false;
  }

  function isPublicPath(req) {
    if(!conf.publicPaths) { return false; }

    for(var i = 0, len = conf.publicPaths.length; i < len; i++) {
      var path = conf.publicPaths[i];
      if(typeof(path) == 'object') { // regex
        if(req.url.match(path)) { return true; }
      } else {
        if(req.url.indexOf(path) == 0) { return true; }
      }
    }

    return false;
  }

  return function checkUser(req, res, next) {
    // /_doorman requests never get proxied
    if(req.url.indexOf('/_doorman') == 0) { return next(); }

    if(userCanAccess(req) || isPublicPath(req)) {
      proxyMiddleware(req, res, next);
    } else {
      if(req.session && req.session.auth) {
        // User had an auth, but it wasn't an acceptable one
        req.session.auth = null;
        log.info("User successfully oauthed but their account does not meet the configured criteria.");

        req.flash('error', "Sorry, your account is not authorized to access the system.");
      }
      next();
    }
  }
}

module.exports.makeUserChecker = makeUserChecker

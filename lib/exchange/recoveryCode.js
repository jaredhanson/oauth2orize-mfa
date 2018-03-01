/**
 * Module dependencies.
 */
var merge = require('utils-merge')
  , TokenError = require('../errors/tokenerror');


module.exports = function(options, authenticate, issue) {
  if (typeof options == 'function') {
    issue = authenticate;
    authenticate = options;
    options = undefined;
  }
  options = options || {};
  
  if (!authenticate) { throw new TypeError('oauth2orize-mfa.recoveryCode exchange requires an authenticate callback'); }
  if (!issue) { throw new TypeError('oauth2orize-mfa.recoveryCode exchange requires an issue callback'); }
  
  var userProperty = options.userProperty || 'user';
  
  return function recovery_code(req, res, next) {
    // The 'user' property of `req` holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , token = req.body.mfa_token
      , recoveryCode = req.body.recovery_code;
    
    if (!token) { return next(new TokenError('Missing required parameter: mfa_token', 'invalid_request')); }
    if (typeof token !== 'string') { return next(new TokenError('mfa_token must be a string', 'invalid_request')); }
    if (!recoveryCode) { return next(new TokenError('Missing required parameter: recovery_code', 'invalid_request')); }
    if (typeof recoveryCode !== 'string') { return next(new TokenError('recovery_code must be a string', 'invalid_request')); }

    function authenticated(err, user, info) {
      if (err) { return next(err); }
      
      function issued(err, accessToken, refreshToken, params) {
        if (err) { return next(err); }
        if (!accessToken) { return next(new TokenError('Invalid resource owner credentials', 'invalid_grant')); }
        if (refreshToken && typeof refreshToken == 'object') {
          params = refreshToken;
          refreshToken = null;
        }
      
        var tok = {};
        tok.access_token = accessToken;
        if (refreshToken) { tok.refresh_token = refreshToken; }
        if (params) { merge(tok, params); }
        tok.token_type = tok.token_type || 'Bearer';
      
        var json = JSON.stringify(tok);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.end(json);
      }
    
      try {
        var arity = issue.length;
        if (arity == 8) {
          issue(client, user, recoveryCode, token, req.body, info, req.authInfo, issued);
        } else if (arity == 7) {
          issue(client, user, recoveryCode, token, req.body, info, issued);
        } else if (arity == 6) {
          issue(client, user, recoveryCode, token, req.body, issued);
        } else if (arity == 5) {
          issue(client, user, recoveryCode, token, issued);
        } else { // arity == 4
          issue(client, user, recoveryCode, issued);
        }
      } catch (ex) {
        return next(ex);
      }
    }
    
    if (options.passReqToCallback) {
      authenticate(req, token, authenticated);
    } else {
      authenticate(token, authenticated);
    }
  };
};

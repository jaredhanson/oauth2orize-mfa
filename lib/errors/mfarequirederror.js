/**
 * Module dependencies.
 */
var TokenError = require('./tokenerror');

/**
 * `TokenError` error.
 *
 * @api public
 */
function MFARequiredError(message, uri, user, areq) {
  TokenError.call(this, message, 'mfa_required', uri);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'MFARequiredError';
  this.user = user;
  this.req = areq;
}

/**
 * Inherit from `TokenError`.
 */
MFARequiredError.prototype.__proto__ = TokenError.prototype;


/**
 * Expose `MFARequiredError`.
 */
module.exports = MFARequiredError;

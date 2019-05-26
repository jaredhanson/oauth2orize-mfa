/**
 * Module dependencies.
 */
var TokenError = require('./tokenerror');

/**
 * `TokenError` error.
 *
 * @api public
 */
function MFARequiredError(message, uri, areq, user, ctx) {
  TokenError.call(this, message, 'mfa_required', uri);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'MFARequiredError';
  this.request = areq;
  this.user = user;
  this.context = ctx;
}

/**
 * Inherit from `TokenError`.
 */
MFARequiredError.prototype.__proto__ = TokenError.prototype;


/**
 * Expose `MFARequiredError`.
 */
module.exports = MFARequiredError;

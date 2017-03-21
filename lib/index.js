exports.exchange = {};
exports.exchange.otp = require('./exchange/otp');
exports.exchange.oob = require('./exchange/oob');
exports.exchange.recoveryCode = require('./exchange/recoveryCode');

exports.TokenError = require('./errors/tokenerror');
exports.MFARequiredError = require('./errors/mfarequirederror');

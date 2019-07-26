/* global describe, it */

var pkg = require('..');
var expect = require('chai').expect;


describe('oauth2orize-2fa', function() {
  
  it('should export exchanges', function() {
    expect(pkg.exchange).to.be.an('object');
    expect(pkg.exchange.otp).to.be.a('function');
    expect(pkg.exchange.oob).to.be.a('function');
    expect(pkg.exchange.recoveryCode).to.be.a('function');
  });
  
});

var chai = require('chai')
  , oob = require('../../lib/exchange/oob');


describe('exchange.oob', function() {
  
  it('should be named oob', function() {
    expect(oob(function(){}, function(){}).name).to.equal('oob');
  });
  
});

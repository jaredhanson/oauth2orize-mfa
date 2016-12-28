var chai = require('chai')
  , oob = require('../../lib/exchange/oob');


describe('exchange.oob', function() {
  
  it('should be named oob', function() {
    expect(oob(function(){}, function(){}).name).to.equal('oob');
  });
  
  it('should throw if constructed without an authenticate callback', function() {
    expect(function() {
      oob();
    }).to.throw(TypeError, 'oauth2orize-2fa.oob exchange requires an authenticate callback');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      oob(function(){});
    }).to.throw(TypeError, 'oauth2orize-2fa.oob exchange requires an issue callback');
  });
  
});

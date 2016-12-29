var chai = require('chai')
  , otp = require('../../lib/exchange/otp');


describe('exchange.otp', function() {
  
  it('should be named otp', function() {
    expect(otp(function(){}, function(){}).name).to.equal('otp');
  });
  
  it('should throw if constructed without an authenticate callback', function() {
    expect(function() {
      otp();
    }).to.throw(TypeError, 'oauth2orize-2fa.otp exchange requires an authenticate callback');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      otp(function(){});
    }).to.throw(TypeError, 'oauth2orize-2fa.otp exchange requires an issue callback');
  });
  
  describe('authenticating and issuing an access token', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        if (token !== 'ey...') { return done(new Error('incorrect token argument')); }
        
        return done(null, { id: '1', username: 'johndoe' })
      }
      
      function issue(client, user, otp, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (user.username !== 'johndoe') { return done(new Error('incorrect user argument')); }
        if (otp !== '123456') { return done(new Error('incorrect otp argument')); }
        
        return done(null, 's3cr1t')
      }
      
      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { access_token: 'ey...', otp: '123456' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
});

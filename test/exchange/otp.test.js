var chai = require('chai')
  , otp = require('../../lib/exchange/otp');

describe('exchange.otp', function() {
  
  it('should be named otp', function() {
    expect(otp(function(){}, function(){}).name).to.equal('otp');
  });
  
  it('should throw if constructed without an authenticate callback', function() {
    expect(function() {
      otp();
    }).to.throw(TypeError, 'oauth2orize-mfa.otp exchange requires an authenticate callback');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      otp(function(){});
    }).to.throw(TypeError, 'oauth2orize-mfa.otp exchange requires an issue callback');
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
          req.body = { mfa_token: 'ey...', otp: '123456' };
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
  
  describe('authenticating and issuing an access token with token', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        if (token !== 'ey...') { return done(new Error('incorrect token argument')); }
        
        return done(null, { id: '1', username: 'johndoe' })
      }
      
      function issue(client, user, otp, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (user.username !== 'johndoe') { return done(new Error('incorrect user argument')); }
        if (otp !== '123456') { return done(new Error('incorrect otp argument')); }
        if (token !== 'ey...') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t')
      }
      
      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { mfa_token: 'ey...', otp: '123456' };
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
  
  describe('handling a request without an MFA token', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        return done(null, { id: '0' })
      }
      
      function issue(client, user, otp, done) {
        return done(null, '.ignore')
      }
      
      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { otp: '123456' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Missing required parameter: mfa_token');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });
  
  describe('handling a request with a non-string MFA token', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        return done(null, { id: '0' })
      }

      function issue(client, user, oobCode, token, done) {
        return done(null, '.ignore')
      }

      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { mfa_token: 1 };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('mfa_token must be a string');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });

  describe('handling a request without a one-time password', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        return done(null, { id: '0' })
      }
      
      function issue(client, user, otp, done) {
        return done(null, '.ignore')
      }
      
      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { mfa_token: 'ey...' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Missing required parameter: otp');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });

  describe('handling a request with a non-string one-time password', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        return done(null, { id: '0' })
      }

      function issue(client, user, oobCode, token, done) {
        return done(null, '.ignore')
      }

      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { otp: 1, mfa_token: 'foo' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('otp must be a string');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });

  describe('authenticating and issuing with token, body, and info', function() {
    var response, err;

    before(function(done) {
      function authenticate(token, done) {
        if (token !== 'ey...') { return done(new Error('incorrect token argument')); }

        return done(null, { id: '1', username: 'johndoe' }, { provider: 'XXX' })
      }

      function issue(client, user, otp, token, body, info, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (user.username !== 'johndoe') { return done(new Error('incorrect user argument')); }
        if (otp !== '123456') { return done(new Error('incorrect otp argument')); }
        if (token !== 'ey...') { return done(new Error('incorrect token argument')); }
        if (body.mfa_token !== 'ey...' || body.otp !== '123456') {
          return done(new Error('incorrect body argument'));
        }
        if (info.provider !== 'XXX') { return done(new Error('incorrect info argument')); }

        return done(null, 's3cr1t')
      }

      chai.connect.use(otp(authenticate, issue))
        .req(function(req) {
          req.user = { id: 'c123', name: 'Example' };
          req.body = { mfa_token: 'ey...', otp: '123456' };
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

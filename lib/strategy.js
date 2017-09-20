var passport = require('passport-strategy')
  , extend = require('extend')
  , url = require('url')
  , uid = require('uid2')
  , util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , AuthorizationError = require('passport-oauth2').AuthorizationError
  , EloquaOAuth2 = require('./oauth2')
  , querystring = require('querystring');

function EloquaStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }

  options = options || {};

  if (!options.clientID) { throw new TypeError('EloquaStrategy requires a clientID option'); }
  if (!options.clientSecret) { throw new TypeError('EloquaStrategy requires a clientSecret option'); }

  passport.Strategy.call(this);
  this.name = options.name || 'eloqua';

  this._verify = verify;
  this._clientSecret = options.clientSecret;
  this._clientId = options.clientID;
  this._tokenURL = options.tokenURL || 'https://login.eloqua.com/auth/oauth2/token';
  this._authorizationURL = options.authorizationURL || 'https://login.eloqua.com/auth/oauth2/authorize';
  this._customHeaders = options.customHeaders || {};

  /**
   * Each Eloqua instance has it's own API baseURL. In order to be able to work with that API this URL needs to be
   * configured otherwise all requests to an API will show up as 401 Unauthorized
   */
  this._baseURL = options.baseURL;

  this._oauth2 = new EloquaOAuth2(this._clientId,  this._clientSecret, '', this._authorizationURL, this._tokenURL, this._customHeaders);

  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._state = options.state;
  this._key = options.sessionKey || ('oauth2:' + url.parse(this._authorizationURL).hostname);
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
}

util.inherits(EloquaStrategy, passport.Strategy);

EloquaStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    if (this._state) {
      if (!req.session) {
        return this.error(new Error('EloquaStrategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      if (!req.session[key]) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }

      var state = req.session[key].state;
      if (!state) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({ message: 'Invalid authorization request state.' }, 403);
      }
    }

    var params = {
      grant_type: "authorization_code",
      redirect_uri: options.callbackURL || this._callbackURL
    };

    this._oauth2.getOAuthAccessToken(code, params, function(err, accessToken, refreshToken, params) {
      if (err) {
        return self.error(self._createOAuthError('Failed to obtain access token', err));
      }

      var verified = function (err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        info = info || {};
        self.success(user, info);
      }

      var profile = {baseURL: self._baseURL};

      try {
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 6) {
            self._verify(req, accessToken, refreshToken, params, profile, verified);
          } else { // arity == 5
            self._verify(req, accessToken, refreshToken, profile, verified);
          }
        } else {
          var arity = self._verify.length;
          if (arity == 5) {
            self._verify(accessToken, refreshToken, params, profile, verified);
          } else { // arity == 4
            self._verify(accessToken, refreshToken, profile, verified);
          }
        }
      } catch (ex) {
        return self.error(ex);
      }
    });

  } else {
    var params = {
      response_type: "code",
      redirect_uri: options.callbackURL || this._callbackURL
    };
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) {
        return this.error(new Error('EloquaStrategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      state = uid(24);
      if (!req.session[key]) { req.session[key] = {}; }
      req.session[key].state = state;
      params.state = state;
    }

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

EloquaStrategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);
  if (json.error) {
    return new OAuth2Strategy.TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

EloquaStrategy.prototype._createOAuthError = function(message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (exception) {}
  }
  if (!e) { e = new OAuth2Strategy.InternalOAuthError(message, err); }
  return e;
};

module.exports = EloquaStrategy;
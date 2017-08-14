/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , url = require('url')
  , uid = require('uid2')
  , util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , OAuth2 = require('oauth').OAuth2
  , AuthorizationError = require('passport-oauth2').AuthorizationError
  , querystring = require('querystring');

/**
 * `Strategy` constructor.
 *
 * The Eloqua authentication strategy authenticates requests by delegating to
 * Eloqua using the OAuth 2.0 protocol.
 *
 * 1. Request initial authorization through the `login.eloqua.com/auth/oauth2/authorize`
 *    endpoint. A call to this endpoint will trigger a prompt for users to enter their credentials.
 *    `/auth/oauth2/authorize` has five possible URL parameters:
 *     - `response_type` (required)  Must be `code`
 *     - `client_id`     (required)  Your App’s `Client Id` provided when registering your app
 *     - `redirect_uri`  (required)  Your App’s registered redirection endpoint, should be the same
 *                                   URL you entered as the `Callback Url` when registering your ap
 *     - `scope`         (optional)  Must be `full` or not supplied
 *     - `state`         (optional)  An optional value that has meaning for your App
 *
 *    The call to the authorize endpoint might resemble:
 *    `https://login.eloqua.com/auth/oauth2/authorize?
 *    response_type=code&client_id=a1b2c3d4&redirect_uri=https://client.example.com/cb&scope=full&state=xyz`
 *
 *    Once users enter their credentials and accept your app’s request to access Eloqua on their
 *    behalf, they are redirected to the `redirect_uri` with a `Grant Token` (which is in this case an
 *    `Authorization Code`) attached in the `code` URL parameter, as in the following example:
 *
 *    HTTP/1.1 302 Found
 *    Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
 *
 * 2. Use the Grant Token to obtain an Access Token and Refresh Token using a POST request to
 *    the `login.eloqua.com/auth/oauth2/token` endpoint.
 *
 *    The POST request should include a JSON body with the following parameters:
 *    - `grant_type`    (required)  The name of the `Grant Token's` type. In this case: `authorization_code`
 *    - `code`          (required)  The `Grant Token`
 *    - `redirect_uri`  (required)  Your App’s registered redirection endpoint
 *
 *    The following example call requests an `Access Token` and a `Refresh Token` token using
 *    the `Grant Token` obtained previously:
 *
 *    POST https://login.eloqua.com/auth/oauth2/token
 *    Authorization: Basic Q09NUEFOWVhcdXNlcjE6cGFzc3dvcmQxMjM=
 *    {
 *      "grant_type":"authorization_code",
 *      "code":"SplxlOBeZQQYbYS6WxSbIA",
 *      "redirect_uri":"https://client.example.com/cb"
 *    }
 *
 *    Note: This request must authenticate using HTTP basic. Use your app’s Client Id as the
 *    username and its Client Secret as the password. The format is client_id:client_secret.
 *    Encode the string with base-64 encoding, and you can pass it as an authentication header.
 *    The system does not support passing Client Id and Client Secret parameters in the JSON body,
 *    and, unlike basic authentication elsewhere, you should not include your site name.
 *
 *    The authorization server validates the authorization code and if valid responds with a JSON body
 *    containing the Access Token, Refresh Token, access token expiration time, and token type, as in
 *    the following example:
 *
 *    HTTP/1.1 200 OK
 *    Content-Type: application/json
 *    {
 *      "access_token":"2YotnFZFEjr1zCsicMWpAA",
 *      "token_type":"bearer",
 *      "expires_in":3600,
 *      "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
 *    }
 *
 * 3. Store and use the access and refresh tokens.
 *    When your app needs a protected resource, it authenticates during the request using the
 *    Access Token. The following call to Eloqua’s Rest API uses the access token to authenticate:
 *    GET /resource/1 HTTP/1.1
 *    Host: api.eloqua.com
 *    Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
 *    api.eloqua.com verifies the Access Token, and supplies the requested resource if the access
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function EloquaStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }

  options = options || {};

  var self = this;

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

  this._oauth2 = new OAuth2(self._clientId,  self._clientSecret, '', self._authorizationURL, self._tokenURL, self._customHeaders);

  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._state = options.state;
  this._key = options.sessionKey || ('oauth2:' + url.parse(this._authorizationURL).hostname);
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;

  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    var params = params || {};

    var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
    params[codeParam] = code;

    var post_data = JSON.stringify(params);

    var authorization = new Buffer(self._clientId + ':' + self._clientSecret);

    var post_headers = {
      "Content-Type": "application/json",
      "Authorization": "Basic " + authorization.toString('base64')
    };

    this._request("POST", self._tokenURL, post_headers, post_data, null, function(error, data, response) {
      if (error) {
        callback(error);
      } else {
        var results;
        try {
          results = JSON.parse(data);
        }
        catch (e) {
          results = querystring.parse(data);
        }
        var access_token = results["access_token"];
        var refresh_token = results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results);
      }
    });
  }
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
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
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
        self.success(user, info);
      }

      try {
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 6) {
            self._verify(req, accessToken, refreshToken, params, {}, verified);
          } else { // arity == 5
            self._verify(req, accessToken, refreshToken, {}, verified);
          }
        } else {
          var arity = self._verify.length;
          if (arity == 5) {
            self._verify(accessToken, refreshToken, params, {}, verified);
          } else { // arity == 4
            self._verify(accessToken, refreshToken, {}, verified);
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
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
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
    } catch (_) {}
  }
  if (!e) { e = new OAuth2Strategy.InternalOAuthError(message, err); }
  return e;
};

module.exports = EloquaStrategy;

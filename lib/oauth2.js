var OAuth2 = require('oauth').OAuth2
  , querystring= require('querystring');


function EloquaOAuth2(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId = clientId;
  this._clientSecret = clientSecret;
  this._baseSite = baseSite;
  this._authorizeUrl = authorizePath || "/oauth/authorize";
  this._accessTokenUrl = accessTokenPath || "/oauth/access_token";
  this._accessTokenName = "access_token";
  this._authMethod = "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET = false;
};

EloquaOAuth2.prototype = Object.create(OAuth2.prototype);

EloquaOAuth2.prototype.constructor = EloquaOAuth2;

EloquaOAuth2.prototype.getOAuthAccessToken = function(code, params, callback) {
  var params = params || {};

  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam] = code;

  var post_data = JSON.stringify(params);

  var authorization = new Buffer(this._clientId + ':' + this._clientSecret);

  var post_headers = {
    "Content-Type": "application/json",
    "Authorization": "Basic " + authorization.toString('base64')
  };

  this._request("POST", this._accessTokenUrl, post_headers, post_data, null, function(error, data, response) {
    if (error) {
      callback(error);
    } else {
      var results;
      try {
        results = JSON.parse(data);
      } catch (e) {
        results = querystring.parse(data);
      }
      var access_token = results["access_token"];
      var refresh_token = results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token, results);
    }
  });
};

module.exports = EloquaOAuth2;
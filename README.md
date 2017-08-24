# passport_eloqua
Eloqua OAuth2 strategy for Passport

## Install
```shell
$ npm install passport_eloqua
```

## Usage

### Configure Strategy

The Eloqua authentication strategy authenticates  Oracle Eloqua API users via OAuth 2.0 mechanism.  The strategy 
requires a `verify` callback, which accepts these credentials and calls `done` providing a user, as well as
`options` specifying a client ID, client Secret, and callback URL.

```js
passport.use(new EloquaStrategy({
    authorizationURL: 'https://login.eloqua.com/auth/oauth2/authorize',
    tokenURL: 'https://login.eloqua.com/auth/oauth2/token',
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/example/callback",
    scope: 'full' // default
  }, 
  (accessToken, refreshToken, profile, done) => {
    done(error);
  }
));
```

## Related Modules

- [passport-oauth2](https://github.com/jaredhanson/passport-oauth2) - OAuth 2.0 Authentication strategy

## Thanks

- [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2017 [Bedrock Data Inc](http://github.com/bedrockdata)

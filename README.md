# passport_eloqua
Eloqua OAuth2 strategy for Passport

## Install
```shell
$ npm install passport-eloqua
```

## Sample provider
```json
{
  "eloqua": {
    "title": "Eloqua",
    "strategy": "OAuth2",
    "refresh": true,
    "options": {
      "authorizationURL": "https://login.eloqua.com/auth/oauth2/authorize",
      "tokenURL": "https://login.eloqua.com/auth/oauth2/token",
      "clientID": CLIENT_ID,
      "clientSecret": CLIENT_SECRET,
      "callbackURL": CALLBACK_URL,
      "scope": "full"
    }
  }
}
```

## Usage

## Thanks

  - [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2017 [Bedrock Data Inc](http://github.com/bedrockdata)

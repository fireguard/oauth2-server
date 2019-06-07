# @fireguard/oauth2-server

[![Build Status](https://travis-ci.org/fireguard/oauth2-server.svg?branch=master)](https://travis-ci.org/fireguard/oauth2-server)

Complete, compliant and well tested module for implementing an OAuth2 server in [Node.js](https://nodejs.org).


## Installation

```bash
npm install @fireguard/oauth2-server
```

## Features

- Supports `authorization_code`, `client_credentials`, `refresh_token` and `password` grant, as well as *extension grants*, with scopes.
- Can be used with *promises*, *Node-style callbacks*, *ES6 generators* and *async*/*await*.
- Fully [RFC 6749](https://tools.ietf.org/html/rfc6749.html) and [RFC 6750](https://tools.ietf.org/html/rfc6749.html) compliant.
- Implicitly supports any form of storage, e.g. *PostgreSQL*, *MySQL*, *MongoDB*, *Redis*, etc.
- Complete [test suite](https://github.com/fireguard/oauth2-server/tree/master/tests).


## Tests

To run the test suite, install dependencies, then run `npm test`:

```bash
npm install
npm test
```


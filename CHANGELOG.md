# Changelog

`servant-hmac-auth` uses [PVP Versioning][1].
The change log is available [on GitHub][2].

## Unrelease: x.y.z

* Authenticate against the request's body. The HMAC signature is influenced by
  the HTTP method, the request's body, some HTTP headers and the requested URL
  (except for the scheme).


## 0.1.3 - Nov 29, 2021
* Bump `servant-*` libraries' version to `0.18-*`
* Use `GHC 8.8.3` (Stack Resolver `16.2`)


## Unreleased: 0.1.0

* Introduce whitelisted headers.
* **Breaking change:** `HmacSettings` now containt post-sign hook for request.
  `hmacClientSign` function accepts `HmacSettings`.

  _Migration guide:_ use `defaultHmacSettings` for `runHmacClient` function.
* Add `hmacAuthHandlerMap` function that allows to perform monadic actions on
  every incoming request for HMAC server.
* [#28](https://github.com/Holmusk/servant-hmac-auth/issues/28):
  Added type alias `HmacAuthHandler` for `AuthHandler Wai.Request ()`
* [#37](https://github.com/Holmusk/servant-hmac-auth/issues/37):
  Upgrade `servant-*` libraries to `0.16-*`
* Use `Cabal-2.4`

## 0.0.0 — Sep 6, 2018

* Initially created.

[1]: https://pvp.haskell.org
[2]: https://github.com/holmusk/servant-hmac-auth/releases

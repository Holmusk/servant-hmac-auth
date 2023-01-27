# Changelog

`servant-hmac-auth` uses [PVP Versioning][1].
The change log is available [on GitHub][2].

## 0.1.5 - Jan 27, 2023
* Bump dependency upper bounds, allow building with `GHC 9.0`, `9.2` and `9.4`

## 0.1.4 - March 8, 2022

* [#55](https://github.com/Holmusk/servant-hmac-auth/pull/55):
  **Breaking change:** non-standard http(s) port are now included in the HMAC signature.

  _Migration guide_: if you are communicating over the standard http(s) port (`80` for http, `443` for https), then you will **not** be impacted.
  Otherwise, you need to make sure that both the client and server include the custom http(s) port number in the HMAC signature generation.
  This library will do so automatically.

* [#53](https://github.com/Holmusk/servant-hmac-auth/pull/53):
  Servant 0.19 support (Support servant-0.19)

* [#51](https://github.com/Holmusk/servant-hmac-auth/pull/51):
  Allow compilation with ghc 8.10.7

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

# Changelog

## [0.2.3](https://github.com/radiumatic/vaydns/compare/v0.2.2...v0.2.3) (2026-03-25)


### Features

* change ([69d595f](https://github.com/radiumatic/vaydns/commit/69d595f5597da395a257a3684fa3664f728da262))

## [0.2.2](https://github.com/radiumatic/vaydns/compare/v0.2.1...v0.2.2) (2026-03-25)


### Features

* fix ([d88cb04](https://github.com/radiumatic/vaydns/commit/d88cb04a65fe64a0bdb0142c6a343a5f0090b2e2))

## [0.2.1](https://github.com/radiumatic/vaydns/compare/v0.2.0...v0.2.1) (2026-03-25)


### Features

* change ([852a3cd](https://github.com/radiumatic/vaydns/commit/852a3cd5f2dc8ff50d800099228e2313803ca161))

## [0.2.0](https://github.com/net2share/vaydns/compare/v0.1.2...v0.2.0) (2026-03-22)


### ⚠ BREAKING CHANGES

* Go module path changed. Update imports from www.bamsoftware.com/git/dnstt.git/* to github.com/net2share/vaydns/*

### Features

* extract client library package and rename Go module ([4b28bea](https://github.com/net2share/vaydns/commit/4b28beacf52768ceeda09cbcb42a9422f6cc2075))

## [0.1.2](https://github.com/net2share/vaydns/compare/v0.1.1...v0.1.2) (2026-03-22)


### Features

* add -dnstt-compat flag for wire protocol compatibility ([#16](https://github.com/net2share/vaydns/issues/16)) ([e371e0c](https://github.com/net2share/vaydns/commit/e371e0c163fc72b216a29f76720df1f59ed9eeb7))


### Bug Fixes

* override server timeout defaults in -dnstt-compat mode ([cce9866](https://github.com/net2share/vaydns/commit/cce98664ab2221b8dae315e237dbba5daa73532f))

## [0.1.1](https://github.com/net2share/vaydns/compare/v0.1.0...v0.1.1) (2026-03-20)


### Features

* make timeout and reconnect settings configurable ([#15](https://github.com/net2share/vaydns/issues/15)) ([9648346](https://github.com/net2share/vaydns/commit/96483461a7e6d386fe9fae1bf35818d0a366af2e))
* wire up dialerControl and improve flag descriptions ([e96f92e](https://github.com/net2share/vaydns/commit/e96f92e731cc188670d5b95655bc7673f987a4b5))

## 0.1.0 (2026-03-17)


### ⚠ BREAKING CHANGES

* rewrite wire protocol to reduce per-query overhead

### Features

* add -max-qname-len and -max-num-labels flags for QNAME constraints ([c8c89ff](https://github.com/net2share/vaydns/commit/c8c89ffec94d5135a80ef65f096fcbf2651e434f))
* add -rps flag with token bucket rate limiter ([4bbf1f4](https://github.com/net2share/vaydns/commit/4bbf1f4c9744e86252156eba069af308010495a7))
* add configurable keepalive/timeout and connection recovery ([f7dc1af](https://github.com/net2share/vaydns/commit/f7dc1af167fde62955669a63906e130af18210a8))
* add per-query UDP transport with worker pool and RCODE filtering ([3d09a6d](https://github.com/net2share/vaydns/commit/3d09a6d243320ae2c0fcf1324850437a6630124b))
* convert positional args to named flags (-domain, -listen, -upstream) ([594c97d](https://github.com/net2share/vaydns/commit/594c97d0b3faa6256b46fb95522eb289e0ac7019))
* migrate from stdlib log to logrus for structured logging ([59c11ff](https://github.com/net2share/vaydns/commit/59c11ff6f20ca09439bbe93b1a8d827e160dfc2a))
* rewrite wire protocol to reduce per-query overhead ([1e94362](https://github.com/net2share/vaydns/commit/1e9436289616c5bdbc1177ffca3d34dafae7cb48))

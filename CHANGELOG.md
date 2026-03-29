# Changelog

## [0.2.5](https://github.com/net2share/vaydns/compare/v0.2.4...v0.2.5) (2026-03-29)


### Bug Fixes

* **ci:** filter download-artifact to vaydns-* pattern ([01b38c0](https://github.com/net2share/vaydns/commit/01b38c03ded836a986e50bdc8dddae945d8d178d))
* clean worker shutdown on transport close ([#47](https://github.com/net2share/vaydns/issues/47)) ([13c9317](https://github.com/net2share/vaydns/commit/13c93171643a8c786e9cb7e629f06ce03809906e))
* rebuild transport stack on reconnect ([#44](https://github.com/net2share/vaydns/issues/44)) ([9594ab7](https://github.com/net2share/vaydns/commit/9594ab7d72666cf15e8f81713790c0e455ec432d))


### Performance Improvements

* increase default packet queue size from 128 to 512 ([92bee04](https://github.com/net2share/vaydns/commit/92bee04f3961fa58f3b4991caeb6af0948c88093))

## [0.2.4](https://github.com/net2share/vaydns/compare/v0.2.3...v0.2.4) (2026-03-26)


### Features

* support multiple DNS record types for tunnel data ([#37](https://github.com/net2share/vaydns/issues/37)) ([efdc838](https://github.com/net2share/vaydns/commit/efdc8387a1243c5a7f821ffe6ca6899afda2236a))


### Bug Fixes

* improve connection recovery in censored networks ([#38](https://github.com/net2share/vaydns/issues/38)) ([5a2c442](https://github.com/net2share/vaydns/commit/5a2c442549f9ec542aac2544e1bfb4dd3c013ace))
* lower KCP MTU minimum from 50 to 25 ([3cbb488](https://github.com/net2share/vaydns/commit/3cbb488d02f25920f2176b74279971273363f487))

## [0.2.3](https://github.com/net2share/vaydns/compare/v0.2.2...v0.2.3) (2026-03-26)


### Bug Fixes

* revert per-query UDP deadline reset after forged responses ([2936897](https://github.com/net2share/vaydns/commit/2936897b32df9fa5900ebc1e6109affa052777d5))

## [0.2.2](https://github.com/net2share/vaydns/compare/v0.2.1...v0.2.2) (2026-03-26)


### Bug Fixes

* clarify -udp-shared-socket and -udp-accept-errors behavior ([b0299b6](https://github.com/net2share/vaydns/commit/b0299b620ba379324fdddc4126bb70d19e15924a))

## [0.2.1](https://github.com/net2share/vaydns/compare/v0.2.0...v0.2.1) (2026-03-26)


### Features

* tune default timeouts for censored networks ([579b45c](https://github.com/net2share/vaydns/commit/579b45c27b584ad8e04d820be927288a1dcce148))


### Bug Fixes

* improve MTU too small error message with actionable hints ([051ad56](https://github.com/net2share/vaydns/commit/051ad56f7fc7e1837664a797aba4b00787275cc9))
* reset UDP deadline after forged responses and unify forged logging ([cb63edb](https://github.com/net2share/vaydns/commit/cb63edb24d26ffc53665a93071b03d36d8ae2825))

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

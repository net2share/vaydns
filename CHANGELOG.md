# Changelog

## 1.0.0 (2026-03-17)


### ⚠ BREAKING CHANGES

* rewrite wire protocol to reduce per-query overhead

### Features

* add -max-qname-len and -max-num-labels flags for QNAME constraints ([c8c89ff](https://github.com/net2share/dnstt-revived/commit/c8c89ffec94d5135a80ef65f096fcbf2651e434f))
* add -rps flag with token bucket rate limiter ([4bbf1f4](https://github.com/net2share/dnstt-revived/commit/4bbf1f4c9744e86252156eba069af308010495a7))
* add configurable keepalive/timeout and connection recovery ([f7dc1af](https://github.com/net2share/dnstt-revived/commit/f7dc1af167fde62955669a63906e130af18210a8))
* add per-query UDP transport with worker pool and RCODE filtering ([3d09a6d](https://github.com/net2share/dnstt-revived/commit/3d09a6d243320ae2c0fcf1324850437a6630124b))
* convert positional args to named flags (-domain, -listen, -upstream) ([594c97d](https://github.com/net2share/dnstt-revived/commit/594c97d0b3faa6256b46fb95522eb289e0ac7019))
* migrate from stdlib log to logrus for structured logging ([59c11ff](https://github.com/net2share/dnstt-revived/commit/59c11ff6f20ca09439bbe93b1a8d827e160dfc2a))
* rewrite wire protocol to reduce per-query overhead ([1e94362](https://github.com/net2share/dnstt-revived/commit/1e9436289616c5bdbc1177ffca3d34dafae7cb48))


### Bug Fixes

* go vet error in noise tests and pin release to 0.1.0 ([4bbc205](https://github.com/net2share/dnstt-revived/commit/4bbc2056c63231ce9444fea0214ff37572ccda4d))

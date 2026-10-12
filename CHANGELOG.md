# Changelog

All notable changes to Podtrace are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the rules described in [STABILITY.md](STABILITY.md).

Going forward, releases are managed by [release-please](https://github.com/googleapis/release-please)
based on [Conventional Commits](https://www.conventionalcommits.org/).

## [0.14.9](https://github.com/gma1k/podtrace/compare/v0.14.8...v0.14.9) (2026-10-12)


### Features

* add a dns failure rule and count dns lookups by answer ([#523](https://github.com/gma1k/podtrace/issues/523)) ([12d4da9](https://github.com/gma1k/podtrace/commit/12d4da9340761e18d4e6d0994dc2c19fbc5ab3d0))
* add a per-request critical path and a slow-dns inspection ([#519](https://github.com/gma1k/podtrace/issues/519)) ([110a449](https://github.com/gma1k/podtrace/commit/110a4493a21d1414b27f8e18967966de74f65ddc))
* add a tls failure rule and count go and netty tls handshakes ([#524](https://github.com/gma1k/podtrace/issues/524)) ([f86a7e5](https://github.com/gma1k/podtrace/commit/f86a7e5444b84032cb66707033b610a368d57b38))
* add filesystem metrics to the plane and a slow-fs inspection ([#522](https://github.com/gma1k/podtrace/issues/522)) ([4d55a7a](https://github.com/gma1k/podtrace/commit/4d55a7ad366220774e237fd78e56dfe66499d5c5))
* add Go pool utilization metrics and user-supplied BTF ([#503](https://github.com/gma1k/podtrace/issues/503)) ([f11d87a](https://github.com/gma1k/podtrace/commit/f11d87af0a6b095036d013ed5db23613a3c9c885))
* add on-cpu profiler, flame graphs and p99 request cpu attribution ([#513](https://github.com/gma1k/podtrace/issues/513)) ([75a504e](https://github.com/gma1k/podtrace/commit/75a504ed30a79d1cc69a444cf9f5f95dbe3d9025))
* add podtrace status for a backend-free cluster view ([#512](https://github.com/gma1k/podtrace/issues/512)) ([247a0b5](https://github.com/gma1k/podtrace/commit/247a0b53f9e1cf737e8cc9e39d1073994067cbf0))
* attribute request cpu across every protocol and harden capture ([#514](https://github.com/gma1k/podtrace/issues/514)) ([a4d80a2](https://github.com/gma1k/podtrace/commit/a4d80a2e50176d3b8e650d32a57453322ae4688c))
* charge event-loop cpu to the connection a loop is serving ([#517](https://github.com/gma1k/podtrace/issues/517)) ([28a773d](https://github.com/gma1k/podtrace/commit/28a773de64b3e9b6dd7b8b491091b79cda9d2a09))
* close the continuous apm gaps and enable them by default ([#510](https://github.com/gma1k/podtrace/issues/510)) ([2f01eb6](https://github.com/gma1k/podtrace/commit/2f01eb677750e709faf9311c9ba48a53f44595b6))
* correlate slow requests with symbolised stack frames ([#505](https://github.com/gma1k/podtrace/issues/505)) ([613d490](https://github.com/gma1k/podtrace/commit/613d490a98d02cfce1e69c890870eea67a2e5f7a))
* link active issues to their likely root cause across workloads ([#525](https://github.com/gma1k/podtrace/issues/525)) ([bf4e9fd](https://github.com/gma1k/podtrace/commit/bf4e9fd217df046b6f8e2607b96d35e3b4c5ada4))
* start a session for a chosen issue and open its report with it ([#518](https://github.com/gma1k/podtrace/issues/518)) ([5ef77cc](https://github.com/gma1k/podtrace/commit/5ef77ccd512bc842ec1c13417f1c0e1866287e41))
* turn every tracerconfig agent toggle on unless set to false ([#511](https://github.com/gma1k/podtrace/issues/511)) ([fa4218b](https://github.com/gma1k/podtrace/commit/fa4218b7ca655d9bb69e428ef91ff5095b2f2cec))


### Bug Fixes

* correct process names and pool figures in the diagnose report ([#500](https://github.com/gma1k/podtrace/issues/500)) ([8ef3183](https://github.com/gma1k/podtrace/commit/8ef3183ba1c7882bf7b7340896511988c8ca5884))
* report pool peak connections and connection age consistently ([#502](https://github.com/gma1k/podtrace/issues/502)) ([719eb12](https://github.com/gma1k/podtrace/commit/719eb123a721c53679b1d36b9b894fc063ab1d5b))


### Documentation

* describe continuous apm in the readme and update dependencies ([#527](https://github.com/gma1k/podtrace/issues/527)) ([6af8c2b](https://github.com/gma1k/podtrace/commit/6af8c2b213f0c3c75f8b2562a20d39e293301e59))
* document clang 18+ and libbpf 0.8+ build prerequisites ([#521](https://github.com/gma1k/podtrace/issues/521)) ([a847378](https://github.com/gma1k/podtrace/commit/a8473786b023ef1f076f3810dc0e1f6e607b5d11))


### Build System

* check for clang 18+ before compiling the eBPF objects ([#520](https://github.com/gma1k/podtrace/issues/520)) ([85d6310](https://github.com/gma1k/podtrace/commit/85d6310b992a7de434077eb4506dabe0211e669c))


### CI

* disable codeql trap caching to fix cpp analysis on ubuntu 26.04 ([#509](https://github.com/gma1k/podtrace/issues/509)) ([9ede6ee](https://github.com/gma1k/podtrace/commit/9ede6eef32322b5e3a172fce729481d8d67cf610))


### Maintenance

* **deps:** update module sigs.k8s.io/controller-runtime to v0.25.1 ([#504](https://github.com/gma1k/podtrace/issues/504)) ([f4289d5](https://github.com/gma1k/podtrace/commit/f4289d55038bc2f46565c18cde8e3ec30d5ad7be))
* update dependencies, toolchain pins and generated client ([#508](https://github.com/gma1k/podtrace/issues/508)) ([afd4fb0](https://github.com/gma1k/podtrace/commit/afd4fb00d48d4487da01efe693978238b9a98150))

## [0.14.8](https://github.com/gma1k/podtrace/compare/v0.14.7...v0.14.8) (2026-09-11)


### Features

* add always-on workload metrics plane ([#486](https://github.com/gma1k/podtrace/issues/486)) ([7377cf2](https://github.com/gma1k/podtrace/commit/7377cf2d9a99b9603b518bda6fdabe36df3111b0))
* add continuous inspections, saturation metrics and exemplars ([#497](https://github.com/gma1k/podtrace/issues/497)) ([22f99f2](https://github.com/gma1k/podtrace/commit/22f99f24a195ed19b12a433b4b12a7abdb22c361))
* add graduation machinery for CRD version cutover ([#475](https://github.com/gma1k/podtrace/issues/475)) ([1b5a68d](https://github.com/gma1k/podtrace/commit/1b5a68de35b53305b0d7a498a286552b1ce9d0ab))
* add OTel semantic conventions and OTLP metric export ([#489](https://github.com/gma1k/podtrace/issues/489)) ([d8f87e3](https://github.com/gma1k/podtrace/commit/d8f87e31d8973393e79994d98957a746c1594ae1))
* add workload service map and un-gate all BPF probes ([#494](https://github.com/gma1k/podtrace/issues/494)) ([79f1419](https://github.com/gma1k/podtrace/commit/79f1419cb05a59f7acbf22fb7b4face723841eab))
* aggregate metrics in the kernel instead of per-event ([#496](https://github.com/gma1k/podtrace/issues/496)) ([a593580](https://github.com/gma1k/podtrace/commit/a593580e0a7b4f41c2cf94cd418c93dbc0ac8b3a))
* measure Go database/sql connection acquisition time ([#498](https://github.com/gma1k/podtrace/issues/498)) ([ab438ac](https://github.com/gma1k/podtrace/commit/ab438ac0740939c83061ddae54bd2cdc59c9a115))


### Bug Fixes

* repair the first-run experience and uninstall cleanup ([#495](https://github.com/gma1k/podtrace/issues/495)) ([6187dd4](https://github.com/gma1k/podtrace/commit/6187dd49fe6ee9ef0e081001211820500b1e3562))


### Documentation

* define the exported metrics surface as a contract ([#482](https://github.com/gma1k/podtrace/issues/482)) ([ec99a77](https://github.com/gma1k/podtrace/commit/ec99a774352c92be19b157d64ad8eeecc3dc05ef))


### Maintenance

* **deps:** update alpine/k8s docker tag to v1.37.0 ([#479](https://github.com/gma1k/podtrace/issues/479)) ([842da51](https://github.com/gma1k/podtrace/commit/842da51b485b4616d1e9824c4110d1b2263d74f3))
* **deps:** update dependency golangci/golangci-lint to v2.13.2 ([#471](https://github.com/gma1k/podtrace/issues/471)) ([8803a08](https://github.com/gma1k/podtrace/commit/8803a08433ab6b9275f4ad2653bf5effb4afc87a))
* **deps:** update docker/dockerfile docker tag to v1.27 ([#484](https://github.com/gma1k/podtrace/issues/484)) ([cf21570](https://github.com/gma1k/podtrace/commit/cf21570d0d69121a2b627c41b8f70d6c9535b3a7))
* **deps:** update docker/setup-qemu-action action to v4.3.0 ([#478](https://github.com/gma1k/podtrace/issues/478)) ([64eca53](https://github.com/gma1k/podtrace/commit/64eca5323d6c2cbc7c2348e22fc15cff41a213f3))
* **deps:** update github/codeql-action action to v4.37.9 ([#466](https://github.com/gma1k/podtrace/issues/466)) ([fcea1f2](https://github.com/gma1k/podtrace/commit/fcea1f23de15ab576f38933516eccecb1b090d82))
* **deps:** update go modules (non-major) ([#463](https://github.com/gma1k/podtrace/issues/463)) ([7c8d542](https://github.com/gma1k/podtrace/commit/7c8d542081197cc1244e83d8de80b5609298f6fa))
* **deps:** update go modules (non-major) ([#467](https://github.com/gma1k/podtrace/issues/467)) ([23de623](https://github.com/gma1k/podtrace/commit/23de6230b0ce27346d57d846e1dec776eaa9f75c))
* **deps:** update go modules (non-major) ([#468](https://github.com/gma1k/podtrace/issues/468)) ([2677f62](https://github.com/gma1k/podtrace/commit/2677f62af75759cfa1ca0668030524196754a295))
* **deps:** update go modules (non-major) ([#470](https://github.com/gma1k/podtrace/issues/470)) ([5569173](https://github.com/gma1k/podtrace/commit/5569173263d8133b293923c28ac1a12b30e94cf4))
* **deps:** update go modules (non-major) ([#477](https://github.com/gma1k/podtrace/issues/477)) ([f24780f](https://github.com/gma1k/podtrace/commit/f24780f5c444857f5ead238413ebf04efe0cd451))
* **deps:** update go modules (non-major) ([#481](https://github.com/gma1k/podtrace/issues/481)) ([58bf08d](https://github.com/gma1k/podtrace/commit/58bf08d245bb78a5272ba0592c84574133bd873f))
* **deps:** update go modules (non-major) ([#492](https://github.com/gma1k/podtrace/issues/492)) ([27d1dcc](https://github.com/gma1k/podtrace/commit/27d1dcca82711cb97131ec0eb6f52f28b3a83942))
* **deps:** update golang:1.27.0-trixie docker digest to df98008 ([#474](https://github.com/gma1k/podtrace/issues/474)) ([d836621](https://github.com/gma1k/podtrace/commit/d836621c8537643bbb1a43281785423796b23c0e))
* **deps:** update golang:1.27.1-trixie docker digest to 9baa6b4 ([#483](https://github.com/gma1k/podtrace/issues/483)) ([4c9da18](https://github.com/gma1k/podtrace/commit/4c9da18dd111a7ae119f82b942446956f3dfdee1))
* **deps:** update helm/kind-action action to v1.15.0 ([#485](https://github.com/gma1k/podtrace/issues/485)) ([bf83ee3](https://github.com/gma1k/podtrace/commit/bf83ee3ab74a794c4305baa32fdeb1f1f8d60b6c))
* **deps:** update kubernetes ecosystem to v0.37.0 ([#469](https://github.com/gma1k/podtrace/issues/469)) ([dd910b4](https://github.com/gma1k/podtrace/commit/dd910b40d8a6077a5b83472f6d2f1046f89a59b3))
* **deps:** update module cloud.google.com/go/storage to v1.67.0 ([#487](https://github.com/gma1k/podtrace/issues/487)) ([8500a5c](https://github.com/gma1k/podtrace/commit/8500a5c0694a349e98294355d10b104f669fba92))
* **deps:** update module github.com/aws/aws-sdk-go-v2/config to v1.32.39 ([#465](https://github.com/gma1k/podtrace/issues/465)) ([f24d80c](https://github.com/gma1k/podtrace/commit/f24d80c2ebe97f66cf62f3d4b38461200e4e60cc))
* **deps:** update module github.com/aws/aws-sdk-go-v2/service/s3 to v1.110.0 ([#480](https://github.com/gma1k/podtrace/issues/480)) ([975b485](https://github.com/gma1k/podtrace/commit/975b485c5615ce4b91cbd040d266fec4260115ee))
* **deps:** update module github.com/aws/aws-sdk-go-v2/service/s3 to v1.113.1 ([#499](https://github.com/gma1k/podtrace/issues/499)) ([7f8caf0](https://github.com/gma1k/podtrace/commit/7f8caf0761ff9754ef2e6dee8b8c89be501f9296))
* **deps:** update module github.com/prometheus/client_model to v0.6.3 ([#476](https://github.com/gma1k/podtrace/issues/476)) ([1c241e8](https://github.com/gma1k/podtrace/commit/1c241e8aaef2bcc95fda10898a34c3e59890cc22))
* **deps:** update module google.golang.org/api to v0.295.0 ([#472](https://github.com/gma1k/podtrace/issues/472)) ([bf0cf97](https://github.com/gma1k/podtrace/commit/bf0cf97d257009148a051122f37f3aa5a819a177))
* **deps:** update module sigs.k8s.io/controller-runtime to v0.25.0 ([#488](https://github.com/gma1k/podtrace/issues/488)) ([b5abe9c](https://github.com/gma1k/podtrace/commit/b5abe9c51e11740df6241ca48c989afabf89328e))
* **deps:** update softprops/action-gh-release action to v3.0.3 ([#473](https://github.com/gma1k/podtrace/issues/473)) ([4d9c3e9](https://github.com/gma1k/podtrace/commit/4d9c3e982f6ce8818ff7202a54c42e1b1be7cb67))
* **renovate:** replace k8s major approval gate with a structured-merge-diff version hold ([#493](https://github.com/gma1k/podtrace/issues/493)) ([e275f0f](https://github.com/gma1k/podtrace/commit/e275f0f567585f9a296890b509f44a7a15566174))
* **renovate:** require dashboard approval for k8s ecosystem Go major bumps ([#491](https://github.com/gma1k/podtrace/issues/491)) ([a94ef9e](https://github.com/gma1k/podtrace/commit/a94ef9e60ecb91949383e11888d60fb0e022d680))

## [0.14.7](https://github.com/gma1k/podtrace/compare/v0.14.6...v0.14.7) (2026-08-25)


### ⚠ BREAKING CHANGES

* PodTrace, PodTraceSession, PodTraceSchedule, ApplicationTrace,ExporterConfig and TracerConfig all rename fields.

### Refactors

* unify CRD field naming before v1beta1 graduation ([#459](https://github.com/gma1k/podtrace/issues/459)) ([19ecfd3](https://github.com/gma1k/podtrace/commit/19ecfd368d0e1576502f6617e2d609e396c53901))


### Documentation

* define API versioning and CRD graduation policy ([#455](https://github.com/gma1k/podtrace/issues/455)) ([217aaf0](https://github.com/gma1k/podtrace/commit/217aaf0b52fbd9285ca9f3fe4c6e954102b96955))


### Maintenance

* **deps:** update dependency golangci/golangci-lint to v2.13.1 ([#448](https://github.com/gma1k/podtrace/issues/448)) ([c498c45](https://github.com/gma1k/podtrace/commit/c498c45071f2d15be23a7f9d66fdf9811b8343a9))
* **deps:** update dependency pbr to v7.1.1 ([#456](https://github.com/gma1k/podtrace/issues/456)) ([413bec1](https://github.com/gma1k/podtrace/commit/413bec1b11cea29839034e959af055a1e90f730b))
* **deps:** update dependency pbr to v7.1.2 ([#461](https://github.com/gma1k/podtrace/issues/461)) ([09af68f](https://github.com/gma1k/podtrace/commit/09af68f39710ae91bef4b38daa845ef0df2d1ab9))
* **deps:** update gcr.io/distroless/static-debian12:nonroot docker digest to afa5c87 ([#454](https://github.com/gma1k/podtrace/issues/454)) ([c1fc582](https://github.com/gma1k/podtrace/commit/c1fc58288291c623f12eda60de352e306735a5cb))
* **deps:** update github/codeql-action action to v4.37.8 ([#453](https://github.com/gma1k/podtrace/issues/453)) ([32ca3f8](https://github.com/gma1k/podtrace/commit/32ca3f824d0fe352c48d47ea7678abaa7145e8b3))
* **deps:** update go modules (non-major) ([#449](https://github.com/gma1k/podtrace/issues/449)) ([cbaa07d](https://github.com/gma1k/podtrace/commit/cbaa07d8fb4547c3d15d31968f933da7d8f375ff))
* **deps:** update go modules (non-major) ([#462](https://github.com/gma1k/podtrace/issues/462)) ([d2a9ee4](https://github.com/gma1k/podtrace/commit/d2a9ee40e749eebbcbe6aec1f8d29f03687c53e9))
* **deps:** update golang:1.27.0-trixie docker digest to 41967f5 ([#457](https://github.com/gma1k/podtrace/issues/457)) ([4c17090](https://github.com/gma1k/podtrace/commit/4c17090ed976f4bbc14071fbcb91d8caf7551aac))
* **deps:** update golang:1.27.0-trixie docker digest to ae28539 ([#458](https://github.com/gma1k/podtrace/issues/458)) ([6d1e2ac](https://github.com/gma1k/podtrace/commit/6d1e2acb67509c525cd2eeedc5c2d5eff048bd79))
* **deps:** update kubernetes ecosystem to v0.36.4 ([#450](https://github.com/gma1k/podtrace/issues/450)) ([1eeee0e](https://github.com/gma1k/podtrace/commit/1eeee0e7a591094eee6262a2b5aa7be534c576fc))
* release 0.14.7 ([#460](https://github.com/gma1k/podtrace/issues/460)) ([a37d013](https://github.com/gma1k/podtrace/commit/a37d0134f5fa3b833534b8b12017d4cb3968e2b8))
* run go mod tidy in renovate updates to satisfy the CI tidiness gate ([#451](https://github.com/gma1k/podtrace/issues/451)) ([6d83686](https://github.com/gma1k/podtrace/commit/6d8368600bc4ca2e2fbf71126b7e4c4d82f5badb))

## [0.14.6](https://github.com/gma1k/podtrace/compare/v0.14.5...v0.14.6) (2026-08-20)


### Bug Fixes

* harden agent runtime, resource use, and exporter/alert paths ([#433](https://github.com/gma1k/podtrace/issues/433)) ([e3090f5](https://github.com/gma1k/podtrace/commit/e3090f569e209c8c222b16e68eeb48ba0129846e))
* harden GCS credential loading and unblock lint on go 1.27 ([#444](https://github.com/gma1k/podtrace/issues/444)) ([d134073](https://github.com/gma1k/podtrace/commit/d134073d9b5a1df71e87e34016a0fb2fcf1b61cb))
* harden L7 decoders, redaction, alerting, and CLI lifecycle ([#438](https://github.com/gma1k/podtrace/issues/438)) ([d384143](https://github.com/gma1k/podtrace/commit/d3841430d6f408ea4d357bce672859b2f4e0bccf))
* harden pod specs, redact reports, and close filter/tee gaps ([#436](https://github.com/gma1k/podtrace/issues/436)) ([4d814d2](https://github.com/gma1k/podtrace/commit/4d814d254ef3a4fd28b48bbf0c181368ea88674c))
* harden trace export, metrics, and diagnose resource bounds ([#435](https://github.com/gma1k/podtrace/issues/435)) ([341619e](https://github.com/gma1k/podtrace/commit/341619e0410d29764e32a914a47c460ff28b256f))


### Build System

* remove dead BPF pid/tid stores, gate warnings, fix sudo hygiene ([#441](https://github.com/gma1k/podtrace/issues/441)) ([03652b9](https://github.com/gma1k/podtrace/commit/03652b90e8fbc71479a963ab211a2dafbfc88fcc))


### Maintenance

* **deps:** update dependency golangci/golangci-lint to v2.13.0 ([#445](https://github.com/gma1k/podtrace/issues/445)) ([40413cf](https://github.com/gma1k/podtrace/commit/40413cf24ee1b6104e4022b5a572b08fb7e2394a))
* **deps:** update docker/setup-buildx-action action to v4.3.0 ([#439](https://github.com/gma1k/podtrace/issues/439)) ([9a722c9](https://github.com/gma1k/podtrace/commit/9a722c9241731c7c4a2b77fdae8f0f9940dc852c))
* **deps:** update go modules (non-major) ([#442](https://github.com/gma1k/podtrace/issues/442)) ([c56b912](https://github.com/gma1k/podtrace/commit/c56b912766c8b20fbf83b3e1202985e12a6936f1))
* **deps:** update module google.golang.org/grpc to v1.83.1 ([#437](https://github.com/gma1k/podtrace/issues/437)) ([64a42b4](https://github.com/gma1k/podtrace/commit/64a42b44c3a8d041fbff4235284681253c61c616))
* gofmt the repo and gate formatting in CI ([#440](https://github.com/gma1k/podtrace/issues/440)) ([43b4c4c](https://github.com/gma1k/podtrace/commit/43b4c4c4154d816b623354db51024d9b9dbfe7f3))
* tidy go.mod and gate tidiness in CI ([#447](https://github.com/gma1k/podtrace/issues/447)) ([e487ed7](https://github.com/gma1k/podtrace/commit/e487ed7f60f31e494b0c51b1f6ab7120941b4cde))
* update go to 1.27.0 and golangci-lint to 2.13.0 ([#446](https://github.com/gma1k/podtrace/issues/446)) ([9b26e0b](https://github.com/gma1k/podtrace/commit/9b26e0b1c571925dd89f9d66e4037531be833d62))

## [0.14.5](https://github.com/gma1k/podtrace/compare/v0.14.4...v0.14.5) (2026-08-18)


### Bug Fixes

* bound CR names stamped into label values to 63 chars ([#424](https://github.com/gma1k/podtrace/issues/424)) ([e4eacbc](https://github.com/gma1k/podtrace/commit/e4eacbcb64cde7d558dcba4e9228a8911ad176ee))
* cap tracked traces and spans-per-trace to bound the trace map ([#418](https://github.com/gma1k/podtrace/issues/418)) ([d6980fe](https://github.com/gma1k/podtrace/commit/d6980fe308058f6183ae30ba07ce8f52bee0df89))
* clamp gRPC status and bound the error_code metric label ([#414](https://github.com/gma1k/podtrace/issues/414)) ([b5996e9](https://github.com/gma1k/podtrace/commit/b5996e962f04cce32bd211803ee9a32735bfc509))
* clear all side maps on the cgroup-prefilter early-out ([#421](https://github.com/gma1k/podtrace/issues/421)) ([e2a2823](https://github.com/gma1k/podtrace/commit/e2a28235533e3f68464210ddd145d9452cc17fce))
* close operator tenancy gaps and bound session/map lifecycles ([#431](https://github.com/gma1k/podtrace/issues/431)) ([abafba5](https://github.com/gma1k/podtrace/commit/abafba52e5ae951fd0d70fe65622c801eaf49e4d))
* close PII redaction gaps and CSV formula injection ([#429](https://github.com/gma1k/podtrace/issues/429)) ([d9fcbc5](https://github.com/gma1k/podtrace/commit/d9fcbc5208e1c4aacead6196332660ad4df71f0a))
* confine kubelet-derived cgroup walk roots to the cgroup base ([#419](https://github.com/gma1k/podtrace/issues/419)) ([c00fcc5](https://github.com/gma1k/podtrace/commit/c00fcc5bd4582b25dadd442a38353258853c28ea))
* correct BPF L7 parser desyncs and wire the gRPC port knob ([#432](https://github.com/gma1k/podtrace/issues/432)) ([4ef0756](https://github.com/gma1k/podtrace/commit/4ef0756db5fbbbe33b06b9dd38d5e018a91a2fbc))
* guard exporter egress against SSRF, cleartext, and redirects ([#423](https://github.com/gma1k/podtrace/issues/423)) ([1adab35](https://github.com/gma1k/podtrace/commit/1adab35e3e444d4b12fce1e29d586b3beb3a9f80))
* harden BPF attribution, bounds, and telemetry integrity ([#430](https://github.com/gma1k/podtrace/issues/430)) ([a70a9dd](https://github.com/gma1k/podtrace/commit/a70a9ddd600464fdb593568f57bd3263c3f896b7))
* harden setup scripts/CI and tracer lifecycle races ([#425](https://github.com/gma1k/podtrace/issues/425)) ([21f7672](https://github.com/gma1k/podtrace/commit/21f76729a1c24b7fff6805fffa744aff1e7d9122))
* honor human bool env values and range-check float config ([#428](https://github.com/gma1k/podtrace/issues/428)) ([f0ef064](https://github.com/gma1k/podtrace/commit/f0ef06453a186c0f211a18dec0a19ae647af0dbd))
* rescope Trivy to vuln/secret and fix code-scanning findings ([#426](https://github.com/gma1k/podtrace/issues/426)) ([8a31278](https://github.com/gma1k/podtrace/commit/8a3127838dd59278c237ea02d84549fea7c7d7eb))
* restore systemd cgroup walk and stop stale h2/h3 record bytes ([#420](https://github.com/gma1k/podtrace/issues/420)) ([dc93e1a](https://github.com/gma1k/podtrace/commit/dc93e1a3e1ed9fb565980a5a344013cb512a788d))
* surface kernel event drops in agent metrics and status ([#422](https://github.com/gma1k/podtrace/issues/422)) ([0f9ec00](https://github.com/gma1k/podtrace/commit/0f9ec00fdfa06eadca15046bdef70fec33b40cef))


### Documentation

* reconcile CRD inventory in STABILITY.md (four -&gt; six) ([#415](https://github.com/gma1k/podtrace/issues/415)) ([64ee6ad](https://github.com/gma1k/podtrace/commit/64ee6ad0638ac78696393cf97f21213a04872a05))


### Maintenance

* **deps:** update golang:1.26.6-trixie docker digest to b75d466 ([#427](https://github.com/gma1k/podtrace/issues/427)) ([33cc98d](https://github.com/gma1k/podtrace/commit/33cc98df00809753685d101ccb7b7a8f49702974))

## [0.14.4](https://github.com/gma1k/podtrace/compare/v0.14.3...v0.14.4) (2026-08-15)


### Bug Fixes

* bound HPACK late-join window by bytes, cap field length ([#412](https://github.com/gma1k/podtrace/issues/412)) ([fdd03fa](https://github.com/gma1k/podtrace/commit/fdd03fa879f39bab1e5acb5bee40ce65ce6ed165))
* bound QPACK dynamic table and sweep idle HTTP/3 connections ([#411](https://github.com/gma1k/podtrace/issues/411)) ([c9f9d63](https://github.com/gma1k/podtrace/commit/c9f9d63386827101f395a994f3d83ddbd09db8c5))
* constrain TracerConfig agent image to a trusted allowlist ([#403](https://github.com/gma1k/podtrace/issues/403)) ([0808e27](https://github.com/gma1k/podtrace/commit/0808e271029967ee999e930550f7c85fb67dd6a1))
* give each event-tee consumer its own copy to end a data race ([#409](https://github.com/gma1k/podtrace/issues/409)) ([f4c5e9d](https://github.com/gma1k/podtrace/commit/f4c5e9d2f946028d2cc90f1e1feaf52f87a02bcb))
* guard tracer map writers against a concurrent Stop ([#406](https://github.com/gma1k/podtrace/issues/406)) ([6a5852a](https://github.com/gma1k/podtrace/commit/6a5852ad16ae5ae79704a1fa4e994fa76c7c819f))
* mount host cgroupfs read-only to close release_agent escap ([#402](https://github.com/gma1k/podtrace/issues/402)) ([b26406a](https://github.com/gma1k/podtrace/commit/b26406a7e3a1b3ea007082f0345d54b5a31bbae0))
* publish tracer cgroup paths atomically to end read race ([#408](https://github.com/gma1k/podtrace/issues/408)) ([3c6189e](https://github.com/gma1k/podtrace/commit/3c6189e1de6fe9d4658bc074093e635fb74610c7))
* size QUIC CRYPTO reassembly from received data, not claimed offset ([#410](https://github.com/gma1k/podtrace/issues/410)) ([c41f3e7](https://github.com/gma1k/podtrace/commit/c41f3e72a1983c0468ad3b6859136a357137e6b0))
* stop the operator caching and cluster-wide-writing every Secret ([#404](https://github.com/gma1k/podtrace/issues/404)) ([1ceaa5e](https://github.com/gma1k/podtrace/commit/1ceaa5ef792fb3713e085bf69c2cfb5596f9d835))


### Maintenance

* auto-maintain Artifact Hub scanned image digests ([#405](https://github.com/gma1k/podtrace/issues/405)) ([d64ef84](https://github.com/gma1k/podtrace/commit/d64ef848d870689e40811110dc0f2f8d7f3a7c7f))
* **deps:** update alpine/k8s docker tag to v1.36.2 ([#407](https://github.com/gma1k/podtrace/issues/407)) ([0882047](https://github.com/gma1k/podtrace/commit/0882047411966887f71aa048d0689bcbf6a4465b))
* **deps:** update dependency helm to v4.2.4 ([#400](https://github.com/gma1k/podtrace/issues/400)) ([a9ca269](https://github.com/gma1k/podtrace/commit/a9ca2692e6f1dd2f81d38b1d97617c7bdaba4287))
* **deps:** update github/codeql-action action to v4.37.7 ([#399](https://github.com/gma1k/podtrace/issues/399)) ([48962ea](https://github.com/gma1k/podtrace/commit/48962ea2806d8e5a53daa75c6d25bce949a7116e))
* **deps:** update go modules (non-major) ([#401](https://github.com/gma1k/podtrace/issues/401)) ([d89f879](https://github.com/gma1k/podtrace/commit/d89f879b90f611c68eec3e15f233e573fae4c976))
* **deps:** update go modules (non-major) ([#413](https://github.com/gma1k/podtrace/issues/413)) ([e2692c6](https://github.com/gma1k/podtrace/commit/e2692c6f26d3a1e51f4f82e668246b0c28072d86))
* **deps:** update golang:1.26.5-trixie docker digest to f1a1324 ([#397](https://github.com/gma1k/podtrace/issues/397)) ([d1aafce](https://github.com/gma1k/podtrace/commit/d1aafce49dc6cbe2f0f95ce16c772afaa026dcb6))

## [0.14.3](https://github.com/gma1k/podtrace/compare/v0.14.2...v0.14.3) (2026-08-12)


### Bug Fixes

* confine uprobe target resolution to the traced workload ([#389](https://github.com/gma1k/podtrace/issues/389)) ([f052485](https://github.com/gma1k/podtrace/commit/f0524859aca35eae9d71fc3a90257ea0bedb73cf))
* skip merge commits in the DCO sign-off check ([#393](https://github.com/gma1k/podtrace/issues/393)) ([8b2f5db](https://github.com/gma1k/podtrace/commit/8b2f5db788c66fc26ef0b5fd4495179016ca3882))
* stop paired-map leak that silently disables the eBPF tracer ([#395](https://github.com/gma1k/podtrace/issues/395)) ([a72f5a1](https://github.com/gma1k/podtrace/commit/a72f5a1cd6dc967d03dc2543765c69a5ed741326))


### Maintenance

* **deps:** update gcr.io/distroless/static-debian12:nonroot docker digest to 1b7b9f0 ([#390](https://github.com/gma1k/podtrace/issues/390)) ([d59ce0d](https://github.com/gma1k/podtrace/commit/d59ce0d3db1b3165c6b1564ae1515328af91c67d))
* **deps:** update go modules (non-major) ([#392](https://github.com/gma1k/podtrace/issues/392)) ([14bfb81](https://github.com/gma1k/podtrace/commit/14bfb81438d246ebba6c84a794420db99b1aab62))
* **deps:** update go modules (non-major) ([#394](https://github.com/gma1k/podtrace/issues/394)) ([3938a8e](https://github.com/gma1k/podtrace/commit/3938a8eed00626714b9286ba65c9eb697edcf83b))
* **deps:** update golang:1.26.5-trixie docker digest to 98988b4 ([#391](https://github.com/gma1k/podtrace/issues/391)) ([ad7a79b](https://github.com/gma1k/podtrace/commit/ad7a79b22ef9e6075c9f79526fe1c6f84b011a2f))
* **deps:** update module cloud.google.com/go/auth to v0.23.0 ([#386](https://github.com/gma1k/podtrace/issues/386)) ([c1a5125](https://github.com/gma1k/podtrace/commit/c1a512596137f8f3087d19022236915d2c736e00))
* **deps:** update module golang.org/x/arch to v0.30.0 ([#388](https://github.com/gma1k/podtrace/issues/388)) ([1aeb9c6](https://github.com/gma1k/podtrace/commit/1aeb9c6ef8fa935ef64075b9817367de2b59a4f1))
* **deps:** update module golang.org/x/net to v0.58.0 ([#396](https://github.com/gma1k/podtrace/issues/396)) ([88dbd61](https://github.com/gma1k/podtrace/commit/88dbd6133ba1511c45ea75da3e5cbb9ee7a75fd8))

## [0.14.2](https://github.com/gma1k/podtrace/compare/v0.14.1...v0.14.2) (2026-08-07)


### Features

* attest every release artifact with SLSA build provenance ([#385](https://github.com/gma1k/podtrace/issues/385)) ([290a0c8](https://github.com/gma1k/podtrace/commit/290a0c802dbee86181c80ac1035d39b5147ce9e5))
* resolve each session Job's TracerConfig per node ([#384](https://github.com/gma1k/podtrace/issues/384)) ([0660b28](https://github.com/gma1k/podtrace/commit/0660b28f04f9a0ed3f46af96def504ee8a3a9733))
* support multiple TracerConfigs as isolated agent fleets ([#382](https://github.com/gma1k/podtrace/issues/382)) ([9ed3d17](https://github.com/gma1k/podtrace/commit/9ed3d17a461ea3f8caee0feef0b736e15d7ca8e9))


### Bug Fixes

* append /v1/traces to OTLP endpoints without a path ([#373](https://github.com/gma1k/podtrace/issues/373)) ([6b876f9](https://github.com/gma1k/podtrace/commit/6b876f983e242eb14908673107028f32527c7aa1))
* **ci:** report dco-check on release-please branches ([#380](https://github.com/gma1k/podtrace/issues/380)) ([72697e8](https://github.com/gma1k/podtrace/commit/72697e862ea806316d0da9894e9db46939f11dc7))
* fix the Go module path and harden the supply chain ([#379](https://github.com/gma1k/podtrace/issues/379)) ([8cd31f1](https://github.com/gma1k/podtrace/commit/8cd31f138bab7f88ebc7ad4528ada023e83f6f7b))


### Tests

* fully cover alert-triggered sessions and gate envtest in CI ([#374](https://github.com/gma1k/podtrace/issues/374)) ([099a06c](https://github.com/gma1k/podtrace/commit/099a06c6ba49e04fbfa53181d37afb17b3f6a502))


### CI

* require DCO sign-off on every commit ([#377](https://github.com/gma1k/podtrace/issues/377)) ([694cb21](https://github.com/gma1k/podtrace/commit/694cb21b792f1e4afda43dbc216531f8c6ecd3c3))
* stabilise chainsaw and skip it for release-please PRs ([#375](https://github.com/gma1k/podtrace/issues/375)) ([7c00165](https://github.com/gma1k/podtrace/commit/7c00165f75e68bee8f9ddae022d8cead4a68bab2))


### Maintenance

* **deps:** update github/codeql-action action to v4.37.5 ([#370](https://github.com/gma1k/podtrace/issues/370)) ([016790b](https://github.com/gma1k/podtrace/commit/016790b4b57afb035ba07ed7480799314699b84c))
* **deps:** update github/codeql-action action to v4.37.6 ([#376](https://github.com/gma1k/podtrace/issues/376)) ([5c9892e](https://github.com/gma1k/podtrace/commit/5c9892e4a37fafe6aac99725f33acf269b8832b9))
* **deps:** update go modules (non-major) ([#372](https://github.com/gma1k/podtrace/issues/372)) ([d1eaeac](https://github.com/gma1k/podtrace/commit/d1eaeaca64680d0c2397199f3c939b41524309dc))
* **deps:** update go modules (non-major) ([#381](https://github.com/gma1k/podtrace/issues/381)) ([f9b30ba](https://github.com/gma1k/podtrace/commit/f9b30baffcea58d6c52bcb5affac6598509ab789))
* **deps:** update module github.com/aws/aws-sdk-go-v2/service/s3 to v1.107.0 ([#383](https://github.com/gma1k/podtrace/issues/383)) ([b22001b](https://github.com/gma1k/podtrace/commit/b22001ba27b9001a082a5c2224330da7b27974bb))
* **deps:** update module google.golang.org/api to v0.292.0 ([#378](https://github.com/gma1k/podtrace/issues/378)) ([ab4f7a8](https://github.com/gma1k/podtrace/commit/ab4f7a8c9c9f85c6488a8649f633c8dab90d01ab))

## [0.14.1](https://github.com/gma1k/podtrace/compare/v0.14.0...v0.14.1) (2026-08-01)


### Features

* surface agent, session and exporter config knobs in the Helm chart ([#355](https://github.com/gma1k/podtrace/issues/355)) ([7b7422a](https://github.com/gma1k/podtrace/commit/7b7422a6e3b0345033017e830203c095da7ba977))
* trigger diagnostic sessions on agent-detected alerts ([#362](https://github.com/gma1k/podtrace/issues/362)) ([6c0896e](https://github.com/gma1k/podtrace/commit/6c0896edfc52daeee60684be0891abe7e41d7158))


### Bug Fixes

* parse boolean env vars via ParseBool so redaction cannot fail open ([#368](https://github.com/gma1k/podtrace/issues/368)) ([4c80a88](https://github.com/gma1k/podtrace/commit/4c80a88d000828fbb0f2dee9f7bf2f561b4cde0b))


### Documentation

* point FOSSA badges at the CI project locator ([#354](https://github.com/gma1k/podtrace/issues/354)) ([3be291b](https://github.com/gma1k/podtrace/commit/3be291b7e507c0034a8c8da9a7dbaa65aa9beb2d))


### CI

* add version, build, tests and coverage badges to README ([#363](https://github.com/gma1k/podtrace/issues/363)) ([eafa076](https://github.com/gma1k/podtrace/commit/eafa0760e9246f954d358b588db04c35325f5e09))
* replace sticky release-as override with one-shot footer trigger ([#350](https://github.com/gma1k/podtrace/issues/350)) ([0723ca6](https://github.com/gma1k/podtrace/commit/0723ca696e4e39572829e1d3dfe712efd3fad4ca))
* scan licenses and dependencies with the FOSSA CLI and exclude the intentional GPL-2.0 bpf/ ([#353](https://github.com/gma1k/podtrace/issues/353)) ([fdad95d](https://github.com/gma1k/podtrace/commit/fdad95d7670d25087a04baa0d2e70dd661310b67))


### Maintenance

* **deps:** update docker/dockerfile docker tag to v1.26 ([#366](https://github.com/gma1k/podtrace/issues/366)) ([d9d1280](https://github.com/gma1k/podtrace/commit/d9d1280e8d8b715d4c109e8be6b28474c9861557))
* **deps:** update docker/login-action action to v4.5.1 ([#352](https://github.com/gma1k/podtrace/issues/352)) ([d997eec](https://github.com/gma1k/podtrace/commit/d997eec95aa5e56d4437c1b1a6cf6cb4ff062e63))
* **deps:** update docker/login-action action to v4.5.2 ([#356](https://github.com/gma1k/podtrace/issues/356)) ([69f7297](https://github.com/gma1k/podtrace/commit/69f7297dbab9ac664c5d0a8a8d633867911c80c1))
* **deps:** update docker/login-action action to v4.6.0 ([#358](https://github.com/gma1k/podtrace/issues/358)) ([df71585](https://github.com/gma1k/podtrace/commit/df71585efc56d3b627d8cac50b87e4566f12fb08))
* **deps:** update gaelgirodon/ci-badges-action digest to 07a6514 ([#365](https://github.com/gma1k/podtrace/issues/365)) ([39c2172](https://github.com/gma1k/podtrace/commit/39c2172ab797ec4523378a822f0ce2ad4451d53a))
* **deps:** update github/codeql-action action to v4.37.4 ([#359](https://github.com/gma1k/podtrace/issues/359)) ([dd3b5ed](https://github.com/gma1k/podtrace/commit/dd3b5ed79eaca1d040c9adc311e8ec4ba4108555))
* **deps:** update go modules (non-major) ([#357](https://github.com/gma1k/podtrace/issues/357)) ([7fffff3](https://github.com/gma1k/podtrace/commit/7fffff34fe2c030f896d58832b97e20490eba82d))
* **deps:** update go modules (non-major) ([#360](https://github.com/gma1k/podtrace/issues/360)) ([aa36654](https://github.com/gma1k/podtrace/commit/aa366547e4411408fb1dc96a430f72bfac272346))
* **deps:** update go modules (non-major) ([#369](https://github.com/gma1k/podtrace/issues/369)) ([d672e48](https://github.com/gma1k/podtrace/commit/d672e48f067b12547f94a47f40405a1e9c0c26d9))
* **deps:** update kubernetes ecosystem to v0.36.3 ([#347](https://github.com/gma1k/podtrace/issues/347)) ([4fc9063](https://github.com/gma1k/podtrace/commit/4fc9063a0457f9245b2bc8d888071d1abc37810d))
* **deps:** update module github.com/prometheus/client_golang to v1.24.1 ([#351](https://github.com/gma1k/podtrace/issues/351)) ([ea4b0cc](https://github.com/gma1k/podtrace/commit/ea4b0cc8e8fce0ec473069fe65f8e3b6ea175fee))
* **deps:** update module google.golang.org/api to v0.290.0 ([#348](https://github.com/gma1k/podtrace/issues/348)) ([8c07967](https://github.com/gma1k/podtrace/commit/8c07967d5d931a5159eaf60407fdd01a945cc477))
* fix issue-form labels, add config.yml and community docs ([#364](https://github.com/gma1k/podtrace/issues/364)) ([6a8efa0](https://github.com/gma1k/podtrace/commit/6a8efa083303dd17ddbc84ee2b7a77ebc1b79be4))
* pin golangci-lint, document code style and config reference ([#367](https://github.com/gma1k/podtrace/issues/367)) ([349bd0f](https://github.com/gma1k/podtrace/commit/349bd0ffdf4d430d74682b68a9407a173a3194e6))

## [0.14.0](https://github.com/gma1k/podtrace/compare/v0.13.10...v0.14.0) (2026-07-22)


### Tests

* broaden unit-test coverage across cmd and internal packages ([#342](https://github.com/gma1k/podtrace/issues/342)) ([2fc4626](https://github.com/gma1k/podtrace/commit/2fc4626aa804092cafaa1d93ad235a5d35a845b3))
* expand unit-test coverage across cmd and internal packages ([#345](https://github.com/gma1k/podtrace/issues/345)) ([414ab25](https://github.com/gma1k/podtrace/commit/414ab2555e314835ea4e1225dba70d710a21c9ce))


### Maintenance

* **deps:** update actions/labeler action to v7 ([#341](https://github.com/gma1k/podtrace/issues/341)) ([d2b3745](https://github.com/gma1k/podtrace/commit/d2b374533a78616db5cb86660394bc3415364aac))
* **deps:** update github actions ([#339](https://github.com/gma1k/podtrace/issues/339)) ([e990afc](https://github.com/gma1k/podtrace/commit/e990afc6952bd3aad692042f58ca5c2e909d9335))
* **deps:** update github/codeql-action action to v4.37.3 ([#344](https://github.com/gma1k/podtrace/issues/344)) ([1e52cea](https://github.com/gma1k/podtrace/commit/1e52cea2874a372b167cbb1c3db4e4667ad773f6))
* **deps:** update go modules (non-major) ([#340](https://github.com/gma1k/podtrace/issues/340)) ([03afb4e](https://github.com/gma1k/podtrace/commit/03afb4e044994be5a14d3d975003e665dd9349fd))
* trigger release 0.14.0 ([#346](https://github.com/gma1k/podtrace/issues/346)) ([7065ee1](https://github.com/gma1k/podtrace/commit/7065ee183c634b85b7065de902fbcfd831fec590))

## [0.13.10](https://github.com/gma1k/podtrace/compare/v0.13.9...v0.13.10) (2026-07-19)


### ⚠ BREAKING CHANGES

* PodTrace/PodTraceSession/PodTraceSchedule CRs can no longer target pods in another namespace unless that namespace opts in via the podtrace.io/allow-tracing-from annotation. Existing cross-namespace CRs silently narrow to their own namespace until the target namespaces are annotated.

### Features

* attribute cgroup_skb events to owning process at ingest ([#327](https://github.com/gma1k/podtrace/issues/327)) ([f09f667](https://github.com/gma1k/podtrace/commit/f09f6672bceaa91cb06e321c2e2b6857ccea15fa))
* wire USDT tracing and full DNS answer decode into the agent ([#333](https://github.com/gma1k/podtrace/issues/333)) ([9070bbf](https://github.com/gma1k/podtrace/commit/9070bbf750980c5939cc8f9fb8596e0611e42502))


### Bug Fixes

* bound process_name label cardinality in all metric exporters ([#329](https://github.com/gma1k/podtrace/issues/329)) ([bb445f3](https://github.com/gma1k/podtrace/commit/bb445f314c2f54b1c185e1ce53a32aba36dd2210))
* gate cross-namespace tracing on target-namespace consent ([#328](https://github.com/gma1k/podtrace/issues/328)) ([acc5944](https://github.com/gma1k/podtrace/commit/acc594401e1e8f38c06c3770cfbf791c0e5cccd6))
* harden cgroup match, numeric conversions, router, and DNS report ([#338](https://github.com/gma1k/podtrace/issues/338)) ([a0c8cec](https://github.com/gma1k/podtrace/commit/a0c8cec026d6a38f005d1daea82ecff37f89b316))
* harden fastcgi/dns/grpc L7 parsing against malformed input ([#334](https://github.com/gma1k/podtrace/issues/334)) ([b02ce31](https://github.com/gma1k/podtrace/commit/b02ce31d6cfcd3491c02ec6953aa6023acbc021f))
* harden graph, truncation, nil derefs, and analyzer bounds ([#337](https://github.com/gma1k/podtrace/issues/337)) ([0e8c21d](https://github.com/gma1k/podtrace/commit/0e8c21d1d71a1778118cec090da5ea8ad21d009b))
* harden session child GC, dedup, env parsing, and artifact perms ([#336](https://github.com/gma1k/podtrace/issues/336)) ([88f4187](https://github.com/gma1k/podtrace/commit/88f41876e016b3627755397bae00d0e92d67bfe6))
* harden session lifecycle and exporter endpoint validation ([#330](https://github.com/gma1k/podtrace/issues/330)) ([333ab38](https://github.com/gma1k/podtrace/commit/333ab38823bb6d96e9e9bbfc0d7dabe4bc938a60))
* redact session/auth headers and harden pid-reuse attribution guard ([#332](https://github.com/gma1k/podtrace/issues/332)) ([8395355](https://github.com/gma1k/podtrace/commit/8395355054854e674f1671d650a96fdb488030a1))
* resolve container main PID and store Splunk token in a Secret ([#335](https://github.com/gma1k/podtrace/issues/335)) ([69e9956](https://github.com/gma1k/podtrace/commit/69e995688b47a01e941ade626b35596569bd883f))
* strip terminal control sequences from diagnose reports and sort kallsyms in n log n ([#331](https://github.com/gma1k/podtrace/issues/331)) ([7642ff3](https://github.com/gma1k/podtrace/commit/7642ff3f524cfe412a23bea8129721e0dbfe8a73))


### Maintenance

* **deps:** update go modules (non-major) ([#325](https://github.com/gma1k/podtrace/issues/325)) ([7e9179e](https://github.com/gma1k/podtrace/commit/7e9179ef7bef7af046b4825db69171f65dba15c2))
* release 0.13.10 ([2834c35](https://github.com/gma1k/podtrace/commit/2834c35b6251575ba436bfbcc0d4f810014c0fbb))

## [0.13.9](https://github.com/gma1k/podtrace/compare/v0.13.8...v0.13.9) (2026-07-16)


### Features

* probe every distinct binary in a container for uprobes ([#320](https://github.com/gma1k/podtrace/issues/320)) ([0461b10](https://github.com/gma1k/podtrace/commit/0461b10efaffe47db2b482712d3b2a23ed896582))
* trace every container of a targeted pod by default ([#323](https://github.com/gma1k/podtrace/issues/323)) ([19d3fe5](https://github.com/gma1k/podtrace/commit/19d3fe5eb05312512a78a40cdbbb6aee76ec86a2))


### Bug Fixes

* gate container uprobes correctly and add missing SYS_PTRACE ([#319](https://github.com/gma1k/podtrace/issues/319)) ([772f0ad](https://github.com/gma1k/podtrace/commit/772f0ad66a0793062b12e67b827f7bc8b6e033ff))


### Maintenance

* **deps:** update actions/setup-go action to v7 ([#322](https://github.com/gma1k/podtrace/issues/322)) ([88e97b2](https://github.com/gma1k/podtrace/commit/88e97b2153c970ed286aa595b60c45e13dcd8201))
* **deps:** update github/codeql-action action to v4.37.1 ([#324](https://github.com/gma1k/podtrace/issues/324)) ([e1f1777](https://github.com/gma1k/podtrace/commit/e1f1777059621b8e11d28008a4535bba32f8bf2e))
* **deps:** update go modules (non-major) ([#318](https://github.com/gma1k/podtrace/issues/318)) ([4d8f3a6](https://github.com/gma1k/podtrace/commit/4d8f3a654331ec453c5b7656221768d2b9f28846))
* **deps:** update module cloud.google.com/go/storage to v1.63.1 ([#315](https://github.com/gma1k/podtrace/issues/315)) ([da5df5d](https://github.com/gma1k/podtrace/commit/da5df5d8357aa676702a07af0e3178d0e0f825d4))
* **deps:** update module google.golang.org/grpc to v1.82.1 ([#321](https://github.com/gma1k/podtrace/issues/321)) ([982a4ab](https://github.com/gma1k/podtrace/commit/982a4ab60bacdca3a72975e92396c62e9e64b20e))
* **deps:** update softprops/action-gh-release action to v3.0.2 ([#317](https://github.com/gma1k/podtrace/issues/317)) ([5dd8ca7](https://github.com/gma1k/podtrace/commit/5dd8ca756f947ee12677f2e1804653a4c65c4a1b))

## [0.13.8](https://github.com/gma1k/podtrace/compare/v0.13.7...v0.13.8) (2026-07-12)


### Features

* bound and sandbox untrusted container-binary parsing ([#297](https://github.com/gma1k/podtrace/issues/297)) ([1306fa4](https://github.com/gma1k/podtrace/commit/1306fa4fd1cbe24ce342862164377b94fca2ce7e))
* graceful L7 degradation via bpf_loop probe and low-severity fixes ([#314](https://github.com/gma1k/podtrace/issues/314)) ([742cdb9](https://github.com/gma1k/podtrace/commit/742cdb9a3cbb6be3fcb88022c85ddc63832a8dd8))
* per-pod multi-pod diagnose/profiling and cmd/ fixes ([#308](https://github.com/gma1k/podtrace/issues/308)) ([1ff1c5d](https://github.com/gma1k/podtrace/commit/1ff1c5d992918da16dca03724c7943d70a3c3685))
* synthesize L7 spans and fix span identity ([#289](https://github.com/gma1k/podtrace/issues/289)) ([f37410e](https://github.com/gma1k/podtrace/commit/f37410ed96fdeec0a6893dd326d5599ee2890356))


### Bug Fixes

* build arm64 BPF objects with correct arch registers ([#298](https://github.com/gma1k/podtrace/issues/298)) ([bc1ed43](https://github.com/gma1k/podtrace/commit/bc1ed43473f1964ef2d34ee838163f477318d019))
* correct multi-namespace targeting and bundle/report lifecycle ([#307](https://github.com/gma1k/podtrace/issues/307)) ([33d390d](https://github.com/gma1k/podtrace/commit/33d390d08d14b1025720caf1692f2ecac98407fc))
* correct protocol-edge decoding and bound diagnose/tracer memory ([#309](https://github.com/gma1k/podtrace/issues/309)) ([b0b695a](https://github.com/gma1k/podtrace/commit/b0b695a33dca953ed404a9d1b44d8fea27b28f94))
* drop bpf_get_current_comm from cgroup_skb programs ([#304](https://github.com/gma1k/podtrace/issues/304)) ([14ef4f8](https://github.com/gma1k/podtrace/commit/14ef4f852d48b5643a3b20063ed101f12835d6b1))
* export session events and evict consumed stack traces ([#285](https://github.com/gma1k/podtrace/issues/285)) ([31fb7e0](https://github.com/gma1k/podtrace/commit/31fb7e0c1dd00ac0661261f4e04bad61ab725c39))
* harden agent security posture, chart schema, and CI drift gates ([#313](https://github.com/gma1k/podtrace/issues/313)) ([f95ee13](https://github.com/gma1k/podtrace/commit/f95ee13fefaf531e3e7389d941284452767c2b44))
* harden operator session lifecycle and agent exporters ([#311](https://github.com/gma1k/podtrace/issues/311)) ([c9d1e81](https://github.com/gma1k/podtrace/commit/c9d1e8139cd841b5bfa282ed768176818c320567))
* make tcp_peer_stash LRU so peer fusion survives thread churn ([#291](https://github.com/gma1k/podtrace/issues/291)) ([9c17ccb](https://github.com/gma1k/podtrace/commit/9c17ccb12c66f5d8ffcac3a238594bfb128fe505))
* repair cgroup v1 resource monitoring and agent credential rotation ([#302](https://github.com/gma1k/podtrace/issues/302)) ([6f60f74](https://github.com/gma1k/podtrace/commit/6f60f748f3948b363f3c3371d5f491fdaba3e07a))
* repair diagnose report math, tracer lifecycle, and validation ([#312](https://github.com/gma1k/podtrace/issues/312)) ([0c48915](https://github.com/gma1k/podtrace/commit/0c489155dcce794bdfd8f310faf892136638b13a))
* report HTTP latency from responses and CPU% as a windowed delta ([#293](https://github.com/gma1k/podtrace/issues/293)) ([895dbd6](https://github.com/gma1k/podtrace/commit/895dbd6f6173b3f2256542fbdd0ccbaa7aaaac28))
* resolve eBPF verifier rejections in HTTP and DNS probes ([#303](https://github.com/gma1k/podtrace/issues/303)) ([4f48a9b](https://github.com/gma1k/podtrace/commit/4f48a9b1cf003ce89f821633fbe642ddbd46b6cb))
* stop resource alerts poisoning Event.Error consumers ([#292](https://github.com/gma1k/podtrace/issues/292)) ([fb34e7a](https://github.com/gma1k/podtrace/commit/fb34e7aae457529b9816fd2b9f158e53466a792b))


### Build System

* bump Go to 1.26.5 and add govulncheck to CI ([#306](https://github.com/gma1k/podtrace/issues/306)) ([ae05c55](https://github.com/gma1k/podtrace/commit/ae05c55e5487eb2eba460315372f4dff9506db5c))


### Maintenance

* **deps:** update actions/download-artifact action to v8 ([#299](https://github.com/gma1k/podtrace/issues/299)) ([e8ebc79](https://github.com/gma1k/podtrace/commit/e8ebc79e4d7dbad0d65587d7ba10114a5ed8284e))
* **deps:** update actions/labeler action to v6.2.0 ([#301](https://github.com/gma1k/podtrace/issues/301)) ([bd15db6](https://github.com/gma1k/podtrace/commit/bd15db67b07f421c6d2b88ff974b11011d02d9b2))
* **deps:** update github/codeql-action action to v4.37.0 ([#295](https://github.com/gma1k/podtrace/issues/295)) ([dddfce3](https://github.com/gma1k/podtrace/commit/dddfce3583b15c3d6ec5ca14e8a3ff4f9188f9d5))
* **deps:** update go modules (non-major) ([#287](https://github.com/gma1k/podtrace/issues/287)) ([6e8bd3e](https://github.com/gma1k/podtrace/commit/6e8bd3e19c826e020a6b5a0dd25d287fed565b61))
* **deps:** update go modules (non-major) ([#296](https://github.com/gma1k/podtrace/issues/296)) ([08ebbe2](https://github.com/gma1k/podtrace/commit/08ebbe214fff554e432ec6811d1c327fba689813))
* **deps:** update go modules (non-major) ([#300](https://github.com/gma1k/podtrace/issues/300)) ([2aef602](https://github.com/gma1k/podtrace/commit/2aef6020f3eb2475bc0b901569391d77d09f72d4))
* **deps:** update module google.golang.org/api to v0.288.0 ([#305](https://github.com/gma1k/podtrace/issues/305)) ([70c38f3](https://github.com/gma1k/podtrace/commit/70c38f34f142680dc3ef2b119d90c996dd893ddb))
* **deps:** update module sigs.k8s.io/structured-merge-diff/v6 to v6.4.1 ([#288](https://github.com/gma1k/podtrace/issues/288)) ([ecbb02e](https://github.com/gma1k/podtrace/commit/ecbb02e1346f25fb5172655e29261118b03e28b1))
* **deps:** update module sigs.k8s.io/structured-merge-diff/v6 to v6.4.2 ([#294](https://github.com/gma1k/podtrace/issues/294)) ([317c1ba](https://github.com/gma1k/podtrace/commit/317c1ba2d9e13fe0b3f395360514fca59e687637))
* **deps:** update oras-project/setup-oras action to v2.0.1 ([#310](https://github.com/gma1k/podtrace/issues/310)) ([9a3301d](https://github.com/gma1k/podtrace/commit/9a3301d02745765c981d9d560cacb8fbf1f6a86c))

## [0.13.7](https://github.com/gma1k/podtrace/compare/v0.13.6...v0.13.7) (2026-07-05)


### Features

* decode HTTP/2 :path mid-stream and stop idle-agent whole-node OOM ([#283](https://github.com/gma1k/podtrace/issues/283)) ([1f9e190](https://github.com/gma1k/podtrace/commit/1f9e190894101d46b4978edf96f5fad48f03e2ca))
* decode inbound HTTP/3 adapter headers and probe quiche crate ([#284](https://github.com/gma1k/podtrace/issues/284)) ([0ba9a08](https://github.com/gma1k/podtrace/commit/0ba9a08ffc375f61819a061c15b8c58eaf6c4885))
* harden HTTP/3 tracing with peer fusion, QUIC v2, and adapters ([#280](https://github.com/gma1k/podtrace/issues/280)) ([d5190bc](https://github.com/gma1k/podtrace/commit/d5190bc16847f3a3166149a448de29f1eea9c232))


### Maintenance

* **deps:** update docker/login-action action to v4.4.0 ([#282](https://github.com/gma1k/podtrace/issues/282)) ([b85af11](https://github.com/gma1k/podtrace/commit/b85af113108e98b0543ef68551d685b9fcf8f53e))

## [0.13.6](https://github.com/gma1k/podtrace/compare/v0.13.5...v0.13.6) (2026-07-02)


### Features

* capture grpc-go and netty-tcnative HTTP/2 L7 over TLS ([#272](https://github.com/gma1k/podtrace/issues/272)) ([9a4db41](https://github.com/gma1k/podtrace/commit/9a4db411a14dce4266234ae68e11f049b068147e))
* capture inbound HTTP/1.x server-side via connection keying ([#269](https://github.com/gma1k/podtrace/issues/269)) ([4d908d5](https://github.com/gma1k/podtrace/commit/4d908d5cfe063db70f9f5f8a1fa2effcbb28a867))
* capture rustls (Rust) TLS L7 via plaintext uprobes ([#276](https://github.com/gma1k/podtrace/issues/276)) ([40eeb1c](https://github.com/gma1k/podtrace/commit/40eeb1c51197442d26c12d0144f0d3ff7e2cf779))
* harden HTTP/3 L7 with DWARF offsets and traceparent capture ([#267](https://github.com/gma1k/podtrace/issues/267)) ([7b982d8](https://github.com/gma1k/podtrace/commit/7b982d85a37ebb42be58ee6490841db28d413555))
* resolve rustls symbols under v0 mangling and via debug files ([#278](https://github.com/gma1k/podtrace/issues/278)) ([bde6ae8](https://github.com/gma1k/podtrace/commit/bde6ae82339e745ac57159e98929e27c1645d1bd))


### Bug Fixes

* reject TLS records in h2c frame detection to drop ciphertext noise ([#277](https://github.com/gma1k/podtrace/issues/277)) ([93c58de](https://github.com/gma1k/podtrace/commit/93c58de370ef2351202c6332776811c009f58170))


### Tests

* cover quicinitial QUIC Initial parsing and agent copy-fail alert ([#279](https://github.com/gma1k/podtrace/issues/279)) ([f573d16](https://github.com/gma1k/podtrace/commit/f573d163dd1bb6f5e19a5843dfd6aad0cf622ad5))


### Maintenance

* **deps:** update github actions ([#273](https://github.com/gma1k/podtrace/issues/273)) ([864585c](https://github.com/gma1k/podtrace/commit/864585cdbf4ba6ace0a70eee79b55bde985d2383))
* **deps:** update github actions ([#275](https://github.com/gma1k/podtrace/issues/275)) ([025479f](https://github.com/gma1k/podtrace/commit/025479fe3e507a4cf807111cd2d94f9c144c70f4))
* **deps:** update go modules (non-major) ([#274](https://github.com/gma1k/podtrace/issues/274)) ([58f6785](https://github.com/gma1k/podtrace/commit/58f6785a43215f32de9e0a60d106823d9690801c))
* **deps:** update module google.golang.org/api to v0.287.0 ([#271](https://github.com/gma1k/podtrace/issues/271)) ([4966153](https://github.com/gma1k/podtrace/commit/4966153dc50f3a09b07082048e8a0a12c5388ffb))
* **deps:** update module google.golang.org/grpc to v1.82.0 ([#270](https://github.com/gma1k/podtrace/issues/270)) ([2383ea3](https://github.com/gma1k/podtrace/commit/2383ea34a1d24825c8b4e675d334323af0252030))

## [0.13.5](https://github.com/gma1k/podtrace/compare/v0.13.4...v0.13.5) (2026-06-29)


### Features

* attach TLS uprobes by offset via build-id debug info ([#261](https://github.com/gma1k/podtrace/issues/261)) ([9381c7d](https://github.com/gma1k/podtrace/commit/9381c7d77b97f1482e29b220d0249749acc8544b))
* capture HTTP/3 (QUIC) connections and SNI from the Initial packet ([#263](https://github.com/gma1k/podtrace/issues/263)) ([a535199](https://github.com/gma1k/podtrace/commit/a535199a9cb87d5d4e3273c2d279b3cae1ab4b1f))
* capture Node.js HTTPS h1 + h2 over TLS, client and server ([#259](https://github.com/gma1k/podtrace/issues/259)) ([90b03f1](https://github.com/gma1k/podtrace/commit/90b03f1d67756ae887d34150b34644e83e58979a))
* capture TLS L7 by resolving SSL symbols from .symtab ([#260](https://github.com/gma1k/podtrace/issues/260)) ([cc43ec9](https://github.com/gma1k/podtrace/commit/cc43ec9a1f77fdba22d19d4dc80eb058bd481b4c))
* decode HTTP/3 (QUIC) L7 requests and responses for quic-go ([#265](https://github.com/gma1k/podtrace/issues/265)) ([e801bc3](https://github.com/gma1k/podtrace/commit/e801bc34dd76bde0d0ce05782542d54a1d1f0cce))
* fuse L4 peer 4-tuple onto L7 events ([#262](https://github.com/gma1k/podtrace/issues/262)) ([e715fa7](https://github.com/gma1k/podtrace/commit/e715fa7231898825f3cb692327fe913adaf83783))


### Bug Fixes

* harden HTTP/2 userspace decode egress chunking, Go reads, buffer ([#257](https://github.com/gma1k/podtrace/issues/257)) ([f99c3ce](https://github.com/gma1k/podtrace/commit/f99c3cec3510a16bd35d89c4d803d7fb7f4e1312))


### Maintenance

* **deps:** update go modules (non-major) ([#266](https://github.com/gma1k/podtrace/issues/266)) ([506fd95](https://github.com/gma1k/podtrace/commit/506fd95811ed26dd77b95f13b8212d9ddd69549d))
* **deps:** update golangci/golangci-lint-action action to v9.3.0 ([#264](https://github.com/gma1k/podtrace/issues/264)) ([c2921d1](https://github.com/gma1k/podtrace/commit/c2921d1cedc814d684c89e17d845e77085fb1282))

## [0.13.4](https://github.com/gma1k/podtrace/compare/v0.13.3...v0.13.4) (2026-06-27)


### Features

* capture HTTP/2 (h2c) and Go crypto/tls L7 endpoints ([#253](https://github.com/gma1k/podtrace/issues/253)) ([323e34a](https://github.com/gma1k/podtrace/commit/323e34ae8f3717d17eb4f98a310f5d87b8d631c8))
* capture HTTPS endpoints via SSL_read/SSL_write uprobes ([#251](https://github.com/gma1k/podtrace/issues/251)) ([cd11ea7](https://github.com/gma1k/podtrace/commit/cd11ea76bf7d71911f2d6c6deb8c31a63c6e8b5a))
* decode HTTP/2 HPACK in userspace, deleting the in-kernel decoder ([#255](https://github.com/gma1k/podtrace/issues/255)) ([4efb74d](https://github.com/gma1k/podtrace/commit/4efb74d2696b64a1187383338b9d7aeeeea4b2a2))
* harden Go crypto/tls tracing (stripped binaries, arm64) ([#254](https://github.com/gma1k/podtrace/issues/254)) ([bc05aa7](https://github.com/gma1k/podtrace/commit/bc05aa7e92cd8c3eacc7a6d73a396b5e023ef376))
* stitch eBPF kernel spans into the apps OpenTelemetry trace ([#249](https://github.com/gma1k/podtrace/issues/249)) ([b7f5bee](https://github.com/gma1k/podtrace/commit/b7f5beef917ecacc86b6ad46f667cfa0876d2939))
* trace HTTP/1.x endpoints from sockets with zero instrumentation ([#248](https://github.com/gma1k/podtrace/issues/248)) ([831e57d](https://github.com/gma1k/podtrace/commit/831e57dee156f01816cd6d199a8c145a36f0f084))


### Maintenance

* **deps:** update github actions ([#246](https://github.com/gma1k/podtrace/issues/246)) ([ac65cd2](https://github.com/gma1k/podtrace/commit/ac65cd2b5c312e3bc87afed9d4a456c9b7be9797))
* **deps:** update module cloud.google.com/go/storage to v1.63.0 ([#250](https://github.com/gma1k/podtrace/issues/250)) ([5df4780](https://github.com/gma1k/podtrace/commit/5df47800fd644ef137f307359877eb6d338f6f69))
* **deps:** update module github.com/cilium/ebpf to v0.22.0 ([#252](https://github.com/gma1k/podtrace/issues/252)) ([681c607](https://github.com/gma1k/podtrace/commit/681c607e484d19ef688aa15e5768c60517650f8b))

## [0.13.3](https://github.com/gma1k/podtrace/compare/v0.13.2...v0.13.3) (2026-06-22)


### Features

* detect unprivileged AF_ALG aead binds (CVE-2026-31431 Copy-Fail) ([#243](https://github.com/gma1k/podtrace/issues/243)) ([3b6c49f](https://github.com/gma1k/podtrace/commit/3b6c49f66d6980501cb62fd7161036b7184a581e))
* wire PII redaction through TracerConfig and honor custom rules ([#242](https://github.com/gma1k/podtrace/issues/242)) ([7d82d3c](https://github.com/gma1k/podtrace/commit/7d82d3cdc72b166acce6be779db338386b377743))


### Maintenance

* **deps:** pin helm to v4.2.2 and free runner disk in chainsaw ([#240](https://github.com/gma1k/podtrace/issues/240)) ([f9ea5fa](https://github.com/gma1k/podtrace/commit/f9ea5fa08eb756bc7d018f27d5801fb031a27a5d))
* **deps:** update docker/dockerfile docker tag to v1.25 ([#238](https://github.com/gma1k/podtrace/issues/238)) ([dfc1c7a](https://github.com/gma1k/podtrace/commit/dfc1c7a1493cc614df2184e22f18b53be6dc8140))
* **deps:** update github actions to v3.0.1 ([#241](https://github.com/gma1k/podtrace/issues/241)) ([3da05f3](https://github.com/gma1k/podtrace/commit/3da05f327fcbfba3d84f5156f7eec3a0995861aa))
* **deps:** update github actions to v7 ([#239](https://github.com/gma1k/podtrace/issues/239)) ([307fe16](https://github.com/gma1k/podtrace/commit/307fe161667e38022dc101c87f8b95fd4958428c))
* **deps:** update go modules (non-major) ([#236](https://github.com/gma1k/podtrace/issues/236)) ([8722398](https://github.com/gma1k/podtrace/commit/87223988f0aa9de713da2abb4ecd3e5a70afd744))
* **deps:** update go modules (non-major) ([#244](https://github.com/gma1k/podtrace/issues/244)) ([a40827c](https://github.com/gma1k/podtrace/commit/a40827c7101104bbb13fefc7138590c3ca08296f))
* **deps:** update go modules (non-major) to v1.14.0 ([#235](https://github.com/gma1k/podtrace/issues/235)) ([bcae399](https://github.com/gma1k/podtrace/commit/bcae399cd152e5e4e3a25f30356ab0da4331686e))
* **deps:** update go modules (non-major) to v1.8.0 ([#233](https://github.com/gma1k/podtrace/issues/233)) ([8308935](https://github.com/gma1k/podtrace/commit/83089350fe41a61543829908cf25a9a7a782bdda))

## [0.13.2](https://github.com/gma1k/podtrace/compare/v0.13.1...v0.13.2) (2026-06-13)


### Bug Fixes

* **ci:** download static bpftool ([#231](https://github.com/gma1k/podtrace/issues/231)) ([c06df08](https://github.com/gma1k/podtrace/commit/c06df0800c7f48dc766c950700c96014e9d4096a))

## [0.13.1](https://github.com/gma1k/podtrace/compare/v0.13.0...v0.13.1) (2026-06-13)


### Bug Fixes

* **ci:** guarantee a working bpftool on hosted runners for the release BTF guard ([#229](https://github.com/gma1k/podtrace/issues/229)) ([494bae0](https://github.com/gma1k/podtrace/commit/494bae0bd63f70473b6dab27ba389d7098f7c6db))

## [0.13.0](https://github.com/gma1k/podtrace/compare/v0.12.10...v0.13.0) (2026-06-13)


### Features

* deliver per-cgroup resource-limit alerts from the agent ([#224](https://github.com/gma1k/podtrace/issues/224)) ([3c25113](https://github.com/gma1k/podtrace/commit/3c25113cad954829aeed58bb3c09b13969f10d2d))


### Bug Fixes

* harden agent routing, k8s resolution, and nodespawn lifecycle ([#217](https://github.com/gma1k/podtrace/issues/217)) ([f77680a](https://github.com/gma1k/podtrace/commit/f77680a229664d2a729ce52079679c7276c9974d))
* harden CLI lifecycle, bundle wire format, and tracer engine ([#220](https://github.com/gma1k/podtrace/issues/220)) ([b3b9de4](https://github.com/gma1k/podtrace/commit/b3b9de4fd297ac5c7cc9e17c2d4ed60ba4530011))
* harden exporters, alerting, metrics, and resource monitoring ([#218](https://github.com/gma1k/podtrace/issues/218)) ([8ecb383](https://github.com/gma1k/podtrace/commit/8ecb3830a72145e3ea80d3438fdc5ea00a3951a7))
* harden operator reconcile loops against conflict and drift ([#215](https://github.com/gma1k/podtrace/issues/215)) ([dc0a96d](https://github.com/gma1k/podtrace/commit/dc0a96d8d0e2d438bc7e5cfc81dc0680feb7f8af))
* make BPF builds BTF-complete and harden chart, CI, and tests ([#221](https://github.com/gma1k/podtrace/issues/221)) ([1218381](https://github.com/gma1k/podtrace/commit/1218381fa2913c6b23fe30b5502a88d5a27fc577))
* **renovate:** match helm uses-with dep name so v4.2.1 skip applies ([9de9ef0](https://github.com/gma1k/podtrace/commit/9de9ef0e1f88d152c7edc2e2e45273114089a0a0))
* **renovate:** replace removed ignoreVersions with allowedVersions ([#227](https://github.com/gma1k/podtrace/issues/227)) ([13fbb18](https://github.com/gma1k/podtrace/commit/13fbb18fac66e080281c4aa4cea9792886ca2437))


### Maintenance

* **deps:** update github actions to v4.2.1 ([#219](https://github.com/gma1k/podtrace/issues/219)) ([310c40d](https://github.com/gma1k/podtrace/commit/310c40d51adbaa787ca166586cc306628c502c3f))
* **deps:** update kubernetes ecosystem to v0.36.2 ([#223](https://github.com/gma1k/podtrace/issues/223)) ([cfbeebd](https://github.com/gma1k/podtrace/commit/cfbeebd9c01d8aad31eb68fe0c642c560efa7074))
* trigger release 0.13.0 ([#226](https://github.com/gma1k/podtrace/issues/226)) ([85d0df6](https://github.com/gma1k/podtrace/commit/85d0df65da0973bcbac042c24af2e8d920656892))

## [0.12.10](https://github.com/gma1k/podtrace/compare/v0.12.9...v0.12.10) (2026-06-11)


### Features

* add auto rebase for olm auto release script ([#205](https://github.com/gma1k/podtrace/issues/205)) ([e61de99](https://github.com/gma1k/podtrace/commit/e61de992b61fcdd04f41d2c6b730aeec3d8f2b02))


### Bug Fixes

* export spans once, surface exporter errors, tee event pipeline ([#208](https://github.com/gma1k/podtrace/issues/208)) ([1247be8](https://github.com/gma1k/podtrace/commit/1247be80b90312b4496b4c8a6a62c55d9126ae8e))
* rate-based utilization, metric caps, probe lifecycle, GCS abort ([#209](https://github.com/gma1k/podtrace/issues/209)) ([2df8803](https://github.com/gma1k/podtrace/commit/2df8803e03c3c599e52fd0ce48473ce183b5f7b7))
* wire OLM bootstrap image and split quickstart manifests ([#211](https://github.com/gma1k/podtrace/issues/211)) ([4ed4ece](https://github.com/gma1k/podtrace/commit/4ed4eceeb80cc0fba667292f5b2480b789490e7f))
* wire systemNamespace override, OTLP headers, exporter close order ([#207](https://github.com/gma1k/podtrace/issues/207)) ([e559c5b](https://github.com/gma1k/podtrace/commit/e559c5ba2f4d109244abe05266dc3ad7d2fd25b6))


### Maintenance

* **deps:** update github actions to v3.21.0 ([#212](https://github.com/gma1k/podtrace/issues/212)) ([01cbf31](https://github.com/gma1k/podtrace/commit/01cbf318dc87b3efebd77dd77a1433c1d21aeef0))
* **deps:** update github actions to v4 ([#214](https://github.com/gma1k/podtrace/issues/214)) ([85ee02b](https://github.com/gma1k/podtrace/commit/85ee02b9d3aa56e7edde18734d3ac92209955943))
* **deps:** update go modules (non-major) ([#210](https://github.com/gma1k/podtrace/issues/210)) ([6ebf36c](https://github.com/gma1k/podtrace/commit/6ebf36c0ac3420ad2f9ef06dffc163d08f2c87f0))

## [0.12.9](https://github.com/gma1k/podtrace/compare/v0.12.8...v0.12.9) (2026-06-10)


### Features

* revive dead eBPF probes and correct event data semantics ([#204](https://github.com/gma1k/podtrace/issues/204)) ([d625421](https://github.com/gma1k/podtrace/commit/d625421c5a834b2d15d19f32ae44f34d8645403f))


### Bug Fixes

* add ApplicationTrace to OLM CSV and sync operator RBAC ([#200](https://github.com/gma1k/podtrace/issues/200)) ([3386d3a](https://github.com/gma1k/podtrace/commit/3386d3a7e5f8fe1a5c435cf8dcacb9cd2b183260))
* anchor BPF event timestamps to wall clock ([#202](https://github.com/gma1k/podtrace/issues/202)) ([fdec2a4](https://github.com/gma1k/podtrace/commit/fdec2a4296468540f126e3c47d3bce567490f952))


### Maintenance

* **deps:** update go modules (non-major) ([#203](https://github.com/gma1k/podtrace/issues/203)) ([2e2fe21](https://github.com/gma1k/podtrace/commit/2e2fe214b1b6a6b51016039989f89465bc82410a))

## [0.12.8](https://github.com/gma1k/podtrace/compare/v0.12.7...v0.12.8) (2026-06-08)


### Features

* add application targeting appSelector and ApplicationTrace CRD ([#197](https://github.com/gma1k/podtrace/issues/197)) ([27d15f4](https://github.com/gma1k/podtrace/commit/27d15f46debe899318546b053327a6b614b90179))


### Tests

* improve coverage; fix nondeterministic mode-loop select ([#198](https://github.com/gma1k/podtrace/issues/198)) ([06f45a7](https://github.com/gma1k/podtrace/commit/06f45a7e14d08243801c8fa5b4cda907555bc877))


### Maintenance

* **deps:** update github actions to v6.0.2 ([#194](https://github.com/gma1k/podtrace/issues/194)) ([e2c4138](https://github.com/gma1k/podtrace/commit/e2c413829a93609e60ae6ea6280345b2bc908c7d))
* **deps:** update github actions to v7 ([#195](https://github.com/gma1k/podtrace/issues/195)) ([e4bb67c](https://github.com/gma1k/podtrace/commit/e4bb67c5a818685ca78d55c0c92a2487afcecbc8))
* **deps:** update go modules (non-major) ([#199](https://github.com/gma1k/podtrace/issues/199)) ([f5502d7](https://github.com/gma1k/podtrace/commit/f5502d77f0d7f8e3a11d335b3908add5ab02357d))

## [0.12.7](https://github.com/gma1k/podtrace/compare/v0.12.6...v0.12.7) (2026-06-06)


### Bug Fixes

* bucket timeline by event clock and clarify DNS fallback log ([#192](https://github.com/gma1k/podtrace/issues/192)) ([b96b0bb](https://github.com/gma1k/podtrace/commit/b96b0bbf66ec187451944ce1422661f77ed8b6ce))

## [0.12.6](https://github.com/gma1k/podtrace/compare/v0.12.5...v0.12.6) (2026-06-06)


### Features

* add libc-independent DNS packet capture with v4/v6 parity ([#191](https://github.com/gma1k/podtrace/issues/191)) ([0846b77](https://github.com/gma1k/podtrace/commit/0846b771392ae230c60b1aa77f69d6c347d87915))


### Bug Fixes

* quieter startup warnings and workstation-side event correlation ([#190](https://github.com/gma1k/podtrace/issues/190)) ([8c23bd8](https://github.com/gma1k/podtrace/commit/8c23bd809fbe9ab21f678e009b99d822f20f81b9))
* timeline bucket overlap ([#186](https://github.com/gma1k/podtrace/issues/186)) and OLM workflow-scope push ([#188](https://github.com/gma1k/podtrace/issues/188)) ([50bcf50](https://github.com/gma1k/podtrace/commit/50bcf50126849a3fa3036360e4e91c7b54230287))

## [0.12.5](https://github.com/gma1k/podtrace/compare/v0.12.4...v0.12.5) (2026-06-05)


### Features

* add --app/--label application targeting (ephemeral + managed) ([#182](https://github.com/gma1k/podtrace/issues/182)) ([73aa96e](https://github.com/gma1k/podtrace/commit/73aa96e052f283474495054a7864721d04b31b56))


### Bug Fixes

* default namespace to current kubeconfig context ([#185](https://github.com/gma1k/podtrace/issues/185)) ([efa6f3a](https://github.com/gma1k/podtrace/commit/efa6f3a95bada8a89dea8b2c2af5c3897905d4f0))
* derive docker GO_VERSION from go.mod with GOTOOLCHAIN=auto ([#180](https://github.com/gma1k/podtrace/issues/180)) ([e5da3cd](https://github.com/gma1k/podtrace/commit/e5da3cd17d3740aa84c678840d191e29a24d0b0f))


### Maintenance

* **deps:** update docker/setup-qemu-action action to v4.1.0 ([#175](https://github.com/gma1k/podtrace/issues/175)) ([9009a71](https://github.com/gma1k/podtrace/commit/9009a7167bfb02238538d28ea859805fa44c53bb))
* **deps:** update github actions ([#177](https://github.com/gma1k/podtrace/issues/177)) ([b8df373](https://github.com/gma1k/podtrace/commit/b8df3735285d3e2ec9ffeac2ef0fa135752638c5))
* **deps:** update github actions to v4.36.2 ([#183](https://github.com/gma1k/podtrace/issues/183)) ([118d6d2](https://github.com/gma1k/podtrace/commit/118d6d21984bb01e2335e2a6039b448a79093c01))
* **deps:** update go modules (non-major) ([#174](https://github.com/gma1k/podtrace/issues/174)) ([3d96d9d](https://github.com/gma1k/podtrace/commit/3d96d9d5f7d1251610435d1aaca0f51818a35be8))
* **deps:** update go modules (non-major) ([#179](https://github.com/gma1k/podtrace/issues/179)) ([0f95880](https://github.com/gma1k/podtrace/commit/0f958802b26c9fbe7d5d95963346ecf3594df24f))
* **deps:** update go modules (non-major) ([#184](https://github.com/gma1k/podtrace/issues/184)) ([2ca4fea](https://github.com/gma1k/podtrace/commit/2ca4fea1000453916085def21f93b49dfef0ab88))
* **deps:** update go modules (non-major) to v0.283.0 ([#178](https://github.com/gma1k/podtrace/issues/178)) ([76570d4](https://github.com/gma1k/podtrace/commit/76570d47a64329890089f68b7a8ac814f07f4e55))

## [0.12.4](https://github.com/gma1k/podtrace/compare/v0.12.3...v0.12.4) (2026-05-29)


### Bug Fixes

* **cli:** always surface spawn-pod failure cause instead of bare kubelet error ([#172](https://github.com/gma1k/podtrace/issues/172)) ([fbc061e](https://github.com/gma1k/podtrace/commit/fbc061efc4a39d22521105eaeb526fb03fc9ad32))

## [0.12.3](https://github.com/gma1k/podtrace/compare/v0.12.2...v0.12.3) (2026-05-27)


### Bug Fixes

* **cli:** reap spawn pod orphans by owner-pid liveness ([#169](https://github.com/gma1k/podtrace/issues/169)) ([e5b8c4b](https://github.com/gma1k/podtrace/commit/e5b8c4b90208786d53df073b06ad14e5ef388a8f))
* **cli:** spawn pod debug UX and host-aware Lockdown LSM detection ([#167](https://github.com/gma1k/podtrace/issues/167)) ([037c0e4](https://github.com/gma1k/podtrace/commit/037c0e4573ad77893b54f3beba91e6a0ebdd03d2))


### Maintenance

* **release:** align chart version with appVersion via helm extra-file ([#170](https://github.com/gma1k/podtrace/issues/170)) ([7a6c716](https://github.com/gma1k/podtrace/commit/7a6c71627a256c0dcc3a0055b961fcc7685f6f2a))
* **release:** align chart version with appVersion via yaml updaters ([#171](https://github.com/gma1k/podtrace/issues/171)) ([3caf65d](https://github.com/gma1k/podtrace/commit/3caf65d15e263c48a22d837d2fac7e18a1d7afbb))

## [0.12.2](https://github.com/gma1k/podtrace/compare/v0.12.1...v0.12.2) (2026-05-26)


### Features

* **cli:** improve spawn pod debug UX and detect kernel Lockdown ([#161](https://github.com/gma1k/podtrace/issues/161)) ([3dd672b](https://github.com/gma1k/podtrace/commit/3dd672b715cc9ed869dadb3ba2ef277f8e5ca8d4))


### Bug Fixes

* full BPF verifier log on failure + spawn pod argv strip ([#166](https://github.com/gma1k/podtrace/issues/166)) ([93978d8](https://github.com/gma1k/podtrace/commit/93978d8ec8a2ff6ed4828ecbe7310c80000a44ea))


### CI

* **release:** use OPERATORHUB_PAT for cross-fork OLM submission ([#164](https://github.com/gma1k/podtrace/issues/164)) ([b485016](https://github.com/gma1k/podtrace/commit/b485016406791502487d7714890d20c8fd0b8b0f))


### Maintenance

* **release:** explicit release bumps via release-as in config ([#163](https://github.com/gma1k/podtrace/issues/163)) ([be53d14](https://github.com/gma1k/podtrace/commit/be53d141db67e04010700b46accff9c699c1d4fa))

## [0.12.1](https://github.com/gma1k/podtrace/compare/v0.12.0...v0.12.1) (2026-05-24)


### Bug Fixes

* spawn image tag v-prefix mismatch and OLM bundle push auth ([#158](https://github.com/gma1k/podtrace/issues/158)) ([9cd2f65](https://github.com/gma1k/podtrace/commit/9cd2f6531bbefb36536d237b7dcf814f405643a0))

## [0.12.0](https://github.com/gma1k/podtrace/compare/v0.11.0...v0.12.0) (2026-05-24)


### Features

* add PodTraceSchedule CRD, rename PodTraceSession to `.status.state`, and harden operator/CLI reconcile and error paths ([#118](https://github.com/gma1k/podtrace/issues/118)) ([97f7407](https://github.com/gma1k/podtrace/commit/97f74073ed8ec355f6647ad017c11ee4f6ce67db))
* **agent:** add --backend flag, backend_degraded metric, and typed startup-error classes for explicit production safety and degraded-mode observability ([#122](https://github.com/gma1k/podtrace/issues/122)) ([170de33](https://github.com/gma1k/podtrace/commit/170de33688d45b85af090a8487025b86e3a539e2))
* **agent:** add Jaeger/DataDog/Splunk exporters, version bundles, manage CRDs via Helm hooks ([#113](https://github.com/gma1k/podtrace/issues/113)) ([dd6a1aa](https://github.com/gma1k/podtrace/commit/dd6a1aae108a6c2a427a5c68483187df1003d582))
* **agent:** attach k8s pod and workload context to exported spans ([#140](https://github.com/gma1k/podtrace/issues/140)) ([d357ab0](https://github.com/gma1k/podtrace/commit/d357ab02348565ea895e1aca706b74f60bf33d37))
* **agent:** stamp nodeStatus.reason and per-program, exporter init metrics ([#145](https://github.com/gma1k/podtrace/issues/145)) ([b31df33](https://github.com/gma1k/podtrace/commit/b31df33d5414c667b57d04bb9a31a2466dd7d317))
* **agent:** surface per-CR failures as Degraded condition with cause on NodeStatus.Message ([#109](https://github.com/gma1k/podtrace/issues/109)) ([bd0322b](https://github.com/gma1k/podtrace/commit/bd0322bdd97229a8d5fd7b1ff55c3bbd24f9a504))
* **agent:** wire podtrace policy, filters, sample, thresholds end-to-end ([#142](https://github.com/gma1k/podtrace/issues/142)) ([15e6800](https://github.com/gma1k/podtrace/commit/15e680007a1b519c7e7bb5e8e6e364493cfd62f0))
* **cli:** add Make-based release pipeline for signed multi-platform tarballs ([#87](https://github.com/gma1k/podtrace/issues/87)) ([4fbd4b9](https://github.com/gma1k/podtrace/commit/4fbd4b9ea0fabf48aafb6ec3ca1cfacf03a11c59))
* **cli:** krew compatibility, auth plugins import and kubectl-aware Use string ([#95](https://github.com/gma1k/podtrace/issues/95)) ([e989941](https://github.com/gma1k/podtrace/commit/e9899417add0ad6685cb86996de5b535631665c4))
* cross-namespace PodTrace targeting via spec.namespaceSelector and chart namespace-bootstrap hardening ([#115](https://github.com/gma1k/podtrace/issues/115)) ([7d70f3f](https://github.com/gma1k/podtrace/commit/7d70f3ff9bed2f7a8bb58a665852e6fb14cc46ff))
* **operator:** ExporterConfig status reconciler, changelog and CI hygiene ([#117](https://github.com/gma1k/podtrace/issues/117)) ([c70a710](https://github.com/gma1k/podtrace/commit/c70a71005646db953cc240ee4504df17bcbd3d27))
* **release:** add OperatorHub.io OLM bundle pipeline ([#100](https://github.com/gma1k/podtrace/issues/100)) ([7f08a63](https://github.com/gma1k/podtrace/commit/7f08a6316514d6c280b0414f400b2478d19a0af7))
* **reports:** upload session reports to S3/GCS/Azure object stores, fix agent BPF wiring, harden chart fresh-install path ([#116](https://github.com/gma1k/podtrace/issues/116)) ([ec6e335](https://github.com/gma1k/podtrace/commit/ec6e3354dae7bc1ccf88a07400e451e313359fda))
* rolling-window error_rate detector and selective probe attach ([#143](https://github.com/gma1k/podtrace/issues/143)) ([4624181](https://github.com/gma1k/podtrace/commit/46241815c58b7039a19fbe64ff597ad427d204ab))
* surface objectStore upload reason, attempts, and retry logs ([#144](https://github.com/gma1k/podtrace/issues/144)) ([9f4937e](https://github.com/gma1k/podtrace/commit/9f4937ee2a14ad8de0c3bf32a5ee83f0f49e6643))
* **tracer:** snapshot-replace cgroup lifecycle with atomic filter set prunes stale attachments on pod churn and closes a kernel-cgroup-ID-recycling correctness bug ([#124](https://github.com/gma1k/podtrace/issues/124)) ([97690f4](https://github.com/gma1k/podtrace/commit/97690f4545d9bcb85c2a14874f883321ca143a4e))


### Bug Fixes

* **build:** cross-compile to darwin via build-tagged Prctl + fail-fast release loop ([#93](https://github.com/gma1k/podtrace/issues/93)) ([16cf498](https://github.com/gma1k/podtrace/commit/16cf498cd48019a2821c8b221ba10e38937ca213))
* **build:** wire ldflags version injection through config and Makefile, add community files ([#90](https://github.com/gma1k/podtrace/issues/90)) ([c33e451](https://github.com/gma1k/podtrace/commit/c33e451c3fcb3bb9385fde2aca53ad363f683721))
* **ci:** route Release-As workflow through a PR to respect branch protection ([#151](https://github.com/gma1k/podtrace/issues/151)) ([e620914](https://github.com/gma1k/podtrace/commit/e6209142aec9da5564aad67a853c5f76eb74914e))
* **cli:** always render help as "podtrace" regardless of invocation path ([#97](https://github.com/gma1k/podtrace/issues/97)) ([25b08a1](https://github.com/gma1k/podtrace/commit/25b08a103e8280c9730b03d929c14d1e655b9bfb))
* **cli:** run eBPF on target node via spawn pod ([#150](https://github.com/gma1k/podtrace/issues/150)) ([edff9a4](https://github.com/gma1k/podtrace/commit/edff9a4fff11533a8fab9d288c2dc58c22fe0e41))
* **olm:** point bundle builder at templates/crds/ and register PodTraceSchedule in the CSV ([#119](https://github.com/gma1k/podtrace/issues/119)) ([4b36ffa](https://github.com/gma1k/podtrace/commit/4b36ffa94adb7e8867ce0ef938e4991208f5c375))
* **release:** correct .krew.yaml indentation + bump docker/login-action to v4.1.0 ([#102](https://github.com/gma1k/podtrace/issues/102)) ([ee7da68](https://github.com/gma1k/podtrace/commit/ee7da6806629a1ea68adc56105765eec27dc5228))


### Refactors

* per-arch BPF objects under internal/ebpf/embedded and sync docs ([#84](https://github.com/gma1k/podtrace/issues/84)) ([470ee82](https://github.com/gma1k/podtrace/commit/470ee82c8fc8eb13ff015dabb3030f49123c572e))


### Documentation

* add Artifact Hub badge to README ([#134](https://github.com/gma1k/podtrace/issues/134)) ([5a9687f](https://github.com/gma1k/podtrace/commit/5a9687fd01100c34c22968d75f2dadef147daf12))
* add OperatorHub.io install path to README + installation + openshift ([#108](https://github.com/gma1k/podtrace/issues/108)) ([c77e9ad](https://github.com/gma1k/podtrace/commit/c77e9ad2e0bdb2e3737b57a2bd57e9664a84c10c))
* **charts:** add chart README rendered on Artifact Hub ([#129](https://github.com/gma1k/podtrace/issues/129)) ([c39fca3](https://github.com/gma1k/podtrace/commit/c39fca306e9f8ff29a262799e5cc37f9a2233da6))
* **charts:** tighten chart description and add PodTraceSchedule to CRD list ([#126](https://github.com/gma1k/podtrace/issues/126)) ([d83da74](https://github.com/gma1k/podtrace/commit/d83da7498d018a1b7961e826637d41b853598e63))
* use sudo for /usr/local/bin extract in CLI install snippets ([#92](https://github.com/gma1k/podtrace/issues/92)) ([e0c9f44](https://github.com/gma1k/podtrace/commit/e0c9f44339c6dad9faa73fb0e85b93e56a54c973))


### Tests

* enforce OTLP-only agent exporter contract with golden tests ([#139](https://github.com/gma1k/podtrace/issues/139)) ([6f452a2](https://github.com/gma1k/podtrace/commit/6f452a2712e12e03b6c7f1d746ea30ef144d6862))


### CI

* add release-notes enrichment, PR labeller, and Release-As trigger ([#121](https://github.com/gma1k/podtrace/issues/121)) ([d974e09](https://github.com/gma1k/podtrace/commit/d974e099cf8ebc246453f4e738b02fe7309b1e2c))
* auto-create conventional-commit labels in label-conventional-prs workflow ([#123](https://github.com/gma1k/podtrace/issues/123)) ([e7af61b](https://github.com/gma1k/podtrace/commit/e7af61ba636ad1a42adb0fba9204942164023ed4))
* migrate CLI checksum signing to cosign v3 keyless bundle format to fix release workflow failures ([#89](https://github.com/gma1k/podtrace/issues/89)) ([09a5226](https://github.com/gma1k/podtrace/commit/09a522632ee85ac52f0efa689f66318c66393f83))
* **olm:** bot commits cannot be GPG-signed ([#112](https://github.com/gma1k/podtrace/issues/112)) ([d29bdff](https://github.com/gma1k/podtrace/commit/d29bdff41c0a7caea495d19a9663d06216184d77))
* **olm:** make upstream remote add idempotent against gh repo clone ([#111](https://github.com/gma1k/podtrace/issues/111)) ([d7e665e](https://github.com/gma1k/podtrace/commit/d7e665e1e7c548aa8db38b3f2e02b3bf95ada22f))
* **refactor:** drop redundant push-to-main triggers ([#107](https://github.com/gma1k/podtrace/issues/107)) ([55d1eeb](https://github.com/gma1k/podtrace/commit/55d1eeb36f76d164208fe7859d75ebb561c505cb))
* **refactor:** tighten triggers, extract BPF toolchain action, pin all third-party actions to SHA ([#106](https://github.com/gma1k/podtrace/issues/106)) ([958fac4](https://github.com/gma1k/podtrace/commit/958fac4d29e28f3ba48e7d180f13966d8dc03811))
* **release:** auto-submit OLM bundle to community-operators per tag ([#105](https://github.com/gma1k/podtrace/issues/105)) ([29053eb](https://github.com/gma1k/podtrace/commit/29053eb22dc9c51e461990867ea61567cc216d55))
* **release:** re-push Artifact Hub verification artifact on every release ([#127](https://github.com/gma1k/podtrace/issues/127)) ([d668e73](https://github.com/gma1k/podtrace/commit/d668e734bfdc64cd335088add214c78db7a810dc))
* **release:** wire krew-release-bot for automated krew-index PRs ([#99](https://github.com/gma1k/podtrace/issues/99)) ([7ce6e25](https://github.com/gma1k/podtrace/commit/7ce6e25a06a427f8d9b3cdeb92a75bb096138c91))


### Maintenance

* announce 0.12.0 ([#152](https://github.com/gma1k/podtrace/issues/152)) ([4d67a5d](https://github.com/gma1k/podtrace/commit/4d67a5d320f5dfbc41652e95980e52437ca78197))
* bump k8s.io packages to v0.34.8 and add FOSSA license badges ([#137](https://github.com/gma1k/podtrace/issues/137)) ([17d46c8](https://github.com/gma1k/podtrace/commit/17d46c868df04eb715d4c125e7f47368af634cd2))
* chart NOTES URL, release tags, and PAT for release-please ([#83](https://github.com/gma1k/podtrace/issues/83)) ([114eeeb](https://github.com/gma1k/podtrace/commit/114eeeba8010eef61546546d88bc5c6e7e59739d))
* **charts:** add artifacthub-repo.yml for Verified Publisher ([#125](https://github.com/gma1k/podtrace/issues/125)) ([0dda799](https://github.com/gma1k/podtrace/commit/0dda79915a3b63e6e37b005b47acfc2b4a6088e1))
* **charts:** add values.schema.json ([#132](https://github.com/gma1k/podtrace/issues/132)) ([3ffb92b](https://github.com/gma1k/podtrace/commit/3ffb92b7af8f807998179911db04540d7206530f))
* **ci:** release-please bumps patch on feat: while pre-1.0 ([#86](https://github.com/gma1k/podtrace/issues/86)) ([9dd5d41](https://github.com/gma1k/podtrace/commit/9dd5d416af9c2e0784a01696842f0239e07ec3b8))
* **config:** migrate config .github/renovate.json ([#146](https://github.com/gma1k/podtrace/issues/146)) ([3a0a18d](https://github.com/gma1k/podtrace/commit/3a0a18ded774e7c7641880e48a87421332ed3205))
* **deps:** update module sigs.k8s.io/structured-merge-diff/v6 to v6.4.0 ([#148](https://github.com/gma1k/podtrace/issues/148)) ([8ff3976](https://github.com/gma1k/podtrace/commit/8ff39765533a58f1a91bb7a6fa4f4e92f81e5163))
* **main:** release 0.11.1 ([#85](https://github.com/gma1k/podtrace/issues/85)) ([cd7f993](https://github.com/gma1k/podtrace/commit/cd7f9933e5df707c9a547b7c0878719a44ce6335))
* **main:** release 0.11.2 ([#88](https://github.com/gma1k/podtrace/issues/88)) ([222773c](https://github.com/gma1k/podtrace/commit/222773c4413f231dfa2e59c65c989369bf1acf28))
* **main:** release 0.11.3 ([#91](https://github.com/gma1k/podtrace/issues/91)) ([11e7c2f](https://github.com/gma1k/podtrace/commit/11e7c2f74ec315121da2e1584cdaaa7d2f9e2568))
* **main:** release 0.11.4 ([#94](https://github.com/gma1k/podtrace/issues/94)) ([126b14a](https://github.com/gma1k/podtrace/commit/126b14acc2b506210bb341e80c76ec2fc9f8f3b8))
* **main:** release 0.11.5 ([#96](https://github.com/gma1k/podtrace/issues/96)) ([9672c56](https://github.com/gma1k/podtrace/commit/9672c56a40662c0db3d1ef146ff634c7e4008bff))
* **main:** release 0.11.6 ([#98](https://github.com/gma1k/podtrace/issues/98)) ([ee750a3](https://github.com/gma1k/podtrace/commit/ee750a3e6952e95b41a9ec8fa820d61f9360e87f))
* **main:** release 0.11.7 ([#101](https://github.com/gma1k/podtrace/issues/101)) ([0f7492b](https://github.com/gma1k/podtrace/commit/0f7492b6d5398130cc329af47b61572786c1bbfb))
* **main:** release 0.11.8 ([#103](https://github.com/gma1k/podtrace/issues/103)) ([67229ce](https://github.com/gma1k/podtrace/commit/67229ceef0760457ca0d8092254f5cc867a557cb))
* **main:** release 0.11.9 ([#110](https://github.com/gma1k/podtrace/issues/110)) ([9e51011](https://github.com/gma1k/podtrace/commit/9e510110f074551aff26d753cd2ccce8a35d0bb4))
* **release:** release 0.11.10 ([#114](https://github.com/gma1k/podtrace/issues/114)) ([3a0a5cf](https://github.com/gma1k/podtrace/commit/3a0a5cf0d938ed5d3f603080fd2685dedf4ba454))
* **release:** release 0.11.11 ([#120](https://github.com/gma1k/podtrace/issues/120)) ([7650709](https://github.com/gma1k/podtrace/commit/765070996080388ac4ba4a52b3fea7a7d1a12c4a))
* **release:** use standard semver bumps for pre-v1.0 ([#155](https://github.com/gma1k/podtrace/issues/155)) ([99f70a1](https://github.com/gma1k/podtrace/commit/99f70a1c0cd74e0d08f06825d7a2a64bb5be77c4))

## [0.11.11](https://github.com/gma1k/podtrace/compare/v0.11.10...v0.11.11) (2026-05-18)


### Features

* **agent:** add --backend flag, backend_degraded metric, and typed startup-error classes for explicit production safety and degraded-mode observability ([#122](https://github.com/gma1k/podtrace/issues/122)) ([170de33](https://github.com/gma1k/podtrace/commit/170de33688d45b85af090a8487025b86e3a539e2))
* **tracer:** snapshot-replace cgroup lifecycle with atomic filter set prunes stale attachments on pod churn and closes a kernel-cgroup-ID-recycling correctness bug ([#124](https://github.com/gma1k/podtrace/issues/124)) ([97690f4](https://github.com/gma1k/podtrace/commit/97690f4545d9bcb85c2a14874f883321ca143a4e))


### Bug Fixes

* **olm:** point bundle builder at templates/crds/ and register PodTraceSchedule in the CSV ([#119](https://github.com/gma1k/podtrace/issues/119)) ([4b36ffa](https://github.com/gma1k/podtrace/commit/4b36ffa94adb7e8867ce0ef938e4991208f5c375))

## [0.11.10](https://github.com/gma1k/podtrace/compare/v0.11.9...v0.11.10) (2026-05-15)


### Added

* add PodTraceSchedule CRD, rename PodTraceSession to `.status.state`, and harden operator/CLI reconcile and error paths ([#118](https://github.com/gma1k/podtrace/issues/118)) ([97f7407](https://github.com/gma1k/podtrace/commit/97f74073ed8ec355f6647ad017c11ee4f6ce67db))
* **agent:** add Jaeger/DataDog/Splunk exporters, version bundles, manage CRDs via Helm hooks ([#113](https://github.com/gma1k/podtrace/issues/113)) ([dd6a1aa](https://github.com/gma1k/podtrace/commit/dd6a1aae108a6c2a427a5c68483187df1003d582))
* cross-namespace PodTrace targeting via spec.namespaceSelector and chart namespace-bootstrap hardening ([#115](https://github.com/gma1k/podtrace/issues/115)) ([7d70f3f](https://github.com/gma1k/podtrace/commit/7d70f3ff9bed2f7a8bb58a665852e6fb14cc46ff))
* **operator:** ExporterConfig status reconciler, changelog and CI hygiene ([#117](https://github.com/gma1k/podtrace/issues/117)) ([c70a710](https://github.com/gma1k/podtrace/commit/c70a71005646db953cc240ee4504df17bcbd3d27))
* **reports:** upload session reports to S3/GCS/Azure object stores, fix agent BPF wiring, harden chart fresh-install path ([#116](https://github.com/gma1k/podtrace/issues/116)) ([ec6e335](https://github.com/gma1k/podtrace/commit/ec6e3354dae7bc1ccf88a07400e451e313359fda))

## [0.11.9](https://github.com/gma1k/podtrace/compare/v0.11.8...v0.11.9) (2026-05-11)


### Added

* **agent:** surface per-CR failures as Degraded condition with cause on NodeStatus.Message ([#109](https://github.com/gma1k/podtrace/issues/109)) ([bd0322b](https://github.com/gma1k/podtrace/commit/bd0322bdd97229a8d5fd7b1ff55c3bbd24f9a504))

## [0.11.8](https://github.com/gma1k/podtrace/compare/v0.11.7...v0.11.8) (2026-05-09)


### Fixed

* **release:** correct .krew.yaml indentation + bump docker/login-action to v4.1.0 ([#102](https://github.com/gma1k/podtrace/issues/102)) ([ee7da68](https://github.com/gma1k/podtrace/commit/ee7da6806629a1ea68adc56105765eec27dc5228))

## [0.11.7](https://github.com/gma1k/podtrace/compare/v0.11.6...v0.11.7) (2026-05-09)


### Added

* **release:** add OperatorHub.io OLM bundle pipeline ([#100](https://github.com/gma1k/podtrace/issues/100)) ([7f08a63](https://github.com/gma1k/podtrace/commit/7f08a6316514d6c280b0414f400b2478d19a0af7))

## [0.11.6](https://github.com/gma1k/podtrace/compare/v0.11.5...v0.11.6) (2026-05-08)


### Fixed

* **cli:** always render help as "podtrace" regardless of invocation path ([#97](https://github.com/gma1k/podtrace/issues/97)) ([25b08a1](https://github.com/gma1k/podtrace/commit/25b08a103e8280c9730b03d929c14d1e655b9bfb))

## [0.11.5](https://github.com/gma1k/podtrace/compare/v0.11.4...v0.11.5) (2026-05-08)


### Added

* **cli:** krew compatibility, auth plugins import and kubectl-aware Use string ([#95](https://github.com/gma1k/podtrace/issues/95)) ([e989941](https://github.com/gma1k/podtrace/commit/e9899417add0ad6685cb86996de5b535631665c4))

## [0.11.4](https://github.com/gma1k/podtrace/compare/v0.11.3...v0.11.4) (2026-05-08)


### Fixed

* **build:** cross-compile to darwin via build-tagged Prctl + fail-fast release loop ([#93](https://github.com/gma1k/podtrace/issues/93)) ([16cf498](https://github.com/gma1k/podtrace/commit/16cf498cd48019a2821c8b221ba10e38937ca213))

## [0.11.3](https://github.com/gma1k/podtrace/compare/v0.11.2...v0.11.3) (2026-05-07)


### Fixed

* **build:** wire ldflags version injection through config and Makefile, add community files ([#90](https://github.com/gma1k/podtrace/issues/90)) ([c33e451](https://github.com/gma1k/podtrace/commit/c33e451c3fcb3bb9385fde2aca53ad363f683721))

## [0.11.2](https://github.com/gma1k/podtrace/compare/v0.11.1...v0.11.2) (2026-05-06)


### Added

* **cli:** add Make-based release pipeline for signed multi-platform tarballs ([#87](https://github.com/gma1k/podtrace/issues/87)) ([4fbd4b9](https://github.com/gma1k/podtrace/commit/4fbd4b9ea0fabf48aafb6ec3ca1cfacf03a11c59))

## [0.11.1](https://github.com/gma1k/podtrace/compare/v0.11.0...v0.11.1) (2026-05-06)


### Changed

* per-arch BPF objects under internal/ebpf/embedded and sync docs ([#84](https://github.com/gma1k/podtrace/issues/84)) ([470ee82](https://github.com/gma1k/podtrace/commit/470ee82c8fc8eb13ff015dabb3030f49123c572e))

## [Unreleased]

## [0.11.0] - 2026-04-25

### Added
- Multi-call libfcgi BPF state machine and enriched FastCGI report section ([#75]).

### Changed
- Tightened gosec / CodeQL findings via scoped fs/conv helpers ([#74]).
- envtest CRD path corrected ([#74]).
- Operational chart layer: `TracerConfig`, monitoring templates, narrowed
  agent RBAC, and the CRD documentation set with a Chainsaw e2e suite
  ([#73]).

### Added (operator)
- `PodTraceSession` Job runtime: operator-mounted exporter bundle, CLI
  session sinks, per-session narrow RBAC, kind-smoke verification of the
  full diagnose → Completed path ([#72]).
- Per-node agent DaemonSet runtime with multi-CR merge router,
  exporter-bundle consumption, SSA status writer, Prometheus metrics ([#71]).
- Operator with `TracerConfig`, `PodTrace`, `PodTraceSession` reconcilers,
  exporter-bundle sync, kind e2e smoke ([#70]).
- Initial scaffold: Kubernetes operator with `v1alpha1` CRDs, validating
  webhooks, tracer engine seam, Helm chart ([#69]).

## [0.10.0] - 2026-04-19

### Added
- DataDog and Zipkin trace exporters ([#68]).
- Multi-pod tracing and cross-namespace support ([#63]).

### Changed
- README consolidated into `docs/` ([#68]).
- Multi-pod tracing features restored to README.

### Fixed
- Capitalization of "Datadog" in README.

## [0.9.0] - 2026-02-28

### Added
- Language-runtime adapters: Redis, Memcached, FastCGI, gRPC, Kafka,
  USDT, and PII redaction ([#61]).
- Filesystem path extraction, IPv6 fix, event schema V4, runtime probe
  groups, configurable BPF map sizes, alert thresholds, and
  unlink/rename event types ([#60]).
- Reliability hardening: stack traces, channel-depth metrics, pprof,
  fuzz tests, govulncheck, gosec, security fixes ([#58]).
- Cross-environment portability improvements, expanded test coverage,
  doc improvements ([#56]).

### Changed
- Replaced large `vmlinux.h` fallback with a minimal stub since the
  required types are locally defined or forward-declared in
  `bpf/common.h` ([#59]).

### Fixed
- Cgroup resolution for CRI runtimes ([#57]).
- DaemonSet no-events and systemd cgroup driver issue ([#55]).

## [0.8.0] - 2025-12-17

### Added
- CRI-O support and enhanced diagnostics ([#53]).
- Real-time alerting system with webhook, Slack, and other sinks ([#46]).
- Connection pool monitoring ([#44]).
- Resource limit monitoring for CPU, memory, and I/O ([#42]).

### Changed
- CLI now prints version on `--version` ([#50]).
- CI workflow optimized; test coverage improved; linter errors cleaned;
  alerting config migrated ([#49]).
- Replaced `pathresolver` with kernel path resolution ([#45]).

### Fixed
- Bug fixes and security hardening ([#48]).
- `vmlinux.h` placeholder file ([#47]).
- `bpf_d_path` replaced with inode-based path resolution for
  cross-kernel compatibility ([#41]).

## [0.7.0] - 2025-12-07

### Added
- Distributed tracing support: OTLP, Jaeger, and Splunk exporters ([#40]).
- TLS / SSL handshake tracking ([#39]).
- Kubernetes context enrichment with pod-to-pod tracking and error
  correlation with root-cause analysis ([#38]).
- Multi-architecture support with dynamic library discovery,
  priority-based event sampling, LRU caching, and improved error
  handling ([#35]).
- Structured logging with zap and internal metrics tracking ([#29]).
- Comprehensive test suite ([#25]).
- Issue templates ([#23]).

### Changed
- Codebase reorganized into modular folder structure ([#34]).
- `GenerateReport()` in `diagnose.go` refactored ([#28]).
- Configuration centralized; bug fixes; code-quality improvements ([#27]).

### Fixed
- `runDiagnoseMode` lint issue.
- Code hardening ([#24]).

### Security
- eBPF parser and cgroup filter testing hardened ([#26]).

## [0.6.0] - 2025-12-02

### Added
- Stack traces, lock contention, syscall tracing, network reliability,
  and database query monitoring ([#22]).
- File-path tracking and I/O bandwidth metrics ([#21]).
- UDP/HTTP tracing, OOM-Kill detection ([#18]).
- Remaining feature gaps from initial roadmap closed ([#17]).
- Initial podtrace doc set ([#16]).

### Changed
- Large files split for maintainability ([#19]).

### Fixed
- I/O bandwidth value calculation ([#18]).

### Security
- CLI validation and metrics config hardened ([#20]).
- Security hardening pass ([#15]).

## [0.5.0] - 2025-11-28

### Added
- Metric visualization via Prometheus and Grafana ([#14]).
- Ring buffer, file read operations, IPv6 support, CPU scheduling, and
  DNS tracking ([#13]).

### Changed
- README logo and description updated ([#11]).

## [0.4.0] - 2025-11-23

### Added
- Real-time mode with periodic updates ([#10]).
- CPU usage tracking.

### Fixed
- ShellCheck warnings; CodeQL Go setup in CI ([#9]).

## [0.3.0] - 2025-11-22

### Changed
- Dependencies bumped to latest; GitHub Actions workflows improved ([#7]).

## [0.2.0] - 2025-11-22

### Changed
- Dependency updates: `golang.org/x/oauth2` 0.12.0 → 0.27.0 ([#6]),
  `google.golang.org/protobuf` 1.31.0 → 1.33.0 ([#5]),
  `golang.org/x/net` 0.19.0 → 0.38.0 ([#4]), eBPF and cobra packages
  updated ([#3]).
- `actions/checkout` upgraded v3 → v4.
- `bash-checks` workflow refactored.

### Fixed
- Filesystem-monitoring description in README.

## [0.1.0] - 2025-11-21

### Added
- Initial public release of podtrace.
- Core eBPF-based diagnostic CLI for Kubernetes pods.
- GitHub Actions CI ([#2]).

[Unreleased]: https://github.com/gma1k/podtrace/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/gma1k/podtrace/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/gma1k/podtrace/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/gma1k/podtrace/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/gma1k/podtrace/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/gma1k/podtrace/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/gma1k/podtrace/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/gma1k/podtrace/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/gma1k/podtrace/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gma1k/podtrace/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gma1k/podtrace/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gma1k/podtrace/releases/tag/v0.1.0

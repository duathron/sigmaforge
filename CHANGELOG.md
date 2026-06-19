# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/).

## [0.3.0](https://github.com/duathron/sigmaforge/compare/v0.2.0...v0.3.0) (2026-06-19)


### Features

* **cli:** bundled manual + `sigmaforge manual` command ([3dae402](https://github.com/duathron/sigmaforge/commit/3dae402ed623e6f3c696d7ab3ddc67f223d0cd73))
* **cli:** hunt command (rules x arbitrary logs -&gt; hits only, unmeasured) ([e83dcf6](https://github.com/duathron/sigmaforge/commit/e83dcf600760fb424e88b550ba5ed48e1be757c5))
* **cli:** real backtest command (config+pipeline, preflight exit codes); drop classify ([b15679b](https://github.com/duathron/sigmaforge/commit/b15679b0b4d55f76f682cbab656e64f4f4a2e693))
* **config:** add backtest block (corpus/mapping/floor, None defaults) ([5b7d515](https://github.com/duathron/sigmaforge/commit/5b7d5154a56463234662aa111f12bd70f9229e52))
* **orchestrate:** row reason-codes + recall_mode ([2f4919e](https://github.com/duathron/sigmaforge/commit/2f4919ef6cc348c7213c83c7d2c1d8988026c85e))
* **render:** inline unmeasured reasons + data-generated caveats ([6b089f5](https://github.com/duathron/sigmaforge/commit/6b089f50920556eeb9c82122d95ebec354a3a63e))
* **score:** net-new unmeasured reason-codes (no-tag/technique-0-events/below-floor) ([358f29b](https://github.com/duathron/sigmaforge/commit/358f29bd083b13530b4195285114f5b9344a6bcb))


### Bug Fixes

* **deps:** declare pyyaml as a runtime dependency (shipped config import; was ModuleNotFoundError on clean install) ([5db6f4c](https://github.com/duathron/sigmaforge/commit/5db6f4c4f92e9780a452bffe4ca8a44171416417))


### Documentation

* **plan:** sigmaforge CLI implementation plan (C1 extract+pyyaml -&gt; C2 backtest -&gt; C3 hunt) ([5a3a923](https://github.com/duathron/sigmaforge/commit/5a3a92377fea69977d33a7607a143df18861e89a))
* **plan:** Skeptic-gate fixes — funnel.recall_mode (no tuple-arity change), surface computed provenance on BacktestResult, hunt temp-ruleset write, drop refused enum ([906cfd1](https://github.com/duathron/sigmaforge/commit/906cfd1e52ca3aefd7c964c6e0be800f88a6cc24))
* **readme:** CLI is the real path now (backtest + hunt, same pipeline); test count 113 ([29300cc](https://github.com/duathron/sigmaforge/commit/29300cc586b62f919e6ba70b713e32b8f1a2229b))
* **run7:** regenerate report with no-benign-exemplars reason annotations (render drift from C3 cleanup) ([8a94a53](https://github.com/duathron/sigmaforge/commit/8a94a535be94748368d5d0656b7bdd837a31ed83))
* **spec:** functional CLI design (hunt + backtest), MeetUp-approved + Skeptic-gated ([e5bded9](https://github.com/duathron/sigmaforge/commit/e5bded9dc3d64d97f549e3f47126f18eeac2adc2))

## [0.2.0](https://github.com/duathron/sigmaforge/compare/v0.1.0...v0.2.0) (2026-06-18)


### Features

* **precision:** run7 — OpTC benign +1 host group (honest diminishing-return result) ([b6fe35a](https://github.com/duathron/sigmaforge/commit/b6fe35af486761babcbdc0251217c6c7b3c3e97f))


### Bug Fixes

* **ingest:** remove hardcoded cwd from shipped run_shard + add reproducibility tooling ([665cbe9](https://github.com/duathron/sigmaforge/commit/665cbe9356e273695be412e50bd0116d3985871a))

## 0.1.0 (2026-06-18)


### Features

* **finding:** hand-verified Service Tampering FP analysis + fix ([0546882](https://github.com/duathron/sigmaforge/commit/054688250cb06e65f3a19c37cb137890f9709798))
* **live:** first real precision@COMISET backtest report ([09a8725](https://github.com/duathron/sigmaforge/commit/09a8725ebe16f017d378e5340db9f44ec3d66c2b))
* **m0:** A1 gate spike ([c38af4d](https://github.com/duathron/sigmaforge/commit/c38af4d6e2eabb13514d5e641a7473ad82f78034))
* **m0:** COMISET schema mapping + A1 slice prep ([e346c0f](https://github.com/duathron/sigmaforge/commit/e346c0f1dcc1e409692a7b341d6ca9874d7f8805))
* **m1:** corpus chunker (true partition) ([7d9ff56](https://github.com/duathron/sigmaforge/commit/7d9ff567b9cde1c6a8330b85972ded935c3885de))
* **m1:** golden fixture validates parse-&gt;score chain ([62e9750](https://github.com/duathron/sigmaforge/commit/62e9750955f0e41755d3a89cdecd5bb8a7ef4e8d))
* **m1:** match/score data model ([e18b372](https://github.com/duathron/sigmaforge/commit/e18b372af132b025386dc7b8df4d80811c038537))
* **m1:** parallel backtest runner + deterministic aggregation ([dead327](https://github.com/duathron/sigmaforge/commit/dead327d1a3e75f36349a5cdfb6fa692a44184b0))
* **m1:** per-rule adapter + scorer (EvalResult reuse) ([ae3b7ae](https://github.com/duathron/sigmaforge/commit/ae3b7ae218f5a348e4c58e962a087a66b42dbb84))
* **m1:** rule-load level+stateful partition ([083a93f](https://github.com/duathron/sigmaforge/commit/083a93fba9a7f965e55db2d2da4e8d97041ad94a))
* **m1:** zircolite runner + parser ([291a25a](https://github.com/duathron/sigmaforge/commit/291a25ab2f7bdce14317dd72005e4167b40aa67a))
* **m2:** emit_precision as the only sanctioned precision path ([5e972a1](https://github.com/duathron/sigmaforge/commit/5e972a182a8fedf4225c9fbe7ebd7018a8c40709))
* **m2:** floor + positive-control + overfit gates ([2ede466](https://github.com/duathron/sigmaforge/commit/2ede4665a5918f3891cf49ae39e65b2dec0e5808))
* **m2:** per-rule coverage counter ([93b231b](https://github.com/duathron/sigmaforge/commit/93b231bf5b9d2972623c4bdbecf3a8db83d3c770))
* **m2:** run manifest + worker-invariant run hash ([7e89f12](https://github.com/duathron/sigmaforge/commit/7e89f1216d1f8f4cfcc9e420498cec50770b0764))
* **m3:** backtest CLI + two-source orchestration ([ce113d1](https://github.com/duathron/sigmaforge/commit/ce113d1a53e67d417985f16c9c91de03791336e0))
* **m3:** cross-engine compare over loaded-rule intersection ([69dbb9d](https://github.com/duathron/sigmaforge/commit/69dbb9df5e1419d642ad9ce304c1fbf6b7d801c4))
* **m3:** FP-tuning report + dataset-card render ([8387223](https://github.com/duathron/sigmaforge/commit/83872239811e9e5afb2473838220addcf8511718))
* **precision:** add DARPA OpTC benign-week corpus (run6) ([42e4c22](https://github.com/duathron/sigmaforge/commit/42e4c22624e63bbf027f3be3cf40bb6bed46268b))
* **recall:** add sub-technique attack_data corpus (run5) — close run4 sub-technique gap ([0469268](https://github.com/duathron/sigmaforge/commit/046926864c93b1cd613d679d47caf3ffa560dde6))
* **selfgen:** benign self-generation kit (normal_workday.ps1 + olafhartong recipe) ([46795d0](https://github.com/duathron/sigmaforge/commit/46795d0a7849c864b25acb5aae5766c89f89d5de))


### Bug Fixes

* **B2:** sub-technique-granular recall scoping (no sibling dilution) ([4a67a6b](https://github.com/duathron/sigmaforge/commit/4a67a6b36fe171acb1cc537fda2db5e80f75c239))
* **B:** per-technique recall (replace pooled denominator) ([8930cb1](https://github.com/duathron/sigmaforge/commit/8930cb1b2e4270650b49fe1e9f9c3fcbf4e53de7))
* **C:** globally-unique event key (stable row hash) — kill EventRecordID cross-file collision deflating recall + multi-file regression ([3fb1dfb](https://github.com/duathron/sigmaforge/commit/3fb1dfbd956fb91d3b2e9885203e7ba631618673))
* **H:** compile only loaded rules into engine ruleset (one source) + acceptance gate ([1301775](https://github.com/duathron/sigmaforge/commit/13017751bbc50ed4c658ec0ea814374b1376344c))
* **live:** label as precision@combined-benign + disclose Nextron blend (A8); commit attack-PC count generator (Skeptic round 3) ([fb88905](https://github.com/duathron/sigmaforge/commit/fb88905d1a6db64b31c57a7af40b0811deedadcd))
* **live:** recall denominator + manifest + scaled benign corpus (Skeptic round 2) ([62672e6](https://github.com/duathron/sigmaforge/commit/62672e6084d3da9244b0ad52bbfdf8914951564f))
* **m3:** BLOCKER A3 label-keyed FP + A2 gate-only precision via live score_rule (Skeptic review) ([f20c41e](https://github.com/duathron/sigmaforge/commit/f20c41edd0c2773cf4d3db65215ea3255ea024a0))
* **m3:** wire run_hash into report (A11); remove stray nested test ([a5281a4](https://github.com/duathron/sigmaforge/commit/a5281a4bd18b3b5aec821917feed43af417e83a2))
* **run6:** disclose OpTC Image path-form caveat + precision-floor + slice provenance (Skeptic B1/N1/N2) ([bf8e6bc](https://github.com/duathron/sigmaforge/commit/bf8e6bc977bf5f4d94dd32297bda454590f8013b))


### Documentation

* **B2:** note WHY recall table is empty (corpus bare-parent vs sub-technique-tagged rules) — Skeptic honesty ([88c0ebb](https://github.com/duathron/sigmaforge/commit/88c0ebb184ee353811384248ccb399ea3268e840))
* **C:** note --parallel row_id-reset caveat in stable-event-id (Skeptic) ([19f1f2b](https://github.com/duathron/sigmaforge/commit/19f1f2bdf69b6189ddc622a870996d151f1c82fe))
* **finding:** relabel attack-corpus TP row + note unconditional Ninite filter leg (Skeptic polish) ([7e833b2](https://github.com/duathron/sigmaforge/commit/7e833b27a93cf763d6da7c795cc9f1b77ce0c2ef))
* **live:** add pooled-recall caveat + fix label typo in run2 (MeetUp gap review) ([3e4efbe](https://github.com/duathron/sigmaforge/commit/3e4efbebc91229bb978d468a0d43b874350b9392))

## [Unreleased]
### Added
- Initial scaffold from the Shipwright framework.

# Changelog

## [0.18.1](https://github.com/nexuslibs/cleanscan/compare/v0.18.0...v0.18.1) (2026-07-22)


### Bug Fixes

* **colo:** map IAD to United States ([0f43717](https://github.com/nexuslibs/cleanscan/commit/0f43717e265dddc900631a48232c713d7225a611))

## [0.18.0](https://github.com/nexuslibs/cleanscan/compare/v0.17.0...v0.18.0) (2026-07-22)


### Features

* **update:** add safe CLI self-updates ([efff080](https://github.com/nexuslibs/cleanscan/commit/efff08010be0b9bd12c76827e16e72d98a547ace))
* **update:** add safe CLI self-updates ([6bf6cd9](https://github.com/nexuslibs/cleanscan/commit/6bf6cd9227f76ce375ef570a83fde8615631a01f))


### Bug Fixes

* **release:** improve checksum validation by trimming whitespace ([75ea7a1](https://github.com/nexuslibs/cleanscan/commit/75ea7a1dd477976f6bcc786ca47d6cbed92e0fce))
* **updater:** adjust client timeout handling and update metadata download timeout ([aa413e3](https://github.com/nexuslibs/cleanscan/commit/aa413e3f51916520115799d3f7fcd89f016d070b))
* **updater:** change redirect policy to limit redirects to 10 ([5fbe105](https://github.com/nexuslibs/cleanscan/commit/5fbe10576de3fe17ee826229e112852f273ce3b4))

## [0.17.0](https://github.com/nexuslibs/cleanscan/compare/v0.16.0...v0.17.0) (2026-07-21)


### Features

* add proxy transport survivability checks and system network info display ([6b93635](https://github.com/nexuslibs/cleanscan/commit/6b936351e2939e3a0178b3154bf48750807f8253))
* enhance scan progress feedback and system network info handling ([1f6fd88](https://github.com/nexuslibs/cleanscan/commit/1f6fd88c9ec543df02df4b08dad1118e0f77f1a6))
* **tui:** show live scan progress ([2d32a62](https://github.com/nexuslibs/cleanscan/commit/2d32a628ac648d68311b98cfd3288c111c0e0649))
* **tui:** show live scan progress ([67d5552](https://github.com/nexuslibs/cleanscan/commit/67d5552b1337c8d8c6e013364ad4ca75ace32b7b))


### Bug Fixes

* **proxy:** enhance error handling for non-TLS WebSocket proxies and improve TLS configuration ([8a5deb2](https://github.com/nexuslibs/cleanscan/commit/8a5deb241f53aff0576a360a8db8283f021e0106))
* **tui:** refactor progress counting logic for compact stats rendering ([8fc78e8](https://github.com/nexuslibs/cleanscan/commit/8fc78e824b13642bd943f2240f8a77d5f191d9c3))
* **tui:** use saturating_sub for remaining probes calculation to prevent underflow ([dd061b9](https://github.com/nexuslibs/cleanscan/commit/dd061b95c74883e3b6dc2f6a404522add0dcb8d9))

## [0.16.0](https://github.com/nexuslibs/cleanscan/compare/v0.15.1...v0.16.0) (2026-07-21)


### Features

* enhance TUI with ASCII support and improved scrolling for help overlay ([b7105c3](https://github.com/nexuslibs/cleanscan/commit/b7105c3caca3b63ea145756876be5598f7cb2e2c))
* refine TUI for Apple design principles ([0d51283](https://github.com/nexuslibs/cleanscan/commit/0d51283a3e06f1cc5183135aeb0061a029e8f06a))
* **tui:** add ASCII support and improve help scrolling ([2a4cc52](https://github.com/nexuslibs/cleanscan/commit/2a4cc52c0077097574c89aa18c9f71977f401d8a))
* **tui:** enhance help overlay scrolling and add ASCII support for markers ([b233035](https://github.com/nexuslibs/cleanscan/commit/b233035288f820ed73702468fca8c7449b289625))

## [0.15.1](https://github.com/nexuslibs/cleanscan/compare/v0.15.0...v0.15.1) (2026-07-21)


### Bug Fixes

* improve TUI feedback and cancellation ([c70857b](https://github.com/nexuslibs/cleanscan/commit/c70857b00a211cba4ad4ff3394619da8081b4483))
* improve TUI feedback and cancellation ([eaf492f](https://github.com/nexuslibs/cleanscan/commit/eaf492ff4eda0ff6a8852523a21afbfea811449e))

## [0.15.0](https://github.com/nexuslibs/cleanscan/compare/v0.14.0...v0.15.0) (2026-07-21)


### Features

* Enhance ProbeResult to include port details and support multiple ports ([412b371](https://github.com/nexuslibs/cleanscan/commit/412b371e27ac96878b8f23dbef851d8f34969185))
* enhanced TUI wizard visual feedback for ranges ([c98a776](https://github.com/nexuslibs/cleanscan/commit/c98a7761485f1b8bffa41d76741c02cc15c883ee))
* enhanced TUI wizard visual feedback for ranges ([aa98c98](https://github.com/nexuslibs/cleanscan/commit/aa98c987c8156f6a7e6a1ea18304efca533e7a1a))


### Bug Fixes

* stop scans promptly on cancellation and align TUI columns ([00eb0d1](https://github.com/nexuslibs/cleanscan/commit/00eb0d1e378184e4adcbf8f21a18114b91ecd9cd))

## [0.14.0](https://github.com/nexuslibs/cleanscan/compare/v0.13.0...v0.14.0) (2026-07-21)


### Features

* add health checks and advanced scanning settings to configuration ([393e48b](https://github.com/nexuslibs/cleanscan/commit/393e48b1e8db4538b3b634b14d5b71e9d490ebac))
* enforce per-required-check thresholds and add two-phase focus C… ([d7a24e0](https://github.com/nexuslibs/cleanscan/commit/d7a24e09b0c8cabd4e1dc95541928082ea8d3e07))
* enforce per-required-check thresholds and add two-phase focus CIDR limit ([d2b5c8a](https://github.com/nexuslibs/cleanscan/commit/d2b5c8a517751eb2c454006587e85f65d547db76))
* enhance profile result merging and dashboard rendering with additional metrics ([991b107](https://github.com/nexuslibs/cleanscan/commit/991b10736399df3fae3e8c2d0043fbcc71f23438))
* refine early stop pruning logic and enhance UI settings for concurrency ([d8d4c76](https://github.com/nexuslibs/cleanscan/commit/d8d4c767d004f057be36e9496bae823baeb90501))
* update host resolution logic and improve config validation in wizard ([9c6012f](https://github.com/nexuslibs/cleanscan/commit/9c6012fccedf2a5a7bb92a419de59fdd0bc3c11b))


### Bug Fixes

* simplify success rate calculation in run_profile_scan ([52ba011](https://github.com/nexuslibs/cleanscan/commit/52ba011ec15dcf809d81ea7840744d09c2e1a5b5))

## [0.13.0](https://github.com/nexuslibs/cleanscan/compare/v0.12.0...v0.13.0) (2026-07-19)


### Features

* add watch mode with adaptive primary endpoint selection ([1f2c411](https://github.com/nexuslibs/cleanscan/commit/1f2c411e96d1049401fa04c81773e5cbf5e226d7))
* add watch mode with adaptive primary endpoint selection ([d6d540f](https://github.com/nexuslibs/cleanscan/commit/d6d540f672f5f7ab0f619e389f03f0df9cfd91f7))
* enhance health check handling and update manifest backup logic ([4e5c8a9](https://github.com/nexuslibs/cleanscan/commit/4e5c8a940465a8a3088cab5f44844e150ae3d1e7))
* enhance health check logic in profile scan to include aggregate health status ([30e1271](https://github.com/nexuslibs/cleanscan/commit/30e1271972a02712e2a161cd782ba5b40a4eedd9))
* improve health check handling in profile scan and add tests for watch state persistence ([99ebe01](https://github.com/nexuslibs/cleanscan/commit/99ebe01179c0765ce644c705d67843a968daac6f))
* integrate watch policy and state management into TUI application ([c6dc3c9](https://github.com/nexuslibs/cleanscan/commit/c6dc3c951746601e12edf515b116efe8fec7f7fa))
* refactor health check and watch state management for improved stability and error handling ([2481831](https://github.com/nexuslibs/cleanscan/commit/2481831b5dba458a3e8648b8eb2281506b2e538b))
* refactor watch policy handling in main and improve watch state management in TUI ([e76fa01](https://github.com/nexuslibs/cleanscan/commit/e76fa013d4fe96fcd06b1e50a65689fcdeceeb5d))

## [0.12.0](https://github.com/nexuslibs/cleanscan/compare/v0.11.0...v0.12.0) (2026-07-19)


### Features

* add manifest backups configuration to App and TUI ([886fb85](https://github.com/nexuslibs/cleanscan/commit/886fb859079a4f8761abe7c5ebb7085cc4d1376b))
* enhance manifest validation and alerting features in TUI ([e4a9c2c](https://github.com/nexuslibs/cleanscan/commit/e4a9c2caed12de9717b9c59c356040ccab4457ea))
* enhance validation by trimming whitespace in header checks and expected values ([34d166f](https://github.com/nexuslibs/cleanscan/commit/34d166fa0849e6416a2685441967d6207a507d1c))
* enhance validation features in AppConfig and CLI ([a33bd84](https://github.com/nexuslibs/cleanscan/commit/a33bd84301e66e0977daca9fd508ce4b835569ca))
* enhance validation features in AppConfig and CLI ([cd7ac05](https://github.com/nexuslibs/cleanscan/commit/cd7ac0505b0b5d739ec7701b07866446ab10200b))
* validate HTTP status range in expected statuses and add unit tests ([b8c7c63](https://github.com/nexuslibs/cleanscan/commit/b8c7c63db4d5ff1b20ec9a743d99fd4069eb58fc))

## [0.11.0](https://github.com/nexuslibs/cleanscan/compare/v0.10.0...v0.11.0) (2026-07-19)


### Features

* add confidence-aware adaptive probing and watch mode ([90da19f](https://github.com/nexuslibs/cleanscan/commit/90da19f79a98ac4de454e7660640aca56ea48714))
* add confidence-aware adaptive probing and watch mode ([c41c28b](https://github.com/nexuslibs/cleanscan/commit/c41c28bf23f6b8ffbce0b7cf5a33e485b7e61b2d))
* enhance adaptive probing logic and improve TUI watch interval handling ([f2ff124](https://github.com/nexuslibs/cleanscan/commit/f2ff124e578195af0a54d11ff0a2703cad93b628))

## [0.10.0](https://github.com/nexuslibs/cleanscan/compare/v0.9.0...v0.10.0) (2026-07-19)


### Features

* add fail-fast early stopping and two-phase sampling ([8e58f21](https://github.com/nexuslibs/cleanscan/commit/8e58f218679e00ea4b326f1c628a7add0da69200))
* add fail-fast early stopping and two-phase sampling ([95a401a](https://github.com/nexuslibs/cleanscan/commit/95a401abc92db545668eb4653d0ce4f97f3a38c8))
* implement early stopping and refine discover fraction validation ([a5a4de3](https://github.com/nexuslibs/cleanscan/commit/a5a4de3507f3a5a7ad256f5507a594602d356089))

## [0.9.0](https://github.com/nexuslibs/cleanscan/compare/v0.8.0...v0.9.0) (2026-07-19)


### Features

* adopt tui-overlay, tui-checkbox and tui-slider for modal and wi… ([28618db](https://github.com/nexuslibs/cleanscan/commit/28618db1c19257f9c4cd59599923a440d6f5c3ab))
* adopt tui-overlay, tui-checkbox and tui-slider for modal and wizard UI ([a171a52](https://github.com/nexuslibs/cleanscan/commit/a171a52f92365e4e1a5760aa7b2fc3bbbd6b311c))
* enhance overlay lifecycle management for result details and quit confirmation ([539f92c](https://github.com/nexuslibs/cleanscan/commit/539f92c0a5f4a088716c34ab68ef8530121baf8d))

## [0.8.0](https://github.com/nexuslibs/cleanscan/compare/v0.7.0...v0.8.0) (2026-07-19)


### Features

* enhance probe results with completed requests and update ranking criteria to include jitter and packet loss ([1980114](https://github.com/nexuslibs/cleanscan/commit/1980114b4a10b714ba6ad8c58ff9a60c32991ca5))
* measure latency jitter and packet loss with stability-aware ran… ([554b748](https://github.com/nexuslibs/cleanscan/commit/554b748e6b1d699941089ffaa7671d0781b5d15e))
* measure latency jitter and packet loss with stability-aware ranking ([88fb087](https://github.com/nexuslibs/cleanscan/commit/88fb0874b435d18deeefe353aea7e92c817215ec))
* update ranking system to prioritize recommendation score, add validation for stability and loss weights ([96ffebb](https://github.com/nexuslibs/cleanscan/commit/96ffebbb40d1c3fcfbc9c9c2f784c212d8e27c29))
* update README and dashboard to reflect new ranking criteria and adjustable weights for stability and loss ([624fd87](https://github.com/nexuslibs/cleanscan/commit/624fd87c60a999bc6a3b77d948646d777e3e11c5))

## [0.7.0](https://github.com/nexuslibs/cleanscan/compare/v0.6.0...v0.7.0) (2026-07-18)


### Features

* add country filtering and display in results ([c90aa31](https://github.com/nexuslibs/cleanscan/commit/c90aa313998740f9b56ea83e3cc4f8c50f4b94ed))
* add datacenter (colo) awareness and steady-state latency via wa… ([9007531](https://github.com/nexuslibs/cleanscan/commit/900753175b3eb453c8bb9c869d1bb07113a93681))
* add datacenter (colo) awareness and steady-state latency via warmup ([d4f2eac](https://github.com/nexuslibs/cleanscan/commit/d4f2eacccaea6b099098105d50603db166775056))


### Bug Fixes

* apply CodeRabbit auto-fixes ([9524d44](https://github.com/nexuslibs/cleanscan/commit/9524d44d0fc9f7a86e1ac1514fa38a0c56a2b6ae))
* correct country and colo mappings in database and improve case-insensitive filtering ([993a86f](https://github.com/nexuslibs/cleanscan/commit/993a86f481ea2a15f39b7bbe67d792799ff6e276))
* import scanner module in tests for proper normalization functionality ([55e7d40](https://github.com/nexuslibs/cleanscan/commit/55e7d4046f6485513eee77d4964a9c2e5ab71c98))
* remove duplicate country argument from Args struct ([acee5c5](https://github.com/nexuslibs/cleanscan/commit/acee5c56ca446f78d68db359151bac052ef2aaf1))

## [0.6.0](https://github.com/nexuslibs/cleanscan/compare/v0.5.0...v0.6.0) (2026-07-18)


### Features

* enhance result details rendering with speed test data and improve latency map selection ([9afd5c9](https://github.com/nexuslibs/cleanscan/commit/9afd5c922ca1dc47c6847d4aa6b83fac09f2b898))
* enhance scanning results and dashboard features ([9cf5388](https://github.com/nexuslibs/cleanscan/commit/9cf53887e4d22b492a7c4b6419f3ccd8396dd285))
* enhance TUI with improved speed testing and navigation ([becf80d](https://github.com/nexuslibs/cleanscan/commit/becf80d76671726dbec7da78a796a2da73ccc571))
* enhance TUI with improved speed testing and navigation ([223b71f](https://github.com/nexuslibs/cleanscan/commit/223b71fb39e48d20dacdd88630d30a242f54a38a))
* enhance TUI with new detail tabs, improved navigation, and additional data visualizations ([e70944c](https://github.com/nexuslibs/cleanscan/commit/e70944c69cd5a25261870a5cb42c37746cfc9c3c))
* enhance TUI with new targets file loading and improved result rendering ([b09dc67](https://github.com/nexuslibs/cleanscan/commit/b09dc6784a954b2dca20465ceef9ab4492791eda))
* optimize speed selection rendering and improve column widths ([01ab518](https://github.com/nexuslibs/cleanscan/commit/01ab5186a04d37268f1a476804a4d6eb846cfaca))

## [0.5.0](https://github.com/nexuslibs/cleanscan/compare/v0.4.0...v0.5.0) (2026-07-18)


### Features

* add protocol column to results and enhance navigation in TUI ([c9ce747](https://github.com/nexuslibs/cleanscan/commit/c9ce7476273188839535a9585c47723d3b8a150d))

## [0.4.0](https://github.com/nexuslibs/cleanscan/compare/v0.3.0...v0.4.0) (2026-07-18)


### Features

* add selective IP speed testing ([c23f1f2](https://github.com/nexuslibs/cleanscan/commit/c23f1f28dcc42376a8e75b8a3c190a37f38c873a))
* add selective IP speed testing ([974e446](https://github.com/nexuslibs/cleanscan/commit/974e446ef1a8131573fec3dddaaae58e6c58e1fe))
* add speed timeout configuration and update related components ([5b11ef4](https://github.com/nexuslibs/cleanscan/commit/5b11ef4c47b2312599c6bdfba59afac1ffc57d84))
* enhance host configuration checks and improve speed testing logic in TUI ([6b21f44](https://github.com/nexuslibs/cleanscan/commit/6b21f44aebaa3363fd628a73175fefd2231a507a))
* implement IP selection and clipboard copy functionality in TUI ([e9c51dd](https://github.com/nexuslibs/cleanscan/commit/e9c51dda88e6bb719ca7d27bee60e3943cae8b55))
* improve scrolling behavior in scanning and speed results screens ([68cbbfb](https://github.com/nexuslibs/cleanscan/commit/68cbbfb82faaeaee7774fdcabffb87715acb1268))
* require host configuration before starting scans and update help text ([11bc8d5](https://github.com/nexuslibs/cleanscan/commit/11bc8d5d0ab8d10a23af08f1f3a78620205ef33e))


### Bug Fixes

* ensure scroll position does not exceed result cursor in compact table rendering ([9440435](https://github.com/nexuslibs/cleanscan/commit/9440435eaa1d777e1674003715c15203e9c3bce2))

## [0.3.0](https://github.com/nexuslibs/cleanscan/compare/v0.2.0...v0.3.0) (2026-07-18)


### Features

* enhance numeric parameter adjustments in settings wizard ([1fe7820](https://github.com/nexuslibs/cleanscan/commit/1fe78202a936433192303594dd59e6ece68f64ce))

## [0.2.0](https://github.com/nexuslibs/cleanscan/compare/v0.1.3...v0.2.0) (2026-07-18)


### Features

* prioritize successful IP probes ([90d4ce4](https://github.com/nexuslibs/cleanscan/commit/90d4ce4f0c8955ac11b9953763aaed3565485824))
* prioritize successful IP probes ([37c4d88](https://github.com/nexuslibs/cleanscan/commit/37c4d8894118cc1b80fec57d9f44a9241359594c))

## [0.1.3](https://github.com/nexuslibs/cleanscan/compare/v0.1.2...v0.1.3) (2026-07-18)


### Bug Fixes

* specify repository in release edit command for better context ([b9db6e8](https://github.com/nexuslibs/cleanscan/commit/b9db6e84bfe742acdab906e77851a65ad79c0a62))

## [0.1.2](https://github.com/nexuslibs/cleanscan/compare/v0.1.1...v0.1.2) (2026-07-18)


### Bug Fixes

* update release workflow to use dedicated token and latest zig setup ([4a6cf8c](https://github.com/nexuslibs/cleanscan/commit/4a6cf8c8f3cf249de9e1d9094a1d58575cbd8d5d))

## [0.1.1](https://github.com/nexuslibs/cleanscan/compare/v0.1.0...v0.1.1) (2026-07-18)


### Bug Fixes

* harden release recovery and permissions ([336b2d8](https://github.com/nexuslibs/cleanscan/commit/336b2d83c2ce9ab10a2a1a8c362646b2840e81c2))

## Changelog

All notable changes to cleanscan are documented in this file.

Release notes are generated from Conventional Commits by Release Please.

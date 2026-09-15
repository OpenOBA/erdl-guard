# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-09-15

### Security

- **js-yaml 4.1.0 → 4.3.2** — fix GHSA-2883-xcg3-v3hh (high): `maxTotalMergeKeys`
  does not limit CPU use for empty merge sources (YAML merge-key DoS).

### Changed

- **json-canonicalize 1.0.0 → 3.0.1** — align with `@openoba/rulsynor-core`;
  canonical output unchanged for normal preimages (verified via hash-compare),
  NaN/Infinity now throw (fail-closed) instead of silently serializing to `null`.
- **vitest 3.0.0 → 5.0.1** — fix GHSA-82fw-gwwq-j7x9 (moderate): path traversal /
  arbitrary file read via `@vitest/mocker` redirect mock. No test-code changes
  required (tests use only `describe`/`it`/`expect`/`beforeAll`/`afterAll`).
- **@openoba/rulsynor-core 1.2.2 → 1.2.3** — pick up js-yaml GHSA-2883 fix.

## [0.1.3] - 2026-09-11

- Depend on `@openoba/rulsynor-core@1.2.2`.

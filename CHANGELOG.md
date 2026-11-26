# Changelog

All notable changes to this project are documented in this file and on the [GitHub Releases](https://github.com/cawalch/node-yara-x/releases) page.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- See docs/release-process.md for how this section is promoted. -->

### Added
- **`rulesFormatInfo()`**: reports the serialized-blob format version plus the YARA-X and package versions, so a blob cache can key on compatibility. `deserialize()` now names all three when a blob was produced by an incompatible build, instead of a bare format number.
- **Structured diagnostic locations**: `CompilerError` and `CompilerWarning` now populate `source`, `line`, and `column` instead of always returning `undefined`. File-based entry points report the rule file path.
- **Metadata on the binary catalog**: `BinaryScanResult.catalog.rules[].meta` and `RuleInfo.meta` (from `getRules()`) carry rule metadata, and `toRuleMatches()` materializes the same `meta` object as `scan()`.
- **`bigint` global variables**: exact signed 64-bit values can be passed through `defineVariables`, scan variables, and `defineVariable()`. Out-of-range BigInts throw instead of truncating.
- **Fields on thrown compile errors**: a rejected rule set now carries `ruleCode` (the `E0nn` code) and, where the diagnostic has one, `source` / `line` / `column` on the thrown `Error` — the same names as the objects from `getCompilationErrors()` and `validate()`. `code` and `message` are unchanged, so existing handling still works. WASM emission (`emitWasmFile()`, `emitWasmFileAsync()`, `compileFileToWasm()`) has no report channel of its own and keeps throwing the plain error until the error-code work in #282 settles.

### Changed
- **Incremental additions cost one compilation, not one per call**: `addRuleSource()`, `addRuleSources()`, `addRuleFile()` and `defineVariable()` now record the change — after checking the new source on its own — and the rule set is rebuilt once, when it is next read or scanned. 120 one-rule sources: 5.67 s → ≈100 ms (100–110 ms across runs), and the cost no longer grows with what is already on the scanner (release build, macOS/arm64). `compile()` and `addRuleSources()` accept what they accepted before.
- **Reads report the current rules, not the rules as of the last rebuild**: `getRules()`, `getWarnings()`, `getIgnoredRules()`, `getCompilationErrors()`, `getImports()`, `ruleCount`, `serialize()`, `emitWasmFile()`, `emitWasmFileAsync()` and every scan materialize a pending addition first. They can therefore report an error a pending source causes; the async entry points (`scanAsync()` and friends) throw it from the call rather than rejecting the promise. The previous rule set is kept, but a strict scanner has nothing that can skip the offending source, so it reports the same error on every read until the rules are fixed and that scanner should be discarded — with `ignoreInvalidRules` the rule is skipped and listed instead.
- **Errors only the whole rule set can judge moved from `addRuleSource()` to the next read**: anything whose cause sits in a source that is not part of the batch, measured here as `E009` (a condition referencing a rule or global no added source defines), `E012` across sources (a rule name an added source already uses) and `E013` across sources (a rule identifier that clashes with one another source brings in, e.g. a rule named `pe` after a source that imports `pe`), because nothing short of the whole set can decide them. Same message, same `ruleCode`, same verdict as one `compile()` of the same sources in the same order. Everything a source is guilty of by itself still throws from the call — `E001`, `E014`, `E025`, the opt-in `E018`, duplicates inside one source, failed `include`s and module errors — and so do the source-level errors in tolerant mode. End a batch of additions with `getRules()` inside the same `try` to keep the strict timing, or load rules with `ignoreInvalidRules` so an unusable rule is skipped and listed by `getIgnoredRules()` instead of blocking the set.
- **`defineVariable()` checks the name where it was called**: an identifier YARA-X refuses (`"1bad"`, `"a b"`, `""`, …) throws from `defineVariable()` and leaves the globals as they were, because a global cannot be removed afterwards — recording it would make every later read fail with nothing to undo. What is deferred is how the existing rules read the value: a type conflict reports `E003` on the next read and is undone by redefining the name with a matching type.
- **`yara-x` is pinned exactly** (`=1.23.0`) because its private serialization format version decides blob compatibility; blob format changes now require a deliberate dependency bump and release note.
- **Source-level errors now throw in tolerant mode**: with `ignoreInvalidRules: true`, syntax errors, invalid UTF-8, banned or unknown module imports, and missing includes are no longer silently swallowed; they throw instead of returning a scanner that silently lacks rules. Per-rule failures remain skipped and reported.
- **Extern string variables keep their type**: a string value such as `"42"` or `"true"` is now a YARA string global instead of being coerced to an integer or boolean. Pass `42`/`true` for those types.
- **`defineVariable()` accepts typed values**: it now takes `string | number | boolean | bigint`; previously only strings were accepted, and numeric-looking strings were coerced.
- **Rule-file paths in diagnostics and includes**: `fromFile()`, `addRuleFile()`, and `compileFileToWasm()` set the file as the source origin, so diagnostics name the file, and `include` statements resolve next to it (explicit `includeDirectories` still win).
- **Module option validation**: unknown names in `bannedModules` are now an error rather than a silent no-op; unknown `ignoreModules` entries produce an `unknown_ignored_module` warning.
- **Batch filtering**: `includePatterns`/`excludePatterns` now match root-relative patterns as well as full paths, so `subdir/**` works like `**/subdir/**`. `BatchScanResult.filteredFiles` reports how many discovered files the filters removed.
- **`setTimeout(0)` disables the timeout** instead of expiring immediately; the best-effort overshoot is documented.
- **Concurrency pools are reused** across batch calls instead of being rebuilt each time, so `concurrency` no longer discards the worker scanner cache.
- **Async typings match the sync API**: `variables` is `Record<string, string | number | boolean | bigint>` everywhere, and `emitWasmFileAsync()` resolves to `Promise<void>`.
- **`BinaryMatchView.catalog` is built once**: the getter marshalled every rule name, tag, pattern and metadata entry on every property access, so reading it inside a per-match loop was quadratic in the catalog size — 0.375 ms per read for a 300-rule catalog, re-measured on the current build. It now builds the object on first read and hands back the same one, costing 0.0016 ms per read; `view.catalog === view.catalog` holds and the object is shared, so treat it as read-only. `view.buffer` still copies the records on each read, and the README says so.

### Fixed
- **Scan options can be changed while a scan is running**: `setTimeout()`, `setMaxScanSize()`, `setMaxMatchesPerPattern()`, `setUseMmap()`, `setFastScan()` and `setMatchContextSize()` threw `InvalidArg` ("the same native value cannot be borrowed mutably while another borrow is active") for as long as a task started with `scanAsync()`, `scanFileAsync()`, `isMatchAsync()`, `scanBinaryAsync()`, `scanFiles()` or `scanDirectory()` was still in flight. They now apply to the next scan without disturbing the running one. `addRuleSource()`, `addRuleFile()`, `defineVariable()` and `setConsoleLog()` still require the scanner to be idle (#292).

---

## [0.13.0] - 2026-11-14

### Added
- **Rule logging**: `setConsoleLog(callback)` routes messages rules emit through the `console` module to JavaScript. Messages are delivered on the event loop, so a synchronous scan returns before they arrive; call it with no argument to stop receiving them.
- **Rule profiling**: `getSlowestRules(n)` and `clearProfilingData()` report the rules that dominate scan time, split into pattern-matching and condition-execution timings. Timings accumulate across synchronous scans and only rules past 100 ms in total are reported. Costs ~16 KB in the binary and no measurable scan time (2.94 ms vs 3.05 ms per 5 MB scan on a 200-rule set).
- **Five more YARA-X modules**: `zip`, `lnk`, `dex`, `crx` and `cuckoo` are now compiled in, so rules importing them compile instead of failing with `error[E010]: unknown module`. Together they cost ~383 KB in the linked binary; `vt` stays out because the public-suffix list it needs is ~1.2 MB on its own.
- **Bun and Deno** are documented as supported — they load the same prebuilt binary through Node-API — and CI now runs a smoke test under both.

### Changed
- **YARA-X moved from 1.22.1 to 1.23.0**, which brings UTF-8 byte sequence regex optimization for smaller and faster PikeVM execution, `\b{start-half}` and `\b{end-half}` word boundary assertions, WASM linker reuse for scanner creation performance, and numerous compiler bugfixes. Rule blobs serialized by 0.12.0 or earlier were compiled by 1.22.x and must be recompiled before they can be deserialized.
- Updated `@napi-rs/cli` to `3.10.12` and `@napi-rs/wasm-runtime` to `1.2.7`.

---

## [0.12.0] - 2026-10-31

### Added
- **XOR key reporting**: `MatchData.xorKey` carries the XOR key that produced a match for patterns compiled with an `xor` modifier, so an obfuscated sample can be decoded without a second scan. Populated by `scan()`, `scanFile()`, the async scan APIs, and the batch/directory scanners; absent for plain patterns.
- **`BinaryMatchView.getXorKey(index)`**: reads the same key from the binary match ABI. It rides in the existing `flags` word (bits 0-7 hold the key, bit 8 marks its presence), so the 24-byte record layout is unchanged, and `toRuleMatches()` fills `MatchData.xorKey` from it.

### Changed
- Pinned the `npm` CLI used by the publish job to an exact version (`11.21.1`) instead of the `^11.5.1` range, so the toolchain holding the publishing credentials cannot change without review.
- **YARA-X moved from 1.21.0 to 1.22.1**, which brings the `int64`/`int64be`/`uint64`/`uint64be` built-ins and `pe.offset_to_rva` to rule authors. Rule blobs serialized by 0.11.0 or earlier were compiled by 1.21.x and must be recompiled before they can be deserialized.

---

## [0.11.0] - 2026-10-25

### Added
- **Compiled Rules Introspection**:
  - `scanner.ruleCount`: Getter returning the total count of compiled rules.
  - `scanner.getImports()`: Returns an array of imported YARA-X module names (`"pe"`, `"math"`, etc.).
  - `scanner.getRules()`: Returns structured metadata (`RuleInfo[]`) including `identifier`, `namespace`, `tags`, and `patterns`.
  - Introspection data is fully preserved across `serialize()` and `deserialize()`.
- **Scanner `maxScanSize` Protection**:
  - `scanner.setMaxScanSize(maxBytes: number)`: Enforces an upper bound on bytes scanned per buffer or file, guarding against memory and processing exhaustion on oversized inputs.
  - `TaskScanOptions.maxScanSize`: Integrated into async buffer and file scanning tasks.
- **Directory Traversal File Size Filtering**:
  - `BatchScanOptions.minFileSize`: Filters out files below the specified byte size during native traversal.
  - `BatchScanOptions.maxFileSize`: Filters out files exceeding the specified byte size during native traversal.
- **`BinaryMatchView` Lazy Materialization**:
  - `BinaryMatchView.prototype.toRuleMatches(source?: Buffer): RuleMatch[]`: Reconstructs standard `RuleMatch` objects directly from the compact binary match buffer, allowing consumers to scan using the binary ABI and lazily unpack match objects on demand.

### Performance
- **Direct Binary Packing**:
  - Elimination of intermediate `Vec<FlatMatchRecord>` allocation in the binary scanning engine, packing directly into napi `Uint8Array` memory buffers.
- **Batch Scanning Zero-Copy Path Consumption**:
  - Shifted batch file list processing to move strings into worker threads without redundant cloning.
- **$O(1)$ Compiler Error Deduplication**:
  - Replaced linear search with `HashSet<(usize, usize)>` during compilation error deduplication in tolerant mode.

---

## [0.10.0] - 2026-10-19

### Added
- **Native Multi-Threaded Batch and Directory Scanning**:
  - `scanner.scanFiles(paths, options?, variables?)` and `scanner.scanFilesSync(...)`: Parallel file scanning across a native Rayon work-stealing pool.
  - `scanner.scanDirectory(dirPath, options?, variables?)` and `scanner.scanDirectorySync(...)`: Native recursive directory traversal with glob pattern filtering (`includePatterns`, `excludePatterns`) and `maxDepth` limits.
- **Flat / Binary Match ABI**:
  - High-throughput binary match scanning (`scanBinary`, `scanFileBinary`, `scanBinaryAsync`, `scanFileBinaryAsync`) returning a zero-copy `BinaryMatchView`.

---

## [0.8.0] - 2026-10-18

### Fixed
- Fixed missing license files in published `@litko/yara-x` and platform tarballs.
- Dual licensing (`MIT AND BSD-3-Clause`) explicitly declared in package metadata.

### Added
- Platform support matrix, troubleshooting guides, and Sigstore / GitHub attestation verification instructions.
- Benchmarking baseline suite (`pnpm profile:baseline`, `pnpm profile:compare`).

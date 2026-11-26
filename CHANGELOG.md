# Changelog

All notable changes to this project are documented in this file and on the [GitHub Releases](https://github.com/cawalch/node-yara-x/releases) page.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- See docs/release-process.md for how this section is promoted. -->

### Added
- **`AbortSignal` on the async scan methods**: pass a signal as the last argument to `scanAsync()`, `scanFileAsync()`, `isMatchAsync()`, `isFileMatchAsync()`, `scanBinaryAsync()`, `scanFileBinaryAsync()`, `scanFiles()` and `scanDirectory()` to stop work you no longer want (#285).
  - A cancelled call rejects — it never throws from the call — with `name` `AbortError` and `code` `Cancelled`, whether the signal fired before the call, while the work sat queued, or between two files of a batch. A signal that was already aborted at the call is refused without dispatching anything.
  - An in-flight call hangs one `abort` listener on the signal and takes it off when the task settles, so a controller held for the lifetime of the process costs no memory per scan. Measured: 1,000,000 `scanAsync()` calls made with one signal keep RSS flat, where N-API's own `AbortSignal` wrapper grew it by ~250 bytes per call with nothing reclaimed.
  - A batch cancelled part-way through resolves with the partial sweep, `cancelled: true`, and `cancelledFiles` counting the files that never started; directory traversal stops too. Up to `concurrency` files already in flight still finish, so `scannedFiles` can overshoot the abort by that much.
  - A scan already running cannot be interrupted: `setTimeout()` and `setMaxScanSize()` stay the in-scan bounds, and the synchronous methods take no signal.
- **`safeRules` preset**: one option for a rule set you did not write. It turns on `errorOnSlowPattern`, forces `ignoreInvalidRules` off, and disables `include` (#291).
  - Passing `false` for any of those alongside the preset does not re-enable it; a merged options object could otherwise undo the preset quietly.
  - `errorOnSlowLoop` is not in the bundle: measured on `/a+b/` it leaves the pattern compiling. The preset is compile-time only, so a running scan still needs `setTimeout()` or `setMaxScanSize()`.
- **`kind` on thrown errors**: every synchronous entry point stamps the class of failure (`compile`, `timeout`, `io`, `mmap`, `protobuf`, `unknown-module`) so callers branch without matching message text. `code`, `message`, and `ruleCode` keep their values (#282).
  - An async rejection carries no stamp: a task's compute phase has no JavaScript environment to decorate.
- **`rulesFormatInfo()`**: reports the serialized-blob format version plus the YARA-X and package versions, so a blob cache can key on compatibility.
- **Clearer blob mismatch errors**: `deserialize()` names all three versions when a blob came from an incompatible build, instead of a bare format number.
- **Structured diagnostic locations**: `CompilerError` and `CompilerWarning` now populate `source`, `line`, and `column` instead of always returning `undefined`. File-based entry points report the rule file path.
- **Metadata on the binary catalog**: `BinaryScanResult.catalog.rules[].meta` and `RuleInfo.meta` (from `getRules()`) carry rule metadata, and `toRuleMatches()` materializes the same `meta` object as `scan()`.
- **`bigint` global variables**: exact signed 64-bit values can be passed through `defineVariables`, scan variables, and `defineVariable()`. Out-of-range BigInts throw instead of truncating.
- **Fields on thrown compile errors**: a rejected rule set throws an `Error` carrying `ruleCode`, the `E0nn` code, plus `source` / `line` / `column` where the diagnostic has them. The names match the objects from `getCompilationErrors()` and `validate()`, and `code` and `message` are unchanged, so existing handling still works.
  - WASM emission (`emitWasmFile()`, `emitWasmFileAsync()`, `compileFileToWasm()`) has no report channel of its own. It keeps throwing the plain error until the error-code work in #282 settles.

### Changed
- **Incremental additions cost one compilation, not one per call**: `addRuleSource()`, `addRuleSources()`, `addRuleFile()` and `defineVariable()` record the change and rebuild the rule set once, when it is next read or scanned. Each new source is still checked on its own when it is added.
  - 120 one-rule sources: 5.67 s → ≈100 ms, and 100–110 ms across runs, release build on macOS/arm64. The cost no longer grows with what is already on the scanner.
  - `compile()` and `addRuleSources()` accept what they accepted before.
- **Reads report the current rules, not the rules as of the last rebuild**: `getRules()`, `getWarnings()`, `getIgnoredRules()`, `getCompilationErrors()`, `getImports()`, `ruleCount`, `serialize()`, `emitWasmFile()`, `emitWasmFileAsync()` and every scan materialize a pending addition first.
  - Such a read can report an error the pending source causes. The async entry points, `scanAsync()` and friends, throw it from the call instead of rejecting the promise.
  - The previous rule set is kept but never served. A strict scanner has nothing that can skip the offending source, so every read reports the same error until the rules are fixed. Discard that scanner and build a new one.
  - With `ignoreInvalidRules` the offending rule is skipped and listed instead.
- **Errors only the whole rule set can judge now report on the next read** instead of from `addRuleSource()`. Their cause sits in a source outside the batch, so nothing short of the whole set can decide them. Measured on this binding:
  - `E009`: a condition references a rule or global that no added source defines.
  - `E012`: a rule name that another added source already uses.
  - `E013`: a rule identifier that clashes with one another source brings in, such as a rule named `pe` after a source that imports `pe`.
  - The message, the `ruleCode`, and the verdict match one `compile()` of the same sources in the same order.
- **Everything a source is guilty of on its own still throws from the adding call**: `E001`, `E014`, `E025`, the opt-in `E018`, duplicates inside one source, failed `include`s and module errors. Source-level errors report there in tolerant mode too.
- **Keep add-time strictness by reading at the end of a batch**: call `getRules()` inside the same `try`, or load with `ignoreInvalidRules` so an unusable rule is skipped and listed by `getIgnoredRules()`. The README's [Build a scanner incrementally](./README.md#build-a-scanner-incrementally) table lists which code reports where.
- **`defineVariable()` checks the name where it was called**: an identifier YARA-X refuses, such as `"1bad"`, `"a b"` or `""`, throws from `defineVariable()` and leaves the globals as they were. A global cannot be removed afterwards, so recording it would make every later read fail with nothing to undo.
  - What is still deferred is how the existing rules read the value. A type conflict reports `E003` on the next read, and redefining the name with a matching type undoes it.
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
- **`BinaryMatchView.catalog` is built once**: the getter marshalled every rule name, tag, pattern and metadata entry on every property access, so reading it inside a per-match loop was quadratic in the catalog size. A 300-rule catalog cost 0.375 ms per read, re-measured on the current build.
  - It now builds the object on first read and hands back the same one, at 0.0016 ms per read. `view.catalog === view.catalog` holds and the object is shared, so treat it as read-only.
  - `view.buffer` still copies the records on each read, and the README says so.

### Fixed
- **Scan options can be changed while a scan is running**: `setTimeout()`, `setMaxScanSize()`, `setMaxMatchesPerPattern()`, `setUseMmap()`, `setFastScan()` and `setMatchContextSize()` threw `InvalidArg` while a task started with `scanAsync()`, `scanFileAsync()`, `isMatchAsync()`, `scanBinaryAsync()`, `scanFiles()` or `scanDirectory()` was still in flight. The message was "the same native value cannot be borrowed mutably while another borrow is active".
  - The setters now apply to the next scan without disturbing the running one.
  - `addRuleSource()`, `addRuleFile()`, `defineVariable()` and `setConsoleLog()` still require the scanner to be idle (#292).

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

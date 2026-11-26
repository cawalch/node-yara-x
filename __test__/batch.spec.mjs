import test from "node:test";
import assert from "node:assert";
import { chmod, mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compile } from "../index.js";

test("Native Multi-Threaded Batch and Directory Scanning", async (t) => {
  const tempDir = await mkdtemp(join(tmpdir(), "yara-x-batch-test-"));

  // Create test directory tree:
  // tempDir/
  //   file1.txt (matches test_rule: "SUSPICIOUS_PAYLOAD")
  //   file2.bin (matches test_rule: "SUSPICIOUS_PAYLOAD")
  //   file3.txt (clean)
  //   subdir/
  //     file4.txt (matches test_rule: "SUSPICIOUS_PAYLOAD")
  //     file5.log (clean)
  //     subsubdir/
  //       file6.txt (matches test_rule: "SUSPICIOUS_PAYLOAD")
  await writeFile(join(tempDir, "file1.txt"), "some benign text SUSPICIOUS_PAYLOAD end");
  await writeFile(join(tempDir, "file2.bin"), "binary data SUSPICIOUS_PAYLOAD trailing bytes");
  await writeFile(join(tempDir, "file3.txt"), "completely clean text file");

  const subDir = join(tempDir, "subdir");
  await mkdir(subDir);
  await writeFile(join(subDir, "file4.txt"), "nested payload: SUSPICIOUS_PAYLOAD");
  await writeFile(join(subDir, "file5.log"), "log line with benign contents");

  const subSubDir = join(subDir, "subsubdir");
  await mkdir(subSubDir);
  await writeFile(join(subSubDir, "file6.txt"), "deep nested payload: SUSPICIOUS_PAYLOAD");

  t.after(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const rule = `
    rule DetectSuspicious {
      meta:
        description = "Detects test suspicious payload"
        severity = 8
      strings:
        $payload = "SUSPICIOUS_PAYLOAD"
      condition:
        $payload
    }
  `;

  const scanner = compile(rule);

  await t.test("scanFilesSync - basic list of files", () => {
    const files = [
      join(tempDir, "file1.txt"),
      join(tempDir, "file2.bin"),
      join(tempDir, "file3.txt"),
    ];

    const result = scanner.scanFilesSync(files);
    assert.strictEqual(result.totalFiles, 3);
    assert.strictEqual(result.scannedFiles, 3);
    assert.strictEqual(result.matchedFiles, 2);
    assert.strictEqual(result.errors.length, 0);
    assert(result.durationMs >= 0);

    // By default, only matching files are included in results
    assert.strictEqual(result.results.length, 2);
    const matchedPaths = result.results.map((r) => r.filePath);
    assert(matchedPaths.includes(join(tempDir, "file1.txt")));
    assert(matchedPaths.includes(join(tempDir, "file2.bin")));
    assert.strictEqual(result.results[0].matches[0].ruleIdentifier, "DetectSuspicious");
  });

  await t.test("scanFilesSync - includeCleanFiles: true", () => {
    const files = [
      join(tempDir, "file1.txt"),
      join(tempDir, "file3.txt"),
    ];

    const result = scanner.scanFilesSync(files, { includeCleanFiles: true });
    assert.strictEqual(result.totalFiles, 2);
    assert.strictEqual(result.scannedFiles, 2);
    assert.strictEqual(result.matchedFiles, 1);
    assert.strictEqual(result.results.length, 2);

    const clean = result.results.find((r) => r.filePath === join(tempDir, "file3.txt"));
    assert(clean);
    assert.strictEqual(clean.isMatch, false);
    assert.strictEqual(clean.matches.length, 0);

    const matched = result.results.find((r) => r.filePath === join(tempDir, "file1.txt"));
    assert(matched);
    assert.strictEqual(matched.isMatch, true);
    assert.strictEqual(matched.matches.length, 1);
  });

  await t.test("scanFilesSync - onlyMatches boolean fast-path", () => {
    const files = [
      join(tempDir, "file1.txt"),
      join(tempDir, "file2.bin"),
    ];

    const result = scanner.scanFilesSync(files, { onlyMatches: true });
    assert.strictEqual(result.matchedFiles, 2);
    assert.strictEqual(result.results.length, 2);
    assert.strictEqual(result.results[0].isMatch, true);
    // Matches array is empty in fast-path boolean mode
    assert.strictEqual(result.results[0].matches.length, 0);
  });

  await t.test("scanFilesSync - error resilience on missing files", () => {
    const files = [
      join(tempDir, "file1.txt"),
      join(tempDir, "does-not-exist.bin"),
    ];

    const result = scanner.scanFilesSync(files);
    assert.strictEqual(result.totalFiles, 2);
    assert.strictEqual(result.scannedFiles, 1);
    assert.strictEqual(result.matchedFiles, 1);
    assert.strictEqual(result.errors.length, 1);
    assert.strictEqual(result.errors[0].filePath, join(tempDir, "does-not-exist.bin"));
    assert(result.errors[0].error.length > 0);
  });

  await t.test("scanFiles (async) - parallel execution across Rayon pool", async () => {
    const files = [
      join(tempDir, "file1.txt"),
      join(tempDir, "file2.bin"),
      join(tempDir, "file3.txt"),
      join(subDir, "file4.txt"),
    ];

    const result = await scanner.scanFiles(files, { concurrency: 2 });
    assert.strictEqual(result.totalFiles, 4);
    assert.strictEqual(result.scannedFiles, 4);
    assert.strictEqual(result.matchedFiles, 3);
    assert.strictEqual(result.results.length, 3);
  });

  await t.test("scanFiles (async) - scan-time variables support", async () => {
    const varRule = `
      rule VarDetection {
        condition:
          suspicious_flag and filesize > 0
      }
    `;
    const varScanner = compile(varRule, {
      defineVariables: { suspicious_flag: false },
    });

    // When variable is false, should not match
    const resultFalse = await varScanner.scanFiles([join(tempDir, "file1.txt")]);
    assert.strictEqual(resultFalse.matchedFiles, 0);

    // Pass variable override in scan
    const resultTrue = await varScanner.scanFiles(
      [join(tempDir, "file1.txt")],
      undefined,
      { suspicious_flag: true },
    );
    assert.strictEqual(resultTrue.matchedFiles, 1);
  });

  await t.test("scanDirectorySync - recursive traversal", () => {
    const result = scanner.scanDirectorySync(tempDir);
    assert.strictEqual(result.totalFiles, 6);
    assert.strictEqual(result.scannedFiles, 6);
    assert.strictEqual(result.matchedFiles, 4); // file1, file2, file4, file6
    assert.strictEqual(result.errors.length, 0);
  });

  await t.test("scanDirectorySync - maxDepth filtering", () => {
    // maxDepth = 1 means only files directly in tempDir
    const result = scanner.scanDirectorySync(tempDir, { maxDepth: 1 });
    assert.strictEqual(result.totalFiles, 3); // file1, file2, file3
    assert.strictEqual(result.matchedFiles, 2);
  });

  await t.test("scanDirectorySync - includePatterns glob filter", () => {
    // Only scan .bin files
    const result = scanner.scanDirectorySync(tempDir, {
      includePatterns: ["*.bin"],
    });
    assert.strictEqual(result.totalFiles, 1); // file2.bin
    assert.strictEqual(result.matchedFiles, 1);
    assert.strictEqual(result.results[0].filePath, join(tempDir, "file2.bin"));
  });

  await t.test("scanDirectorySync - excludePatterns glob filter", () => {
    // Exclude subdir entirely
    const result = scanner.scanDirectorySync(tempDir, {
      excludePatterns: ["**/subdir/**"],
    });
    assert.strictEqual(result.totalFiles, 3); // file1, file2, file3
    assert.strictEqual(result.matchedFiles, 2);
  });

  await t.test("scanDirectory - relative excludePatterns match from the scan root", () => {
    const result = scanner.scanDirectorySync(tempDir, {
      excludePatterns: ["subdir/**"],
      includeCleanFiles: true,
    });

    assert.strictEqual(result.totalFiles, 3);
    assert.strictEqual(result.filteredFiles, 3);
    assert.ok(
      !result.results.some((entry) => entry.filePath.includes("subdir")),
      "the relative exclude must remove the whole subtree",
    );
  });

  await t.test("scanDirectory - filteredFiles counts filter misses", () => {
    const result = scanner.scanDirectorySync(tempDir, {
      includePatterns: ["*.bin"],
      includeCleanFiles: true,
    });

    assert.strictEqual(result.totalFiles, 1);
    assert.strictEqual(result.filteredFiles, 5);
    assert.strictEqual(result.results[0].filePath, join(tempDir, "file2.bin"));
  });

  await t.test("scanFiles - filteredFiles is zero for an explicit list", () => {
    const result = scanner.scanFilesSync([join(tempDir, "file1.txt")]);
    assert.strictEqual(result.filteredFiles, 0);
  });

  await t.test("scanDirectorySync - results do not depend on the concurrency size", () => {
    const expected = scanner.scanDirectorySync(tempDir, { onlyMatches: true });

    // 8 sizes also exercises the pool cache's overflow path (sizes past the
    // cached cap still get a working pool).
    for (const concurrency of [1, 2, 3, 4, 5, 6, 7, 8]) {
      const result = scanner.scanDirectorySync(tempDir, { onlyMatches: true, concurrency });
      assert.strictEqual(result.totalFiles, expected.totalFiles);
      assert.strictEqual(result.matchedFiles, expected.matchedFiles);
      assert.deepStrictEqual(
        result.results.map((entry) => entry.filePath).sort(),
        expected.results.map((entry) => entry.filePath).sort(),
      );
    }
  });

  await t.test("scanDirectorySync - a fixed `concurrency` reuses its thread pool (#277)", () => {
    // Rebuilding a Rayon pool per call spawned fresh threads every time, and
    // new threads start with an empty worker-side scanner cache, so the option
    // cost more than omitting it. The guard used to time that against the
    // shared pool; on runners the per-call medians are ~0.1 ms and the ratio
    // landed at 1.5x-2.5x either way (#296), so assert the mechanism instead:
    // a thread count that is already cached must not build another pool.
    const options = { onlyMatches: true };

    assert.ok(
      scanner.scanDirectorySync(tempDir, options).totalFiles >= 4,
      "fixture has files to scan",
    );

    // Sizes no other test in this file asks for, so the cache cannot be warm.
    const reused = 9;
    const fresh = 13;

    scanner.scanDirectorySync(tempDir, { ...options, concurrency: reused });
    const afterWarm = scanner.threadPoolBuilds();

    for (let i = 0; i < 5; i++) {
      scanner.scanDirectorySync(tempDir, { ...options, concurrency: reused });
      // Interleave the default lane, as the timing version did.
      scanner.scanDirectorySync(tempDir, options);
    }

    assert.strictEqual(
      scanner.threadPoolBuilds() - afterWarm,
      0,
      "calls at a fixed `concurrency` must reuse the cached pool",
    );

    // Non-vacuity: the counter really does move when a pool is built.
    const beforeFresh = scanner.threadPoolBuilds();
    scanner.scanDirectorySync(tempDir, { ...options, concurrency: fresh });
    assert.strictEqual(
      scanner.threadPoolBuilds() - beforeFresh,
      1,
      "a first call at a new thread count must build exactly one pool",
    );
  });

  await t.test("scanDirectory (async) - full recursive parallel scan", async () => {
    const result = await scanner.scanDirectory(tempDir, {
      concurrency: 4,
    });
    assert.strictEqual(result.totalFiles, 6);
    assert.strictEqual(result.scannedFiles, 6);
    assert.strictEqual(result.matchedFiles, 4);
    assert(result.durationMs > 0);
  });

  await t.test("scanDirectorySync - file size filters (minFileSize & maxFileSize)", async () => {
    const sizeTestDir = await mkdtemp(join(tmpdir(), "yara-x-size-filter-"));
    try {
      await writeFile(join(sizeTestDir, "empty.txt"), ""); // 0 bytes
      await writeFile(join(sizeTestDir, "medium.txt"), "A".repeat(50) + " SUSPICIOUS_PAYLOAD"); // ~70 bytes
      await writeFile(join(sizeTestDir, "large.txt"), "B".repeat(500) + " SUSPICIOUS_PAYLOAD"); // ~520 bytes

      // Filter: minFileSize: 10 (should exclude empty.txt)
      const resMin = scanner.scanDirectorySync(sizeTestDir, { minFileSize: 10, includeCleanFiles: true });
      assert.strictEqual(resMin.totalFiles, 2);

      // Filter: maxFileSize: 100 (should exclude large.txt)
      const resMax = scanner.scanDirectorySync(sizeTestDir, { maxFileSize: 100, includeCleanFiles: true });
      assert.strictEqual(resMax.totalFiles, 2);

      // Filter: between 10 and 100 bytes (should only include medium.txt)
      const resBoth = scanner.scanDirectorySync(sizeTestDir, { minFileSize: 10, maxFileSize: 100 });
      assert.strictEqual(resBoth.totalFiles, 1);
      assert.strictEqual(resBoth.matchedFiles, 1);
      assert.strictEqual(resBoth.results[0].filePath, join(sizeTestDir, "medium.txt"));

      // Async scanDirectory with size filters
      const resAsync = await scanner.scanDirectory(sizeTestDir, { minFileSize: 10, maxFileSize: 100 });
      assert.strictEqual(resAsync.totalFiles, 1);
      assert.strictEqual(resAsync.matchedFiles, 1);
    } finally {
      await rm(sizeTestDir, { recursive: true, force: true });
    }
  });

  await t.test("scanDirectory - reports traversal errors for unreadable directories", async (t) => {
    if (process.platform === "win32") {
      t.skip("Windows does not enforce POSIX directory mode bits");
      return;
    }
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      t.skip("root bypasses directory mode bits");
      return;
    }

    const rootDir = await mkdtemp(join(tmpdir(), "yara-x-traversal-test-"));
    const lockedDir = join(rootDir, "locked");
    await mkdir(lockedDir);
    await writeFile(join(rootDir, "open.txt"), "clean file");
    await writeFile(join(lockedDir, "hidden.txt"), "SUSPICIOUS_PAYLOAD");
    await chmod(lockedDir, 0o000);

    t.after(async () => {
      await chmod(lockedDir, 0o755).catch(() => {});
      await rm(rootDir, { recursive: true, force: true });
    });

    const syncResult = scanner.scanDirectorySync(rootDir, { includeCleanFiles: true });
    assert.ok(syncResult.errors.length >= 1, "sync scan must report the traversal error");
    assert.ok(
      syncResult.errors.some((error) => error.filePath.includes("locked")),
      `traversal error must name the unreadable directory: ${JSON.stringify(syncResult.errors)}`,
    );

    const asyncResult = await scanner.scanDirectory(rootDir, { includeCleanFiles: true });
    assert.ok(asyncResult.errors.length >= 1, "async scan must report the traversal error");
    assert.ok(
      asyncResult.errors.some((error) => error.filePath.includes("locked")),
      `traversal error must name the unreadable directory: ${JSON.stringify(asyncResult.errors)}`,
    );

    assert.ok(syncResult.results.some((result) => result.filePath.endsWith("open.txt")));
  });

  await t.test("AbortSignal - a sweep cancelled part-way through keeps what it scanned", async () => {
    // Long enough that the abort lands inside the sweep: 12,000 files on one thread
    // against a 5 ms delay. The uncancelled run afterwards is what shows these
    // assertions are about cancellation and not about a sweep too short to finish.
    const files = Array.from({ length: 12_000 }, () => join(tempDir, "file1.txt"));
    const controller = new AbortController();

    const sweep = scanner.scanFiles(files, { concurrency: 1 }, null, controller.signal);
    await new Promise((resolve) => setTimeout(resolve, 5));
    controller.abort();
    const result = await sweep;

    assert.strictEqual(result.totalFiles, files.length, "every file was submitted");
    assert.strictEqual(result.cancelled, true, "a cancelled sweep must say so");
    assert.ok(result.cancelledFiles > 0, `files never started must be counted, got ${result.cancelledFiles}`);
    assert.strictEqual(
      result.scannedFiles + result.cancelledFiles + result.errors.length,
      result.totalFiles,
      "no file may disappear between the counters",
    );
    assert.ok(
      result.results.length <= result.scannedFiles,
      "results cannot outnumber the files that were scanned",
    );

    const full = await scanner.scanFiles(files, { concurrency: 1 });
    assert.strictEqual(full.cancelled, false, "no signal means no cancellation");
    assert.strictEqual(full.cancelledFiles, 0);
    assert.strictEqual(full.scannedFiles, files.length);
  });

  await t.test("AbortSignal - a signal aborted during traversal stops the walk", async () => {
    // Queued means a rejection, walking means a partial sweep; both are documented
    // outcomes, so each branch is asserted on its own terms. What must never happen
    // is a sweep that settles with nothing reported, or one that never settles.
    const treeDir = await mkdtemp(join(tmpdir(), "yara-x-cancel-tree-"));
    t.after(() => rm(treeDir, { recursive: true, force: true }));
    await Promise.all(
      Array.from({ length: 2000 }, (_, i) => writeFile(join(treeDir, `f${i}.txt`), "benign contents")),
    );

    const controller = new AbortController();
    const sweep = scanner.scanDirectory(treeDir, { concurrency: 1, onlyMatches: true }, null, controller.signal);
    controller.abort();

    const outcome = await sweep.then((result) => ({ result }), (error) => ({ error }));
    if (outcome.error) {
      assert.strictEqual(outcome.error.name, "AbortError", "cancelling queued work rejects as an abort");
      assert.strictEqual(outcome.error.code, "Cancelled");
    } else {
      const { result } = outcome;
      assert.strictEqual(result.cancelled, true, "a sweep cut short must report the cancellation");
      assert.ok(result.scannedFiles < 2000, `the walk must stop early, scanned ${result.scannedFiles}`);
      assert.strictEqual(
        result.scannedFiles + result.cancelledFiles + result.errors.length,
        result.totalFiles,
        "no discovered file may disappear between the counters",
      );
    }
  });
  await t.test("scanDirectory - throws on invalid directory", async () => {
    assert.throws(() => {
      scanner.scanDirectorySync(join(tempDir, "non-existent-dir"));
    }, /Directory not found/);

    await assert.rejects(async () => {
      await scanner.scanDirectory(join(tempDir, "non-existent-dir"));
    }, /Directory not found/);
  });
});

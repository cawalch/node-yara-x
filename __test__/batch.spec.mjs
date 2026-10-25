import test from "node:test";
import assert from "node:assert";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
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

  await t.test("scanDirectory - throws on invalid directory", async () => {
    assert.throws(() => {
      scanner.scanDirectorySync(join(tempDir, "non-existent-dir"));
    }, /Directory not found/);

    await assert.rejects(async () => {
      await scanner.scanDirectory(join(tempDir, "non-existent-dir"));
    }, /Directory not found/);
  });
});

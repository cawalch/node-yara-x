import yarax from "../index.js";
import { existsSync, mkdirSync, writeFileSync, rmSync, statSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { strictEqual, ok, fail, throws, deepStrictEqual } from "assert";
import { describe, it, before, after } from "node:test";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const __tempDir = join(__dirname, "temp");

function createTempFile(content, extension = ".txt") {
  const tempFile = join(__tempDir, `test-${Date.now()}${extension}`);
  writeFileSync(tempFile, content);
  return tempFile;
}

function createTempDirectory() {
  if (!existsSync(__tempDir)) {
    mkdirSync(__tempDir, { recursive: true });
  }
}

function cleanupTempDirectory() {
  if (existsSync(__tempDir)) {
    rmSync(__tempDir, { recursive: true });
  }
}

before(createTempDirectory);
after(cleanupTempDirectory);

describe("yarax Tests", () => {
  it("should perform basic rule matching", () => {
    const rule = `
      rule test_rule {
        strings:
          $a = "hello world"
        condition:
          $a
      }
    `;

    const rules = yarax.compile(rule);
    const buffer = Buffer.from("This is a test with hello world in it");
    const matches = rules.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_rule",
      "Rule identifier should match",
    );
    strictEqual(matches[0].matches.length, 1, "Should have one match");
    strictEqual(
      matches[0].matches[0].data,
      "hello world",
      "Matched data should be correct",
    );
  });

  it("should compile rules into a namespace", () => {
    const rule = `
      rule namespaced_rule {
        strings:
          $a = "namespace test"
        condition:
          $a
      }
    `;

    const scanner = yarax.compile(rule, { namespace: "alpha" });
    const matches = scanner.scan(Buffer.from("This is a namespace test"));

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(matches[0].ruleIdentifier, "namespaced_rule");
    strictEqual(matches[0].namespace, "alpha");
  });

  it("should allow duplicate rule names in different namespaces", () => {
    const scanner = yarax.create();

    scanner.addRuleSource(
      `
        rule shared_name {
          strings:
            $a = "alpha value"
          condition:
            $a
        }
      `,
      "alpha",
    );

    scanner.addRuleSource(
      `
        rule shared_name {
          strings:
            $a = "beta value"
          condition:
            $a
        }
      `,
      "beta",
    );

    const matches = scanner.scan(Buffer.from("alpha value and beta value"));

    strictEqual(matches.length, 2, "Should match both namespaced rules");
    strictEqual(matches[0].ruleIdentifier, "shared_name");
    strictEqual(matches[0].namespace, "alpha");
    strictEqual(matches[1].ruleIdentifier, "shared_name");
    strictEqual(matches[1].namespace, "beta");
  });

  it("should not have any matches for any rules", () => {
    const rule = `
      rule test_no_match {
        strings:
          $a = "hello world"
        condition:
          $a
      }
    `;
    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is a test without the keyword");
    const matches = scanner.scan(buffer);
    strictEqual(matches.length, 0, "Should have no matching rules");
  });

  it("should handle multiple matches", () => {
    const rule = `
      rule test_multiple {
        strings:
          $a = "test"
        condition:
          $a
      }
    `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is a test with another test in it");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(matches[0].matches.length, 2, "Should have two matches");
  });

  it("should scan files", () => {
    const rule = `
      rule test_file {
        strings:
          $a = "file content"
        condition:
          $a
      }
    `;

    const fileContent = "This is file content for testing";
    const tempFile = createTempFile(fileContent);

    const scanner = yarax.compile(rule);
    const matches = scanner.scanFile(tempFile);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_file",
      "Rule identifier should match",
    );
  });

  it("should load rules from a file", () => {
    const rule = `
      rule test_from_file {
        strings:
          $a = "test content"
        condition:
          $a
      }
    `;

    const ruleFile = createTempFile(rule, ".yar");

    const scanner = yarax.fromFile(ruleFile);
    const buffer = Buffer.from("This is test content");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_from_file",
      "Rule identifier should match",
    );
  });

  it("should allow setting options when loading rules from a file", () => {
    const rule = `
      rule test_from_file_with_options {
        strings:
          $a = "test content"
        condition:
          $a and test_var == "test"
      }
    `;

    const ruleFile = createTempFile(rule, ".yar");
    const options = {
      defineVariables: {
        test_var: "test",
      },
    };
    const scanner = yarax.fromFile(ruleFile, options);
    const buffer = Buffer.from("This is test content");
    const matches = scanner.scan(buffer);
    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_from_file_with_options",
      "Rule identifier should match",
    );
  });

  it("should compile to WASM", () => {
    const rule = `
      rule test_wasm {
        strings:
          $a = "wasm test"
        condition:
          $a
      }
    `;

    const wasmFile = join(__tempDir, `test-${Date.now()}.wasm`);

    const scanner = yarax.compile(rule);
    scanner.emitWasmFile(wasmFile);

    strictEqual(existsSync(wasmFile), true, "WASM file should exist");
    ok(statSync(wasmFile).size > 0, "WASM file should not be empty");
  });

  it("should perform static WASM compilation", () => {
    const rule = `
      rule test_static_wasm {
        strings:
          $a = "static wasm"
        condition:
          $a
      }
    `;

    const wasmFile = join(__tempDir, `test-static-${Date.now()}.wasm`);

    yarax.compileToWasm(rule, wasmFile);

    strictEqual(existsSync(wasmFile), true, "WASM file should exist");
    ok(statSync(wasmFile).size > 0, "WASM file should not be empty");
  });

  it("should perform static WASM compilation from a file", () => {
    const rule = `
      rule test_static_wasm_file {
        strings:
          $a = "static wasm file"
        condition:
          $a
      }
    `;

    const ruleFile = createTempFile(rule, ".yar");
    const wasmFile = join(__tempDir, `test-static-file-${Date.now()}.wasm`);

    yarax.compileFileToWasm(ruleFile, wasmFile);

    strictEqual(existsSync(wasmFile), true, "WASM file should exist");
    ok(statSync(wasmFile).size > 0, "WASM file should not be empty");
  });

  it("should perform async scanning", async () => {
    const rule = `
      rule test_async {
        strings:
          $a = "async test"
        condition:
          $a
      }
    `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is an async test");

    try {
      const matches = await scanner.scanAsync(buffer);
      strictEqual(matches.length, 1, "Should have one matching rule");
      strictEqual(
        matches[0].ruleIdentifier,
        "test_async",
        "Rule identifier should match",
      );
    } catch (error) {
      fail(`Async scanning failed: ${error.message}`);
    }
  });

  it("should perform async file scanning", async () => {
    const rule = `
      rule test_async_file {
        strings:
          $a = "async file"
        condition:
          $a
      }
    `;

    const fileContent = "This is async file content";
    const tempFile = createTempFile(fileContent);

    try {
      const scanner = yarax.compile(rule);
      const matches = await scanner.scanFileAsync(tempFile);

      strictEqual(matches.length, 1, "Should have one matching rule");
      strictEqual(
        matches[0].ruleIdentifier,
        "test_async_file",
        "Rule identifier should match",
      );
    } catch (error) {
      fail(`Async file scanning failed: ${error.message}`);
    }
  });

  it("should perform async WASM compilation", async () => {
    const rule = `
      rule test_async_wasm {
        strings:
          $a = "async wasm"
        condition:
          $a
      }
    `;

    const wasmFile = join(__tempDir, `test-async-${Date.now()}.wasm`);

    try {
      const scanner = yarax.compile(rule);
      await scanner.emitWasmFileAsync(wasmFile);

      strictEqual(existsSync(wasmFile), true, "WASM file should exist");
      ok(statSync(wasmFile).size > 0, "WASM file should not be empty");
    } catch (error) {
      fail(`Async WASM compilation failed: ${error.message}`);
    }
  });

  it("should handle incremental rule building", () => {
    const scanner = yarax.create();

    scanner.addRuleSource(`
      rule test_incremental_1 {
        strings:
          $a = "first rule"
        condition:
          $a
      }
    `);

    scanner.addRuleSource(`
      rule test_incremental_2 {
        strings:
          $b = "second rule"
        condition:
          $b
      }
    `);

    const buffer1 = Buffer.from("This contains first rule text");
    const matches1 = scanner.scan(buffer1);

    strictEqual(matches1.length, 1, "Should have one matching rule");
    strictEqual(
      matches1[0].ruleIdentifier,
      "test_incremental_1",
      "First rule identifier should match",
    );

    const buffer2 = Buffer.from("This contains second rule text");
    const matches2 = scanner.scan(buffer2);

    strictEqual(matches2.length, 1, "Should have one matching rule");
    strictEqual(
      matches2[0].ruleIdentifier,
      "test_incremental_2",
      "Second rule identifier should match",
    );
  });

  it("should handle adding a rule from a file", () => {
    const rule = `
      rule test_add_file {
        strings:
          $a = "added from file"
        condition:
          $a
      }
    `;

    const ruleFile = createTempFile(rule, ".yar");

    const scanner = yarax.compile(`
      rule test_initial {
        strings:
          $a = "initial rule"
        condition:
          $a
      }
    `);

    scanner.addRuleFile(ruleFile);

    const buffer1 = Buffer.from("This contains initial rule");
    const matches1 = scanner.scan(buffer1);

    strictEqual(matches1.length, 1, "Should have one matching rule");
    strictEqual(
      matches1[0].ruleIdentifier,
      "test_initial",
      "Initial rule identifier should match",
    );

    const buffer2 = Buffer.from("This contains added from file");
    const matches2 = scanner.scan(buffer2);

    strictEqual(matches2.length, 1, "Should have one matching rule");
    strictEqual(
      matches2[0].ruleIdentifier,
      "test_add_file",
      "Added rule identifier should match",
    );
  });

  it("should handle YARA-X variables", () => {
    const rule = `
      rule test_yara_x_variable {
        condition:
          test_var > 50
      }
    `;

    const options = {
      defineVariables: {
        test_var: "100",
      },
    };

    const scanner = yarax.compile(rule, options);

    const buffer = Buffer.from("");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_yara_x_variable",
      "Rule identifier should match",
    );
  });

  it("should handle setting variables at scan time", () => {
    const rule = `
      rule test_scan_time_var {
        condition:
          scan_var > 50
      }
    `;

    const options = {
      defineVariables: {
        scan_var: "10",
      },
    };

    const scanner = yarax.compile(rule, options);

    const buffer = Buffer.from("");
    const matches = scanner.scan(buffer, { scan_var: "100" });

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_scan_time_var",
      "Rule identifier should match",
    );
  });

  it("should capture and expose compiler warnings", () => {
    const rule = `rule test_1 { condition: true }`;

    const scanner = yarax.compile(rule);

    const warnings = scanner.getWarnings();

    ok(Array.isArray(warnings), "Warnings should be an array");

    ok(warnings.length > 0, "Should have at least one warning");
    strictEqual(
      warnings[0].code,
      "invariant_expr",
      "Warning code should match",
    );
    strictEqual(
      warnings[0].message,
      "warning[invariant_expr]: invariant boolean expression\n" +
        " --> line:1:26\n" +
        "  |\n" +
        "1 | rule test_1 { condition: true }\n" +
        "  |                          ---- this expression is always true\n" +
        "  |\n" +
        "  = note: rule `test_1` is always `true`",
      "Warning message should match",
    );
  });

  describe("ignore invalid rules", () => {
    const validRule = `rule test_good {
      strings:
        $a = "hello world"
      condition:
        $a
    }`;
    const brokenRule = `rule test_bad {
      condition:
        undefined_variable_xyz
    }`;

    it("should throw when invalid rules are not ignored", () => {
      throws(
        () => yarax.compile(validRule + "\n" + brokenRule),
        /undefined_variable_xyz/,
        "Compiling an invalid rule should throw without ignoreInvalidRules",
      );
    });

    it("should skip invalid rules when ignoreInvalidRules is set", () => {
      const scanner = yarax.compile(validRule + "\n" + brokenRule, {
        ignoreInvalidRules: true,
      });

      const ignored = scanner.getIgnoredRules();
      strictEqual(ignored.length, 1, "Should have one ignored rule");
      strictEqual(ignored[0].name, "test_bad", "Rule name should match");
      strictEqual(
        ignored[0].reason,
        "compile_error",
        "Reason should be compile_error",
      );
      ok(
        ignored[0].detail.includes("undefined_variable_xyz"),
        "Ignored rule detail should mention the error",
      );

      const buffer = Buffer.from("This is a test with hello world in it");
      const matches = scanner.scan(buffer);
      strictEqual(matches.length, 1, "Valid rule should still match");
      strictEqual(
        matches[0].ruleIdentifier,
        "test_good",
        "Rule identifier should match",
      );
    });

    it("should report empty ignored rules when nothing is skipped", () => {
      const scanner = yarax.compile(validRule, {
        ignoreInvalidRules: true,
      });

      strictEqual(
        scanner.getIgnoredRules().length,
        0,
        "No rules should be ignored",
      );
    });

    it("should keep the tolerant behavior and report across incremental compilation", () => {
      const scanner = yarax.compile(brokenRule, {
        ignoreInvalidRules: true,
      });

      deepStrictEqual(
        scanner.getIgnoredRules().map((r) => r.name),
        ["test_bad"],
        "Broken rule should be reported after creation",
      );

      scanner.addRuleSource(
        'rule test_added {\n  strings:\n    $a = "found me"\n  condition:\n    $a\n}',
      );

      deepStrictEqual(
        scanner.getIgnoredRules().map((r) => r.name),
        ["test_bad"],
        "Report should be refreshed after addRuleSource",
      );
      strictEqual(
        scanner.scan(Buffer.from("found me"))[0].ruleIdentifier,
        "test_added",
        "New rule should match",
      );
    });

    it("should report rules that depend on an ignored module", () => {
      const rule = `rule test_pe {
        condition:
          pe.is_pe
      }`;

      const scanner = yarax.compile(rule, { ignoreModules: ["pe"] });

      const warnings = scanner.getWarnings();
      ok(
        warnings.some((w) => w.code === "unsupported_module"),
        "Should have an unsupported_module warning",
      );
      deepStrictEqual(
        scanner.getIgnoredRules(),
        [{ name: "test_pe", reason: "ignored_module", detail: "pe" }],
        "Ignored-module rules should be reported without ignoreInvalidRules",
      );
    });

    it("should report rules that depend on another ignored rule", () => {
      const rule = `rule test_pe {
        condition:
          pe.is_pe
      }

      rule test_dep {
        condition:
          test_pe
      }`;

      const scanner = yarax.compile(rule, { ignoreModules: ["pe"] });

      deepStrictEqual(
        scanner.getIgnoredRules(),
        [
          { name: "test_pe", reason: "ignored_module", detail: "pe" },
          { name: "test_dep", reason: "ignored_rule", detail: "test_pe" },
        ],
        "Rules depending on an ignored rule should be reported",
      );
    });

    it("should report source-level errors via getCompilationErrors", () => {
      const scanner = yarax.compile(validRule + "\n" + brokenRule, {
        ignoreInvalidRules: true,
      });

      const errors = scanner.getCompilationErrors();
      strictEqual(errors.length, 1, "Should have one compilation error");
      ok(
        errors[0].message.includes("undefined_variable_xyz"),
        "Compilation error message should mention the broken rule",
      );
      ok(
        scanner.getIgnoredRules().some((r) => r.name === "test_bad"),
        "Per-rule failures stay attributed to the ignored rule report",
      );
    });

    it("should report syntax errors via getCompilationErrors instead of silently dropping them", () => {
      const scanner = yarax.compile('rule bad { condition: true', {
        ignoreInvalidRules: true,
      });

      strictEqual(
        scanner.getIgnoredRules().length,
        0,
        "A syntax error is not a per-rule failure",
      );
      const errors = scanner.getCompilationErrors();
      ok(
        errors.length > 0,
        "Syntax errors should be surfaced, not silently dropped",
      );
      ok(
        scanner.scan(Buffer.from("x")).length === 0,
        "Scanner should have no compiled rules",
      );
    });

    it("should return an empty getCompilationErrors when nothing was dropped", () => {
      const scanner = yarax.compile(validRule, {
        ignoreInvalidRules: true,
      });
      deepStrictEqual(
        scanner.getCompilationErrors(),
        [],
        "No errors should be reported for a clean compile",
      );
    });

    it("should surface banned-module import errors via getCompilationErrors", () => {
      const scanner = yarax.compile('import "pe"\nrule test_pe { condition: pe.is_pe }', {
        ignoreInvalidRules: true,
        bannedModules: [{ name: "pe", errorTitle: "no pe", errorMessage: "pe is banned" }],
      });

      const errors = scanner.getCompilationErrors();
      ok(
        errors.some((e) => e.message.includes("no pe")),
        "Banned-module errors should be surfaced",
      );
    });

    it("should throw on source-level errors in tolerant WASM compilation", () => {
      const wasmFile = join(__tempDir, `test-ignored-throws-${Date.now()}.wasm`);
      throws(
        () =>
          yarax.compileToWasm(
            "rule bad { condition: true",
            wasmFile,
            { ignoreInvalidRules: true },
          ),
        /Compilation error/,
        "Tolerant WASM compilation should fail on source-level errors",
      );
      strictEqual(
        existsSync(wasmFile),
        false,
        "No WASM file should be written on failure",
      );
    });

    it("should keep per-rule failures tolerant in WASM compilation", () => {
      const wasmFile = join(__tempDir, `test-ignored-valid-${Date.now()}.wasm`);
      yarax.compileToWasm(validRule + "\n" + brokenRule, wasmFile, {
        ignoreInvalidRules: true,
      });
      strictEqual(
        existsSync(wasmFile),
        true,
        "WASM should still be emitted with the valid rules",
      );
      ok(
        statSync(wasmFile).size > 0,
        "WASM file should not be empty",
      );
    });
  });

  describe("incremental compilation state", () => {
    it("should allow redefining a variable via defineVariable", () => {
      const scanner = yarax.compile("rule r { condition: x == 5 }", {
        defineVariables: { x: 5 },
      });
      strictEqual(scanner.scan(Buffer.from("x")).length, 1, "Initial value should match");

      scanner.defineVariable("x", "6");
      strictEqual(
        scanner.scan(Buffer.from("x")).length,
        0,
        "Redefined value should no longer match x == 5",
      );
    });

    it("should support create + defineVariable + addRuleSource", async () => {
      const scanner = yarax.create();
      scanner.defineVariable("x", "5");
      scanner.addRuleSource("rule r { condition: x == 5 }");

      strictEqual(scanner.scan(Buffer.from("x")).length, 1, "Sync scan should match");
      const asyncMatches = await scanner.scanAsync(Buffer.from("x"));
      strictEqual(asyncMatches.length, 1, "Async scan should match");
    });

    it("should keep global variables when adding rule sources", () => {
      const scanner = yarax.compile("rule r { condition: x == 5 }", {
        defineVariables: { x: 5 },
      });
      scanner.addRuleSource("rule ok { condition: true }");

      const matches = scanner.scan(Buffer.from("x"));
      strictEqual(matches.length, 2, "Both rules should be present");
      ok(
        matches.some((m) => m.ruleIdentifier === "ok"),
        "New rule should match",
      );
      ok(
        matches.some((m) => m.ruleIdentifier === "r"),
        "Existing globals-based rule should still match",
      );
    });

    it("should preserve compiler options across incremental compilation", () => {
      const scanner = yarax.compile("rule r { strings: $a = /xyz{/ condition: $a }", {
        relaxedReSyntax: true,
      });
      scanner.addRuleSource("rule ok { condition: true }");

      strictEqual(
        scanner.scan(Buffer.from("xyz{"))[0].ruleIdentifier,
        "r",
        "Relaxed-regex rule should survive the recompile",
      );
      ok(
        scanner.scan(Buffer.from("zzz")).some((m) => m.ruleIdentifier === "ok"),
        "Added rule should match too",
      );
    });

    it("should emit WASM reproducing scanner options and toleration", async () => {
      const wasmFile = join(__tempDir, `test-state-${Date.now()}.wasm`);
      const asyncWasmFile = join(__tempDir, `test-state-async-${Date.now()}.wasm`);

      const relaxed = yarax.compile("rule r { strings: $a = /xyz{/ condition: $a }", {
        relaxedReSyntax: true,
      });
      relaxed.emitWasmFile(wasmFile);
      ok(statSync(wasmFile).size > 0, "Relaxed scanner should emit WASM");

      const tolerant = yarax.compile(
        'rule good { strings: $a = "hi" condition: $a }\nrule bad { condition: nope }',
        { ignoreInvalidRules: true },
      );
      await tolerant.emitWasmFileAsync(asyncWasmFile);
      ok(
        statSync(asyncWasmFile).size > 0,
        "Tolerant scanner should emit WASM with the surviving rules",
      );
    });

    it("should keep sources out of previously-set namespaces", () => {
      const scanner = yarax.compile("rule in_x { condition: true }", {
        namespace: "x",
      });
      scanner.addRuleSource("rule in_default { condition: true }");

      const namespaces = scanner.scan(Buffer.from("x")).map((m) => m.namespace);
      deepStrictEqual(
        [...new Set(namespaces)].sort(),
        ["default", "x"],
        "Unnamed sources should land in the default namespace",
      );
    });

    it("should refresh warnings and ignored-rules after incremental compilation", () => {
      const scanner = yarax.compile("rule ok { condition: true }", {
        ignoreModules: ["pe"],
      });
      scanner.addRuleSource("rule p { condition: pe.is_pe }");

      ok(
        scanner.getWarnings().some((w) => w.code === "unsupported_module"),
        "Warnings should reflect the current rules",
      );
      deepStrictEqual(
        scanner.getIgnoredRules().map((i) => i.name),
        ["p"],
        "Ignored-rules report should reflect the current rules",
      );
    });
  });

  it("should handle relaxed regular expression syntax", () => {
    const rule = `
      rule test_relaxed_re {
        strings:
          $a = /hello[[:space:]]world/
        condition:
          $a
      }
    `;

    const options = {
      relaxedReSyntax: true,
    };

    const scanner = yarax.compile(rule, options);
    const buffer = Buffer.from("This is a test with hello world in it");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_relaxed_re",
      "Rule identifier should match",
    );
  });

  it("should handle condition optimization", () => {
    const rule = `
      rule test_condition_optimization {
        strings:
          $a = "hello"
          $b = "world"
        condition:
          $a and $b or $a and $b
      }
    `;

    const options = {
      conditionOptimization: true,
    };

    const scanner = yarax.compile(rule, options);
    const buffer = Buffer.from("This is a test with hello and world in it");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_condition_optimization",
      "Rule identifier should match",
    );
  });

  it("should handle unsupported modules gracefully", () => {
    const rule = `
    import "non_existent_module"
    rule test_unsupported_module {
      condition:
        true
    }
  `;

    const options = {
      ignoreModules: ["non_existent_module"],
    };

    try {
      const scanner = yarax.compile(rule, options);
      const buffer = Buffer.from("This is a test");
      const matches = scanner.scan(buffer);

      strictEqual(matches.length, 1, "Should have one matching rule");
      strictEqual(
        matches[0].ruleIdentifier,
        "test_unsupported_module",
        "Rule identifier should match",
      );
    } catch (error) {
      fail(`Scanning with unsupported module failed: ${error.message}`);
    }
  });

  it("should handle banned modules", () => {
    const rule = `
      import "pe"
      rule test_banned_module {
        condition:
          pe.is_pe
      }
    `;

    const options = {
      bannedModules: [
        {
          name: "pe",
          errorTitle: "PE Module Banned",
          errorMessage: "The PE module is banned for testing",
        },
      ],
    };

    try {
      yarax.compile(rule, options);
      fail("Should have thrown an error for banned module");
    } catch (error) {
      ok(
        error.message.includes("PE Module Banned") ||
          error.message.includes("banned"),
        "Error should mention banned module",
      );
    }
  });

  it("should handle enabling features", () => {
    const rule = `
      rule test_feature {
        strings:
          $a = "feature test"
        condition:
          $a
      }
    `;

    const options = {
      features: ["some_feature"],
    };

    const scanner = yarax.compile(rule, options);
    const buffer = Buffer.from("This is a feature test");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
  });

  it("should handle error on slow pattern", () => {
    const rule = `rule test { strings: $a = /a.*/ condition: $a }`;

    const options = {
      errorOnSlowPattern: true,
    };

    try {
      yarax.compile(rule, options);

      const buffer = Buffer.from("This is a test with a b c d e in it");
      const scanner = yarax.compile(rule);
      const matches = scanner.scan(buffer);

      strictEqual(matches.length, 1, "Should have one matching rule");
    } catch (error) {
      ok(
        error.message.includes("slow pattern"),
        "Error should mention slow pattern",
      );
    }
  });

  it("should handle error on slow loop", () => {
    const rule = `rule test { condition: for all x in (0..filesize): (x == 0) }`;

    const options = {
      errorOnSlowLoop: true,
    };

    try {
      yarax.compile(rule, options);
    } catch (error) {
      ok(error.message.includes("slow loop"), "Error should mention slow loop");
    }
  });

  it("should handle multiple compiler options together", () => {
    const rule = `
      rule test_multiple_options {
        strings:
          $a = "multiple options"
        condition:
          $a and test_var > 10
      }
    `;

    const options = {
      defineVariables: {
        test_var: "20",
      },
      relaxedReSyntax: true,
      conditionOptimization: true,
    };

    const scanner = yarax.compile(rule, options);
    const buffer = Buffer.from("This is a test with multiple options");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_multiple_options",
      "Rule identifier should match",
    );
  });

  it("should handle variables of different types", () => {
    const rule = `
      rule test_variable_types {
        condition:
          string_var contains "test" and
          int_var > 10 and
          bool_var
      }
    `;

    const options = {
      defineVariables: {
        string_var: "this is a test string",
        int_var: "20",
        bool_var: "true",
      },
    };

    const scanner = yarax.compile(rule, options);
    const buffer = Buffer.from("");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
  });

  it("should accept typed JavaScript variables", () => {
    const rule = `
      rule test_typed_variables {
        condition:
          string_var contains "test" and
          int_var > 10 and
          float_var > 1.5 and
          bool_var
      }
    `;

    const scanner = yarax.compile(rule, {
      defineVariables: {
        string_var: "this is a test string",
        int_var: 20,
        float_var: 2.5,
        bool_var: true,
      },
    });

    const matches = scanner.scan(Buffer.from(""), {
      int_var: 30,
      float_var: 3.5,
      bool_var: true,
    });

    strictEqual(matches.length, 1, "Should match with typed JS variables");
  });

  it("should validate YARA rules without executing them", () => {
    const validRule = `
    rule valid_rule {
      strings:
        $a = "valid"
      condition:
        $a
    }
  `;

    const invalidRule = `
    rule invalid_rule {
      strings:
        $a = "invalid
      condition:
        $a
    }
  `;

    const validResult = yarax.validate(validRule);
    strictEqual(
      Array.isArray(validResult.errors),
      true,
      "Errors should be an array",
    );
    strictEqual(
      validResult.errors.length,
      0,
      "Valid rule should have no errors",
    );

    const invalidResult = yarax.validate(invalidRule);
    strictEqual(
      Array.isArray(invalidResult.errors),
      true,
      "Errors should be an array",
    );
    strictEqual(
      invalidResult.errors.length > 0,
      true,
      "Invalid rule should have errors",
    );
    ok(invalidResult.errors[0].code, "Error should have a code");
    ok(invalidResult.errors[0].message, "Error should have a message");
  });

  it("should handle defining variables for rules", () => {
    const options = {
      defineVariables: {
        test_var: "100",
      },
    };

    const scanner = yarax.compile(
      `
    rule test_with_variable {
      condition:
        test_var > 50
    }
  `,
      options,
    );

    const buffer = Buffer.from("");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_with_variable",
      "Rule should match",
    );

    const matches2 = scanner.scan(buffer, { test_var: "40" });
    strictEqual(
      matches2.length,
      0,
      "Rule should not match with updated variable value",
    );
  });

  it("should handle rule metadata", () => {
    const rule = `
    rule test_metadata {
      meta:
        author = "Test Author"
        description = "Test Description"
        severity = 5
        is_dangerous = true
      strings:
        $a = "metadata test"
      condition:
        $a
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is a metadata test");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].meta.author,
      "Test Author",
      "Author metadata should match",
    );
    strictEqual(
      matches[0].meta.description,
      "Test Description",
      "Description metadata should match",
    );
    strictEqual(matches[0].meta.severity, 5, "Severity metadata should match");

    strictEqual(
      matches[0].meta.is_dangerous,
      true,
      "Boolean metadata should be preserved",
    );
  });

  it("should handle rule tags", () => {
    const rule = `
    rule test_tags : tag1 tag2 tag3 {
      strings:
        $a = "tag test"
      condition:
        $a
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is a tag test");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(matches[0].tags.length, 3, "Should have three tags");
    strictEqual(matches[0].tags[0], "tag1", "First tag should match");
    strictEqual(matches[0].tags[1], "tag2", "Second tag should match");
    strictEqual(matches[0].tags[2], "tag3", "Third tag should match");
  });

  it("should handle rule namespaces", () => {
    const rule = `
    rule test_rule {
      strings:
        $a = "test string"
      condition:
        $a
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is a test string");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_rule",
      "Rule identifier should match",
    );

    ok("namespace" in matches[0], "Match should have a namespace property");

    const namespace = matches[0].namespace;
    ok(
      namespace === "default" || namespace === "",
      `Namespace should be 'default' or empty string, got '${namespace}'`,
    );
  });

  it("should handle hex pattern matching", () => {
    const rule = `
    rule test_hex_pattern {
      strings:
        $hex1 = { 48 65 6C 6C 6F }
        $hex2 = { 57 6F 72 6C 64 }
      condition:
        $hex1 and $hex2
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("Hello World");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_hex_pattern",
      "Rule identifier should match",
    );
    strictEqual(matches[0].matches.length, 2, "Should have two matches");
  });

  it("should handle regex pattern matching", () => {
    const rule = `
    rule test_regex_pattern {
      strings:
        $re1 = /[0-9]{3}-[0-9]{3}-[0-9]{4}/
      condition:
        $re1
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from(
      "Contact us at 555-123-4567 for more information",
    );
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_regex_pattern",
      "Rule identifier should match",
    );
    strictEqual(matches[0].matches.length, 1, "Should have one match");
    strictEqual(
      matches[0].matches[0].data,
      "555-123-4567",
      "Matched data should be correct",
    );
  });

  it("should handle regex escape sequences and character classes", () => {
    const rule = `
    rule test_regex_escape {
      strings:
        // NOTE: double escaping backslashes (could also use String.raw)
        $re = /Speak \\"\\S+\\"\\sand\\Wenter/
      condition:
        $re
    }
  `;

    const valid = yarax.validate(rule);
    strictEqual(valid.errors.length, 0, "Rule should be valid");

    const scanner = yarax.compile(rule);

    const testStrings = [
      'Speak "friend" and enter',
      'Speak "foe" and enter',
      'Speak "stranger" and enter',
    ];

    testStrings.forEach((testString) => {
      const buffer = Buffer.from(testString);
      const matches = scanner.scan(buffer);
      strictEqual(matches.length, 1, "Should have one matching rule");
      strictEqual(
        matches[0].ruleIdentifier,
        "test_regex_escape",
        "Rule identifier should match",
      );

      strictEqual(matches[0].matches.length, 1, "Should have one match");
      console.log("match:", matches[0].matches[0]);
      strictEqual(
        matches[0].matches[0].data,
        testString,
        "Matched data should be correct",
      );
    });
  });

  it("should handle wildcard hex patterns", () => {
    const rule = `
    rule test_wildcard_hex {
      strings:
        $hex = { 54 65 ?? 74 }
      condition:
        $hex
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("Test Text");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_wildcard_hex",
      "Rule identifier should match",
    );
    strictEqual(matches[0].matches.length, 2, "Should have two matches");
  });

  it("should handle case insensitive strings", () => {
    const rule = `
    rule test_case_insensitive {
      strings:
        $text = "hello" nocase
      condition:
        $text
    }
  `;

    const scanner = yarax.compile(rule);
    const buffer = Buffer.from("This is HELLO and hello");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(matches[0].matches.length, 2, "Should have two matches");
  });

  it("should handle wide character strings", () => {
    const rule = `
    rule test_wide_strings {
      strings:
        $wide = "wide" wide
      condition:
        $wide
    }
  `;

    const wideBuffer = Buffer.from("w\0i\0d\0e\0", "binary");

    const scanner = yarax.compile(rule);
    const matches = scanner.scan(wideBuffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(matches[0].matches.length, 1, "Should have one match");
  });

  it("should handle complex conditions with logical operators", () => {
    const rule = `
    rule test_complex_condition {
      strings:
        $a = "first"
        $b = "second"
        $c = "third"
      condition:
        ($a and $b) or ($b and $c) or ($a and $c)
    }
  `;

    const scanner = yarax.compile(rule);

    const buffer = Buffer.from("This string has first and third keywords");
    const matches = scanner.scan(buffer);

    strictEqual(matches.length, 1, "Should have one matching rule");
    strictEqual(
      matches[0].ruleIdentifier,
      "test_complex_condition",
      "Rule identifier should match",
    );
  });

  it("should handle count conditions", () => {
    const rule = `
    rule test_count_condition {
      strings:
        $a = "test"
      condition:
        #a >= 3
    }
  `;

    const scanner = yarax.compile(rule);

    const buffer1 = Buffer.from("This is a test with another test");
    const matches1 = scanner.scan(buffer1);
    strictEqual(matches1.length, 0, "Should have no matching rules");

    const buffer2 = Buffer.from("This test is a test with another test");
    const matches2 = scanner.scan(buffer2);
    strictEqual(matches2.length, 1, "Should have one matching rule");
  });

  it("should handle at and in conditions", () => {
    const rule = `
    rule test_at_condition {
      strings:
        $a = "specific"
      condition:
        $a at 10
    }

    rule test_in_condition {
      strings:
        $b = "range"
      condition:
        $b in (5..15)
    }
  `;

    const scanner = yarax.compile(rule);

    const buffer1 = Buffer.from("0123456789specific");
    const matches1 = scanner.scan(buffer1);
    strictEqual(matches1.length, 1, "Should have one matching rule");
    strictEqual(
      matches1[0].ruleIdentifier,
      "test_at_condition",
      "Rule identifier should match",
    );

    const buffer2 = Buffer.from("01234range");
    const matches2 = scanner.scan(buffer2);
    strictEqual(matches2.length, 1, "Should have one matching rule");
    strictEqual(
      matches2[0].ruleIdentifier,
      "test_in_condition",
      "Rule identifier should match",
    );
  });

  it("should handle filesize condition", () => {
    const rule = `
    rule test_filesize {
      condition:
        filesize > 10 and filesize < 20
    }
  `;

    const scanner = yarax.compile(rule);

    const buffer1 = Buffer.from("123456789012345");
    const matches1 = scanner.scan(buffer1);
    strictEqual(matches1.length, 1, "Should have one matching rule");

    const buffer2 = Buffer.from("12345");
    const matches2 = scanner.scan(buffer2);
    strictEqual(matches2.length, 0, "Should have no matching rules");

    const buffer3 = Buffer.from("12345678901234567890");
    const matches3 = scanner.scan(buffer3);
    strictEqual(matches3.length, 0, "Should have no matching rules");
  });

  it("should handle error cases gracefully", () => {
    try {
      yarax.fromFile("/path/to/nonexistent/file.yar");
      fail("Should have thrown an error for nonexistent file");
    } catch (error) {
      ok(
        error.message.includes("reading file"),
        "Error should mention file reading",
      );
    }

    try {
      yarax.compile("this is not a valid rule");
      fail("Should have thrown an error for invalid rule syntax");
    } catch (error) {
      ok(
        error.message.includes("Compilation error"),
        "Error should mention compilation",
      );
    }

    const scanner = yarax.compile("rule test { condition: true }");
    try {
      scanner.scanFile("/path/to/nonexistent/file.txt");
      fail("Should have thrown an error for nonexistent file");
    } catch (error) {
      ok(
        error.message.includes("reading file"),
        "Error should mention file reading",
      );
    }
  });

  describe("Variable Definition Functionality", () => {
    it("should test defineVariable method exists", () => {
      const rule = `
        rule test_define_variable {
          condition:
            true
        }
      `;

      const scanner = yarax.compile(rule);

      // Test that the method exists and can be called
      ok(
        typeof scanner.defineVariable === "function",
        "defineVariable method should exist",
      );

      // Test that it doesn't throw when called (even if it doesn't work as expected)
      try {
        scanner.defineVariable("test_var", "test_value");
        ok(true, "defineVariable should not throw");
      } catch (error) {
        // This is expected since the variable isn't declared in the rule
        ok(
          error.message.includes("unknown identifier"),
          "Should get unknown identifier error",
        );
      }
    });
  });

  describe("Error and Warning Handling", () => {
    const errorTestCases = [
      {
        name: "Syntax Error",
        rule: "rule test { condition: invalid syntax }",
        errorCode: "E001",
      },
      {
        name: "Unknown Identifier",
        rule: "rule test { condition: unknown_identifier }",
        errorCode: "E009",
      },
      {
        name: "Wrong Types",
        rule: 'rule test { condition: 1 + "string" }',
        errorCode: "E002",
      },
      {
        name: "Duplicate Rule",
        rule: `rule test1 { condition: true } rule test1 { condition: false}`,
        errorCode: "E012",
      },
      {
        name: "Invalid Regexp",
        rule: "rule test { strings: $a = /[/ condition: $a }",
        errorCode: "E014",
      },
      {
        name: "Number Out Of Range",
        rule: 'rule test {  strings:    $a = "foo"  condition:    !a[-1]}',
        errorCode: "E007",
      },
      {
        name: "Redundant Case Modifier",
        rule: 'rule test { strings: $a = "test" nocase nocase condition: $a }',
        errorCode: "E020",
      },
    ];

    errorTestCases.forEach(({ name, rule, errorCode }) => {
      it(`should handle compile error: ${name}`, () => {
        try {
          yarax.compile(rule);
          fail("Should have thrown a compile error");
        } catch (error) {
          ok(
            error.message.includes("Compilation error"),
            "Error should be compilation error",
          );
          ok(
            error.message.includes(`(${errorCode}):`),
            `Error should have code ${errorCode}`,
          );
        }
      });

      it(`should handle validate error: ${name}`, () => {
        const result = yarax.validate(rule);
        strictEqual(result.errors.length, 1, "Should have one error");
        strictEqual(
          result.errors[0].code,
          errorCode,
          `Error code should be ${errorCode}`,
        );
      });
    });

    const warningTestCases = [
      {
        name: "Invariant Boolean Expression",
        rule: "rule test { condition: true }",
        warningCode: "invariant_expr",
      },
      {
        name: "Potentially Slow Loop",
        rule: `import "math"
rule test_1 {
	condition:
		for any i in (0..filesize) : ( int32(i) == 0 )
}`,
        warningCode: "potentially_slow_loop",
      },
      {
        name: "Non Boolean As Boolean",
        rule: "rule test { condition: 1 }",
        warningCode: "non_bool_expr",
      },
      {
        name: "Slow Pattern (single-byte)",
        rule: `rule test_slow_pattern {
	strings:
		$a = "a"
	condition:
		$a
}`,
        warningCode: "slow_pattern",
      },
      {
        name: "Duplicate Pattern Value",
        rule: `rule test_duplicate_pattern {
	strings:
		$a = "hello"
		$b = "hello"
	condition:
		any of them
}`,
        warningCode: "duplicate_pattern_value",
      },
    ];

    warningTestCases.forEach(({ name, rule, warningCode }) => {
      it(`should capture warning: ${name}`, () => {
        const scanner = yarax.compile(rule, { errorOnSlowLoop: false });
        const warnings = scanner.getWarnings();
        ok(warnings.length > 0, "Should have warnings");
        ok(
          warnings.some((warning) => warning.code === warningCode),
          `Should have warning code ${warningCode}`,
        );
      });

      it(`should validate and capture warning: ${name}`, () => {
        const result = yarax.validate(rule, { errorOnSlowLoop: false });
        ok(result.warnings.length > 0, "Should have warnings");
        ok(
          result.warnings.some((warning) => warning.code === warningCode),
          `Should have warning code ${warningCode}`,
        );
      });
    });

    // These options map to the underlying YARA warning-control API:
    //   Compiler::max_warnings / switch_all_warnings / switch_warning
    describe("Warning controls", () => {
      // Two distinct single-byte patterns => exactly two `slow_pattern` warnings.
      const twoSlowPatternRule = `rule test_slow_patterns {
	strings:
		$a = "a"
		$b = "b"
	condition:
		any of them
}`;

      it("should cap the number of reported warnings (maxWarnings)", () => {
        // Baseline: this rule emits exactly 2 slow_pattern warnings.
        const baseline = yarax.compile(twoSlowPatternRule).getWarnings();
        strictEqual(
          baseline.length,
          2,
          "baseline should emit 2 slow_pattern warnings",
        );

        const scanner = yarax.compile(twoSlowPatternRule, { maxWarnings: 1 });
        const warnings = scanner.getWarnings();
        ok(
          warnings.length === 1,
          `maxWarnings:1 should yield exactly 1 warning, got ${warnings.length}`,
        );
        strictEqual(
          warnings[0].code,
          "slow_pattern",
          "Capped warning should be the first slow_pattern",
        );
      });

      it("should disable a specific warning code (disableWarnings)", () => {
        const scanner = yarax.compile(twoSlowPatternRule, {
          disableWarnings: ["slow_pattern"],
        });
        const warnings = scanner.getWarnings();
        ok(
          warnings.length === 0,
          "slow_pattern should be suppressed by disableWarnings",
        );
      });

      it("should disable all warnings (enableAllWarnings: false)", () => {
        const scanner = yarax.compile(twoSlowPatternRule, {
          enableAllWarnings: false,
        });
        const warnings = scanner.getWarnings();
        strictEqual(
          warnings.length,
          0,
          "enableAllWarnings:false should suppress every warning",
        );
      });

      it("should error on an invalid warning code in disableWarnings", () => {
        throws(
          () => yarax.compile(twoSlowPatternRule, {
            disableWarnings: ["totally_made_up_code"],
          }),
          /is not a valid warning code/,
          "An unknown warning code should surface a N-API error",
        );
      });

      it("should validate with maxWarnings applied", () => {
        const result = yarax.validate(twoSlowPatternRule, { maxWarnings: 1 });
        ok(
          result.warnings.length === 1,
          `validate() maxWarnings:1 should yield exactly 1 warning, got ${result.warnings.length}`,
        );
      });
    });
  });

  describe("New YARA-X v1.5.0-v1.7.1 APIs", () => {
    describe("max_matches_per_pattern", () => {
      it("should limit matches per pattern", () => {
        const rule = `
					rule test_max_matches {
						strings:
							$a = "test"
						condition:
							$a
					}
				`;

        const scanner = yarax.compile(rule);

        // Create data with many occurrences of "test"
        const data = Buffer.from(
          "test test test test test test test test test test",
        );

        // Without limit - should find all matches
        const unlimitedMatches = scanner.scan(data);
        ok(unlimitedMatches.length > 0, "Should find matches");
        const unlimitedCount = unlimitedMatches[0].matches.length;
        ok(
          unlimitedCount >= 10,
          `Should find at least 10 matches, found ${unlimitedCount}`,
        );

        // With limit - should find only limited matches
        const limitedScanner = yarax.compile(rule);
        limitedScanner.setMaxMatchesPerPattern(3);
        const limitedMatches = limitedScanner.scan(data);
        ok(limitedMatches.length > 0, "Should find matches");
        const limitedCount = limitedMatches[0].matches.length;
        strictEqual(
          limitedCount,
          3,
          `Should find exactly 3 matches, found ${limitedCount}`,
        );
      });

      it("should work with file scanning", () => {
        const rule = `
					rule test_file_max_matches {
						strings:
							$a = "data"
						condition:
							$a
					}
				`;

        const testFile = join(__tempDir, "max-matches-test.txt");
        writeFileSync(
          testFile,
          "data data data data data data data data data data",
        );

        const scanner = yarax.compile(rule);
        scanner.setMaxMatchesPerPattern(5);

        const matches = scanner.scanFile(testFile);
        ok(matches.length > 0, "Should find matches");
        const matchCount = matches[0].matches.length;
        strictEqual(
          matchCount,
          5,
          `Should find exactly 5 matches, found ${matchCount}`,
        );
      });

      it("should work with async scanning", async () => {
        const rule = `
					rule test_async_max_matches {
						strings:
							$a = "test"
						condition:
							$a
					}
				`;

        const scanner = yarax.compile(rule);
        scanner.setMaxMatchesPerPattern(4);

        const matches = await scanner.scanAsync(
          Buffer.from("test test test test test test"),
        );

        strictEqual(matches[0].matches.length, 4);
      });
    });

    describe("use_mmap", () => {
      it("should allow disabling memory-mapped files", () => {
        const rule = `
					rule test_mmap {
						strings:
							$a = "hello"
						condition:
							$a
					}
				`;

        const testFile = join(__tempDir, "mmap-test.txt");
        writeFileSync(testFile, "hello world");

        // Test with mmap enabled (default)
        const scannerWithMmap = yarax.compile(rule);
        const matchesWithMmap = scannerWithMmap.scanFile(testFile);
        ok(matchesWithMmap.length > 0, "Should find matches with mmap");

        // Test with mmap disabled
        const scannerWithoutMmap = yarax.compile(rule);
        scannerWithoutMmap.setUseMmap(false);
        const matchesWithoutMmap = scannerWithoutMmap.scanFile(testFile);
        ok(matchesWithoutMmap.length > 0, "Should find matches without mmap");

        // Results should be the same
        strictEqual(
          matchesWithMmap[0].matches.length,
          matchesWithoutMmap[0].matches.length,
          "Match count should be the same with or without mmap",
        );
      });

      it("should apply file options to async file scanning", async () => {
        const rule = `
					rule test_async_file_options {
						strings:
							$a = "data"
						condition:
							$a
					}
				`;

        const testFile = join(__tempDir, "async-file-options-test.txt");
        writeFileSync(testFile, "data data data data data data");

        const scanner = yarax.compile(rule);
        scanner.setMaxMatchesPerPattern(2);
        scanner.setUseMmap(false);

        const matches = await scanner.scanFileAsync(testFile);

        strictEqual(matches[0].matches.length, 2);
      });
    });

    describe("timeout", () => {
      it("should expose a scan timeout setter", () => {
        const scanner = yarax.compile(`rule test_timeout_api { condition: true }`);
        strictEqual(typeof scanner.setTimeout, "function");
        scanner.setTimeout(1000);
      });
    });

    describe("include_directories", () => {
      it("should support include directories", () => {
        const includeDir = join(__tempDir, "includes");
        mkdirSync(includeDir, { recursive: true });

        // Create an included rule file
        const includedRule = `
					rule included_rule {
						strings:
							$included = "included"
						condition:
							$included
					}
				`;
        writeFileSync(join(includeDir, "included.yar"), includedRule);

        // Create main rule that includes the other
        const mainRule = `
					include "included.yar"

					rule main_rule {
						strings:
							$main = "main"
						condition:
							$main
					}
				`;

        // Compile with include directory
        const scanner = yarax.compile(mainRule, {
          includeDirectories: [includeDir],
        });

        // Test that both rules work
        const dataWithIncluded = Buffer.from("included text");
        const matchesIncluded = scanner.scan(dataWithIncluded);
        ok(matchesIncluded.length > 0, "Should match included rule");
        strictEqual(matchesIncluded[0].ruleIdentifier, "included_rule");

        const dataWithMain = Buffer.from("main text");
        const matchesMain = scanner.scan(dataWithMain);
        ok(matchesMain.length > 0, "Should match main rule");
        strictEqual(matchesMain[0].ruleIdentifier, "main_rule");
      });

      it("should support multiple include directories", () => {
        const includeDir1 = join(__tempDir, "includes1");
        const includeDir2 = join(__tempDir, "includes2");
        mkdirSync(includeDir1, { recursive: true });
        mkdirSync(includeDir2, { recursive: true });

        // Create rules in different directories
        writeFileSync(
          join(includeDir1, "rule1.yar"),
          `rule rule1 { strings: $a = "test1" condition: $a }`,
        );
        writeFileSync(
          join(includeDir2, "rule2.yar"),
          `rule rule2 { strings: $b = "test2" condition: $b }`,
        );

        const mainRule = `
					include "rule1.yar"
					include "rule2.yar"

					rule main {
						strings:
							$c = "main"
						condition:
							$c
					}
				`;

        const scanner = yarax.compile(mainRule, {
          includeDirectories: [includeDir1, includeDir2],
        });

        const data1 = Buffer.from("test1");
        const matches1 = scanner.scan(data1);
        ok(matches1.length > 0, "Should match rule from first include dir");

        const data2 = Buffer.from("test2");
        const matches2 = scanner.scan(data2);
        ok(matches2.length > 0, "Should match rule from second include dir");
      });
    });

    describe("Rules Serialization (serialize/deserialize)", () => {
    const serializeRule = `
      rule serialized_rule {
        meta:
          author = "test"
        strings:
          $a = "needle"
          $b = /needle[0-9]+/
        condition:
          any of them
      }
      rule serialized_other {
        strings:
          $c = "haystack"
        condition:
          $c and not serialized_rule
      }
    `;

    it("should serialize compiled rules to a Buffer with YARA-X magic", () => {
      const rules = yarax.compile(serializeRule);
      const blob = rules.serialize();
      ok(Buffer.isBuffer(blob), "serialize() should return a Buffer");
      ok(blob.length > 0, "serialized blob should not be empty");
      ok(
        blob.subarray(0, 6).toString("utf8").startsWith("YARA-X"),
        "blob should start with the YARA-X magic",
      );
    });

    it("should round-trip rules with identical scan results", () => {
      const rules = yarax.compile(serializeRule);
      const restored = yarax.deserialize(rules.serialize());

      const payload = Buffer.from("a needle in a haystack needle42");
      const original = rules.scan(payload);
      const roundTripped = restored.scan(payload);

      strictEqual(roundTripped.length, original.length, "same number of matching rules");
      strictEqual(roundTripped[0].ruleIdentifier, original[0].ruleIdentifier);
      strictEqual(roundTripped[0].matches.length, original[0].matches.length);
      strictEqual(roundTripped[0].matches[0].data, original[0].matches[0].data);
      strictEqual(roundTripped[0].matches[0].offset, original[0].matches[0].offset);
      deepStrictEqual(roundTripped[0].meta, original[0].meta, "metadata should survive");
      strictEqual(restored.scan(Buffer.from("nothing here")).length, 0);
    });

    it("should scan files with deserialized rules", () => {
      const rules = yarax.compile(
        `rule file_rule { strings: $a = "file content" condition: $a }`,
      );
      const restored = yarax.deserialize(rules.serialize());
      const tempFile = createTempFile("This is file content for serialized scanning");
      const matches = restored.scanFile(tempFile);
      strictEqual(matches.length, 1);
      strictEqual(matches[0].ruleIdentifier, "file_rule");
    });

    it("should scan asynchronously with deserialized rules", async () => {
      const rules = yarax.compile(`rule async_rule { strings: $a = "async" condition: $a }`);
      const restored = yarax.deserialize(rules.serialize());
      const matches = await restored.scanAsync(Buffer.from("scan async here"));
      strictEqual(matches.length, 1);
      strictEqual(matches[0].ruleIdentifier, "async_rule");
    });

    it("should preserve compile-time variables in the serialized blob", () => {
      const rule = `rule var_rule { condition: test_var == 100 }`;
      const rules = yarax.compile(rule, { defineVariables: { test_var: "100" } });
      const restored = yarax.deserialize(rules.serialize());
      const matches = restored.scan(Buffer.from("x"));
      strictEqual(matches.length, 1, "variable should survive serialization");
    });

    it("should apply scan-time options to deserialized rules", () => {
      const rules = yarax.compile(`rule m { strings: $a = "a" condition: $a }`);
      const restored = yarax.deserialize(rules.serialize());
      restored.setMaxMatchesPerPattern(1);
      const matches = restored.scan(Buffer.from("aaa"));
      strictEqual(matches.length, 1);
      strictEqual(matches[0].matches.length, 1, "max matches per pattern should apply");
    });

    it("should reject garbage input on deserialize", () => {
      throws(() => yarax.deserialize(Buffer.from("not a yara-x blob")), /deserialize/i);
      throws(() => yarax.deserialize(Buffer.alloc(0)), /deserialize/i);
    });

    it("should reject the emitWasmFile debug artifact on deserialize", () => {
      const rules = yarax.compile(serializeRule);
      const wasmPath = join(__tempDir, `serialized-${Date.now()}.wasm`);
      rules.emitWasmFile(wasmPath);
      const wasmBytes = readFileSync(wasmPath);
      ok(
        wasmBytes.subarray(0, 4).equals(Buffer.from([0, 97, 115, 109])),
        "emitWasmFile should produce a wasm module",
      );
      throws(
        () => yarax.deserialize(wasmBytes),
        /deserialize/i,
        "wasm debug artifact is not a serialized rules blob",
      );
    });

    it("should report that source code is unavailable after deserialize", () => {
      const rules = yarax.compile(`rule r { strings: $a = "x" condition: $a }`);
      const restored = yarax.deserialize(rules.serialize());
      const wasmPath = join(__tempDir, `nosource-${Date.now()}.wasm`);
      throws(() => restored.emitWasmFile(wasmPath), /source code not available/i);
    });

    it("should round-trip a blob written to and read from disk", () => {
      const rules = yarax.compile(serializeRule);
      const blobPath = join(__tempDir, `rules-${Date.now()}.yarx`);
      writeFileSync(blobPath, rules.serialize());
      const restored = yarax.deserialize(readFileSync(blobPath));
      strictEqual(restored.scan(Buffer.from("needle")).length, 1);
      strictEqual(restored.scan(Buffer.from("haystack")).length, 1);
    });

    it("should report match offsets and context offsets as numbers", () => {
      const scanner = yarax.compile(
        'rule r { strings: $a = "needle" condition: $a }',
      );
      scanner.setMatchContextSize(8);

      const [match] = scanner.scan(Buffer.from("hay needle stack"));
      const [pattern] = match.matches;
      strictEqual(pattern.offset, 4, "Match offset should be exact");
      strictEqual(pattern.length, 6, "Match length should be exact");
      strictEqual(typeof pattern.offset, "number", "Offset should be a number");
      ok(
        pattern.contextData.startsWith("hay ne"),
        "Context should include bytes before the match",
      );
      strictEqual(
        pattern.contextMatchOffset,
        4,
        "Context match offset should point at the match within the context",
      );
    });
  });

  describe("Concurrent async scanning", () => {
    it("should handle concurrent async scans with the same scanner", async () => {
      const scanner = yarax.compile(`
        rule test_concurrent {
          strings:
            $a = "needle"
          condition:
            $a
        }
      `);

      const matchBuf = Buffer.from("hay needle stack");
      const noMatchBuf = Buffer.from("hay haystack");

      const tasks = [];
      for (let i = 0; i < 50; i++) {
        const isMatch = i % 2 === 0;
        tasks.push(
          scanner.scanAsync(isMatch ? matchBuf : noMatchBuf).then((matches) => {
            if (isMatch) {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].ruleIdentifier, "test_concurrent");
            } else {
              strictEqual(matches.length, 0);
            }
          }),
        );
      }

      await Promise.all(tasks);
    });

    it("should handle concurrent async scans across different rule sets without collision", async () => {
      const scannerA = yarax.compile(`rule rule_a { strings: $a = "alpha" condition: $a }`);
      const scannerB = yarax.compile(`rule rule_b { strings: $b = "beta" condition: $b }`);
      const scannerC = yarax.compile(`rule rule_c { strings: $c = "gamma" condition: $c }`);

      const dataA = Buffer.from("contains alpha here");
      const dataB = Buffer.from("contains beta here");
      const dataC = Buffer.from("contains gamma here");

      const tasks = [];
      for (let i = 0; i < 60; i++) {
        const type = i % 3;
        if (type === 0) {
          tasks.push(
            scannerA.scanAsync(dataA).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].ruleIdentifier, "rule_a");
            }),
          );
        } else if (type === 1) {
          tasks.push(
            scannerB.scanAsync(dataB).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].ruleIdentifier, "rule_b");
            }),
          );
        } else {
          tasks.push(
            scannerC.scanAsync(dataC).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].ruleIdentifier, "rule_c");
            }),
          );
        }
      }

      await Promise.all(tasks);
    });

    it("should handle concurrent async scans across different scan options", async () => {
      const rule = `
        rule test_options {
          strings:
            $p = "tok"
          condition:
            $p
        }
      `;
      const scanner1 = yarax.compile(rule);
      scanner1.setMaxMatchesPerPattern(1);

      const scanner2 = yarax.compile(rule);
      scanner2.setMaxMatchesPerPattern(3);

      const scannerDefault = yarax.compile(rule);

      // Buffer has 6 occurrences of "tok"
      const data = Buffer.from("tok tok tok tok tok tok");

      const tasks = [];
      for (let i = 0; i < 45; i++) {
        const type = i % 3;
        if (type === 0) {
          tasks.push(
            scanner1.scanAsync(data).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].matches.length, 1);
            }),
          );
        } else if (type === 1) {
          tasks.push(
            scanner2.scanAsync(data).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].matches.length, 3);
            }),
          );
        } else {
          tasks.push(
            scannerDefault.scanAsync(data).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].matches.length, 6);
            }),
          );
        }
      }

      await Promise.all(tasks);
    });

    it("should handle concurrent async scans with different scan-time variables", async () => {
      const rule = `
        rule test_scan_var {
          condition:
            val > 50
        }
      `;
      const scanner = yarax.compile(rule, {
        defineVariables: { val: "0" },
      });

      const buf = Buffer.from("dummy");
      const tasks = [];
      for (let i = 0; i < 60; i++) {
        const shouldMatch = i % 2 === 0;
        const vars = { val: shouldMatch ? "100" : "10" };
        tasks.push(
          scanner.scanAsync(buf, vars).then((matches) => {
            if (shouldMatch) {
              strictEqual(matches.length, 1, `Iteration ${i} with val=100 should match`);
              strictEqual(matches[0].ruleIdentifier, "test_scan_var");
            } else {
              strictEqual(matches.length, 0, `Iteration ${i} with val=10 should not match`);
            }
          }),
        );
      }

      await Promise.all(tasks);
    });

    it("should handle concurrent async file scans and buffer scans simultaneously", async () => {
      const fileRule = `rule file_r { strings: $f = "file_pattern" condition: $f }`;
      const dataRule = `rule data_r { strings: $d = "data_pattern" condition: $d }`;

      const fileScanner = yarax.compile(fileRule);
      const dataScanner = yarax.compile(dataRule);

      const tempFile = createTempFile("content with file_pattern embedded");
      const dataBuf = Buffer.from("content with data_pattern embedded");

      const tasks = [];
      for (let i = 0; i < 50; i++) {
        if (i % 2 === 0) {
          tasks.push(
            fileScanner.scanFileAsync(tempFile).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].ruleIdentifier, "file_r");
            }),
          );
        } else {
          tasks.push(
            dataScanner.scanAsync(dataBuf).then((matches) => {
              strictEqual(matches.length, 1);
              strictEqual(matches[0].ruleIdentifier, "data_r");
            }),
          );
        }
      }

      await Promise.all(tasks);
    });

    it("should invalidate and reuse worker cache when rules are incrementally recompiled", async () => {
      const scanner = yarax.compile(`rule r1 { strings: $a = "first" condition: $a }`);

      const buf1 = Buffer.from("first test");
      const res1 = await scanner.scanAsync(buf1);
      strictEqual(res1.length, 1);
      strictEqual(res1[0].ruleIdentifier, "r1");

      // Incremental recompile modifies scanner.rules (new Arc<Rules>)
      scanner.addRuleSource(`rule r2 { strings: $b = "second" condition: $b }`);

      const buf2 = Buffer.from("second test");
      const res2 = await scanner.scanAsync(buf2);
      strictEqual(res2.length, 1);
      strictEqual(res2[0].ruleIdentifier, "r2");

      // Concurrent scans on both patterns
      const tasks = [];
      for (let i = 0; i < 20; i++) {
        tasks.push(
          scanner.scanAsync(buf1).then((matches) => {
            strictEqual(matches.length, 1);
            strictEqual(matches[0].ruleIdentifier, "r1");
          }),
        );
        tasks.push(
          scanner.scanAsync(buf2).then((matches) => {
            strictEqual(matches.length, 1);
            strictEqual(matches[0].ruleIdentifier, "r2");
          }),
        );
      }
      await Promise.all(tasks);
    });
  });

  describe("Fast-path boolean match check API", () => {
    const matchRule = `
      rule match_rule {
        strings:
          $a = "malicious payload"
        condition:
          $a
      }
    `;

    const varRule = `
      rule var_rule {
        condition:
          score > 50 and flag and tag == "threat"
      }
    `;

    describe("isMatch (synchronous)", () => {
      it("should return true when a rule matches", () => {
        const scanner = yarax.compile(matchRule);
        const buf = Buffer.from("Here is some malicious payload to detect");
        const result = scanner.isMatch(buf);
        strictEqual(typeof result, "boolean");
        strictEqual(result, true);
      });

      it("should return false when no rule matches", () => {
        const scanner = yarax.compile(matchRule);
        const buf = Buffer.from("Clean payload without detection");
        const result = scanner.isMatch(buf);
        strictEqual(typeof result, "boolean");
        strictEqual(result, false);
      });

      it("should respect compile-time and scan-time variables", () => {
        const scanner = yarax.compile(varRule, {
          defineVariables: { score: 10, flag: false, tag: "benign" },
        });

        // Default compile-time vars don't meet condition (> 50, true, "threat")
        strictEqual(scanner.isMatch(Buffer.from("")), false);

        // Override scan-time vars to satisfy condition
        strictEqual(
          scanner.isMatch(Buffer.from(""), {
            score: 75,
            flag: true,
            tag: "threat",
          }),
          true,
        );

        // Override only partially (should be false)
        strictEqual(
          scanner.isMatch(Buffer.from(""), {
            score: 75,
            flag: false,
            tag: "threat",
          }),
          false,
        );
      });

      it("should throw on invalid variable types", () => {
        const scanner = yarax.compile(matchRule);
        throws(
          () => scanner.isMatch(Buffer.from("test"), { badVar: {} }),
          /Unsupported variable type/i,
        );
      });
    });

    describe("isFileMatch (synchronous)", () => {
      it("should return true when a file matches", () => {
        const scanner = yarax.compile(matchRule);
        const tempFile = createTempFile("contains malicious payload here");
        const result = scanner.isFileMatch(tempFile);
        strictEqual(typeof result, "boolean");
        strictEqual(result, true);
      });

      it("should return false when a file does not match", () => {
        const scanner = yarax.compile(matchRule);
        const tempFile = createTempFile("completely benign content");
        const result = scanner.isFileMatch(tempFile);
        strictEqual(typeof result, "boolean");
        strictEqual(result, false);
      });

      it("should respect variables and options like useMmap", () => {
        const scanner = yarax.compile(varRule, {
          defineVariables: { score: 100, flag: true, tag: "threat" },
        });
        scanner.setUseMmap(false);
        const tempFile = createTempFile("dummy content");
        strictEqual(scanner.isFileMatch(tempFile), true);

        // Override to fail condition
        strictEqual(scanner.isFileMatch(tempFile, { score: 20 }), false);
      });

      it("should throw when scanning a non-existent file", () => {
        const scanner = yarax.compile(matchRule);
        throws(
          () => scanner.isFileMatch(join(__tempDir, "does-not-exist.bin")),
          /I\/O error/i,
        );
      });
    });

    describe("isMatchAsync", () => {
      it("should resolve to true when a rule matches", async () => {
        const scanner = yarax.compile(matchRule);
        const buf = Buffer.from("Here is some malicious payload to detect");
        const result = await scanner.isMatchAsync(buf);
        strictEqual(typeof result, "boolean");
        strictEqual(result, true);
      });

      it("should resolve to false when no rule matches", async () => {
        const scanner = yarax.compile(matchRule);
        const buf = Buffer.from("Clean payload without detection");
        const result = await scanner.isMatchAsync(buf);
        strictEqual(typeof result, "boolean");
        strictEqual(result, false);
      });

      it("should respect compile-time and scan-time variables", async () => {
        const scanner = yarax.compile(varRule, {
          defineVariables: { score: 10, flag: false, tag: "benign" },
        });

        strictEqual(await scanner.isMatchAsync(Buffer.from("")), false);
        strictEqual(
          await scanner.isMatchAsync(Buffer.from(""), {
            score: 80,
            flag: true,
            tag: "threat",
          }),
          true,
        );
      });

      it("should reject on invalid inputs", async () => {
        const scanner = yarax.compile(matchRule);
        let rejected = false;
        try {
          await scanner.isMatchAsync(Buffer.from("test"), { badVar: [] });
        } catch (err) {
          rejected = true;
          ok(/Unsupported variable type/i.test(err.message));
        }
        strictEqual(rejected, true, "Promise should reject on invalid variable input");
      });

      it("should support concurrent isMatchAsync queries", async () => {
        const scanner = yarax.compile(matchRule);
        const matchBuf = Buffer.from("malicious payload");
        const nonMatchBuf = Buffer.from("clean payload");

        const promises = [];
        for (let i = 0; i < 50; i++) {
          promises.push(scanner.isMatchAsync(matchBuf).then((res) => strictEqual(res, true)));
          promises.push(scanner.isMatchAsync(nonMatchBuf).then((res) => strictEqual(res, false)));
        }
        await Promise.all(promises);
      });
    });

    describe("isFileMatchAsync", () => {
      it("should resolve to true when a file matches", async () => {
        const scanner = yarax.compile(matchRule);
        const tempFile = createTempFile("contains malicious payload here");
        const result = await scanner.isFileMatchAsync(tempFile);
        strictEqual(typeof result, "boolean");
        strictEqual(result, true);
      });

      it("should resolve to false when a file does not match", async () => {
        const scanner = yarax.compile(matchRule);
        const tempFile = createTempFile("completely benign content");
        const result = await scanner.isFileMatchAsync(tempFile);
        strictEqual(typeof result, "boolean");
        strictEqual(result, false);
      });

      it("should respect variables in file scan", async () => {
        const scanner = yarax.compile(varRule, {
          defineVariables: { score: 99, flag: true, tag: "threat" },
        });
        const tempFile = createTempFile("test file");
        strictEqual(await scanner.isFileMatchAsync(tempFile), true);
        strictEqual(await scanner.isFileMatchAsync(tempFile, { flag: false }), false);
      });

      it("should reject on non-existent file or invalid input", async () => {
        const scanner = yarax.compile(matchRule);
        let fileRejected = false;
        try {
          await scanner.isFileMatchAsync(join(__tempDir, "non-existent-async-file.bin"));
        } catch (err) {
          fileRejected = true;
          ok(/I\/O error/i.test(err.message));
        }
        strictEqual(fileRejected, true, "Should reject for missing file");

        let varRejected = false;
        const tempFile = createTempFile("valid file");
        try {
          await scanner.isFileMatchAsync(tempFile, { invalid: Symbol("test") });
        } catch (err) {
          varRejected = true;
          ok(/Unsupported variable type/i.test(err.message));
        }
        strictEqual(varRejected, true, "Should reject for invalid variable type");
      });
    });
  });

  describe("fastScan and zero-copy async buffer handling", () => {
    it("should allow enabling fastScan mode to limit pattern matches", () => {
      const rule = `
        rule test_fast_scan {
          strings:
            $a = "target"
          condition:
            $a
        }
      `;
      const scanner = yarax.compile(rule);
      const data = Buffer.from("target ... target ... target");

      // Default scan finds all 3 occurrences
      const matchesAll = scanner.scan(data);
      strictEqual(matchesAll.length, 1);
      strictEqual(matchesAll[0].matches.length, 3);

      // Fast scan limits pattern search to first match
      scanner.setFastScan(true);
      const matchesFast = scanner.scan(data);
      strictEqual(matchesFast.length, 1);
      strictEqual(matchesFast[0].matches.length, 1);
      strictEqual(matchesFast[0].matches[0].offset, 0);

      // Re-disabling fast scan restores full reporting
      scanner.setFastScan(false);
      const matchesRestored = scanner.scan(data);
      strictEqual(matchesRestored[0].matches.length, 3);
    });

    it("should apply fastScan mode across async buffer and file scanning", async () => {
      const rule = `
        rule test_fast_async {
          strings:
            $a = "target"
          condition:
            $a
        }
      `;
      const scanner = yarax.compile(rule);
      scanner.setFastScan(true);
      const data = Buffer.from("target target target");

      const asyncMatches = await scanner.scanAsync(data);
      strictEqual(asyncMatches[0].matches.length, 1);

      const isMatch = await scanner.isMatchAsync(data);
      strictEqual(isMatch, true);
    });

    it("should scan large 20MB buffers zero-copy asynchronously without memory corruption", async () => {
      const rule = `
        rule large_buffer_test {
          strings:
            $a = "malware_payload_marker"
          condition:
            $a
        }
      `;
      const scanner = yarax.compile(rule);

      // 20 MB buffer filled with zeroes and needle at offset 18 MB
      const size = 20 * 1024 * 1024;
      const largeBuffer = Buffer.alloc(size);
      const needle = Buffer.from("malware_payload_marker");
      const targetOffset = 18 * 1024 * 1024;
      needle.copy(largeBuffer, targetOffset);

      // Zero-copy async scan
      const matches = await scanner.scanAsync(largeBuffer);
      strictEqual(matches.length, 1);
      strictEqual(matches[0].ruleIdentifier, "large_buffer_test");
      strictEqual(matches[0].matches.length, 1);
      strictEqual(matches[0].matches[0].offset, targetOffset);

      // Zero-copy async boolean check
      const hasMatch = await scanner.isMatchAsync(largeBuffer);
      strictEqual(hasMatch, true);

      // Buffer without match
      const cleanBuffer = Buffer.alloc(1024 * 1024 * 5);
      const noMatch = await scanner.isMatchAsync(cleanBuffer);
      strictEqual(noMatch, false);
    });
  });

  describe("Compiled Rules Introspection", () => {
    it("should return the correct ruleCount", () => {
      const source = `
        rule rule_one { strings: $a = "one" condition: $a }
        rule rule_two { strings: $b = "two" condition: $b }
        rule rule_three { strings: $c = "three" condition: $c }
      `;
      const scanner = yarax.compile(source);
      strictEqual(scanner.ruleCount, 3);
    });

    it("should return module imports via getImports", () => {
      const source = `
        import "math"
        rule math_rule {
          condition:
            math.max(1, 2) == 2
        }
      `;
      const scanner = yarax.compile(source);
      const imports = scanner.getImports();
      ok(Array.isArray(imports));
      ok(imports.includes("math"), "Expected imports to include 'math'");
    });

    it("should return rule metadata via getRules", () => {
      const source = `
        rule tagged_rule : tag1 tag2 {
          strings:
            $str1 = "abc"
            $str2 = "xyz"
          condition:
            any of them
        }
      `;
      const scanner = yarax.compile(source);
      const rules = scanner.getRules();
      strictEqual(rules.length, 1);
      strictEqual(rules[0].identifier, "tagged_rule");
      strictEqual(rules[0].namespace, "default");
      deepStrictEqual(rules[0].tags, ["tag1", "tag2"]);
      deepStrictEqual(rules[0].patterns, ["$str1", "$str2"]);
    });

    it("should preserve rule inspection across serialize/deserialize", () => {
      const source = `
        rule serialized_rule : mytag {
          strings:
            $a = "needle"
          condition:
            $a
        }
      `;
      const scanner = yarax.compile(source);
      const serialized = scanner.serialize();
      const restored = yarax.deserialize(serialized);

      strictEqual(restored.ruleCount, 1);
      const rules = restored.getRules();
      strictEqual(rules.length, 1);
      strictEqual(rules[0].identifier, "serialized_rule");
      deepStrictEqual(rules[0].tags, ["mytag"]);
      deepStrictEqual(rules[0].patterns, ["$a"]);
    });
  });

  describe("maxScanSize Protection", () => {
    it("should limit scanned byte size on buffer scans", () => {
      const source = `
        rule find_tail {
          strings:
            $tail = "tail_signature"
          condition:
            $tail
        }
      `;
      const scanner = yarax.compile(source);

      // Create a 10KB buffer with needle at byte 8,000
      const buf = Buffer.alloc(10 * 1024, "A");
      buf.write("tail_signature", 8000);

      // Unrestricted scan matches
      strictEqual(scanner.isMatch(buf), true);

      // Restricting maxScanSize to 4,000 bytes prevents scanning the needle
      scanner.setMaxScanSize(4000);
      strictEqual(scanner.isMatch(buf), false);

      // Re-expanding maxScanSize finds the needle
      scanner.setMaxScanSize(10000);
      strictEqual(scanner.isMatch(buf), true);
    });

    it("should apply maxScanSize to async scanning", async () => {
      const source = `
        rule find_tail_async {
          strings:
            $tail = "async_tail"
          condition:
            $tail
        }
      `;
      const scanner = yarax.compile(source);
      const buf = Buffer.alloc(10 * 1024, "X");
      buf.write("async_tail", 8000);

      scanner.setMaxScanSize(5000);
      const isMatchCapped = await scanner.isMatchAsync(buf);
      strictEqual(isMatchCapped, false);

      scanner.setMaxScanSize(0); // clear limit
      const isMatchUncapped = await scanner.isMatchAsync(buf);
      strictEqual(isMatchUncapped, true);
    });
  });
  });
});



describe("XOR key reporting", () => {
  const xorSource = `
    rule keyed_pattern {
      strings:
        $keyed = "malware" xor(0x01-0xff)
      condition:
        $keyed
    }

    rule plain_pattern {
      strings:
        $plain = "malware"
      condition:
        $plain
    }
  `;

  const xorEncode = (text, key) =>
    Buffer.from(Buffer.from(text, "latin1").map((byte) => byte ^ key));

  it("should report the XOR key that produced a match", () => {
    const scanner = yarax.compile(xorSource);
    const matches = scanner.scan(xorEncode("malware", 0x42));
    const keyed = matches.find((match) => match.ruleIdentifier === "keyed_pattern");

    ok(keyed, "expected the xor pattern to match");
    strictEqual(keyed.matches[0].xorKey, 0x42);
  });

  it("should not set xorKey for plain patterns", () => {
    const scanner = yarax.compile(xorSource);
    const matches = scanner.scan(Buffer.from("malware"));
    const plain = matches.find((match) => match.ruleIdentifier === "plain_pattern");

    ok(plain, "expected the plain pattern to match");
    strictEqual(plain.matches[0].xorKey, undefined);
  });

  it("should report xorKey from async scans", async () => {
    const scanner = yarax.compile(xorSource);
    const matches = await scanner.scanAsync(xorEncode("malware", 0x7f));
    const keyed = matches.find((match) => match.ruleIdentifier === "keyed_pattern");

    ok(keyed, "expected the xor pattern to match");
    strictEqual(keyed.matches[0].xorKey, 0x7f);
  });
});

describe("Rule logging and profiling", () => {
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  it("should route console module output to the callback", async () => {
    const scanner = yarax.compile(`
      import "console"
      rule Logging {
        condition:
          console.log("from rule") and true
      }
    `);

    const messages = [];
    scanner.setConsoleLog((message) => messages.push(message));
    scanner.scan(Buffer.from("x"));

    strictEqual(messages.length, 0, "messages arrive on the event loop, not during the scan");
    await sleep(20);
    deepStrictEqual(messages, ["from rule"]);

    scanner.setConsoleLog();
    scanner.scan(Buffer.from("x"));
    await sleep(20);
    strictEqual(messages.length, 1, "clearing the callback stops delivery");
  });

  it("should report slow rules above the throttling threshold", () => {
    const scanner = yarax.compile(`
      rule SlowRule {
        strings:
          $r = /ab+c/
        condition:
          $r
      }
    `);

    const data = Buffer.alloc(1024 * 1024, "abbb");
    for (let i = 0; i < 8 && scanner.getSlowestRules(1).length === 0; i++) {
      scanner.scan(data);
    }

    const slowest = scanner.getSlowestRules(3);
    ok(slowest.length >= 1, "expected the slow rule to be reported");
    strictEqual(slowest[0].identifier, "SlowRule");
    strictEqual(slowest[0].namespace, "default");
    ok(slowest[0].patternMatchingMs + slowest[0].conditionMs > 100);

    scanner.clearProfilingData();
    strictEqual(scanner.getSlowestRules(3).length, 0);
  });
});

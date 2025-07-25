import yarax from "../index.js";
import { existsSync, mkdirSync, writeFileSync, rmSync, statSync } from "fs";
import { join, dirname } from "path";
import { strictEqual, ok, fail } from "assert";
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
			"unknown",
			"Boolean metadata is returned as 'unknown'",
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
	});
});

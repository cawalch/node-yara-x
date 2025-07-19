import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { cpus, totalmem, freemem, loadavg } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import yarax from "../index.js";
import YaraXProfiler from "./profiling.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Performance regression detection and analysis system
 * Provides data-driven insights into YARA-X performance bottlenecks
 */
class PerformanceRegressionAnalyzer {
	constructor() {
		this.profiler = new YaraXProfiler();
		this.testData = this.generateTestData();
		this.testRules = this.generateTestRules();
		this.results = [];
	}

	generateTestData() {
		// Generate various sizes of test data to stress different aspects
		const smallData = Buffer.from(
			"This is a small test string with malware and virus patterns",
		);

		const mediumData = Buffer.alloc(1024 * 100); // 100KB
		mediumData.fill("A");
		mediumData.write("malware pattern", 1000);
		mediumData.write("virus signature", 50000);
		mediumData.write("trojan horse", 80000);

		const largeData = Buffer.alloc(1024 * 1024 * 5); // 5MB
		largeData.fill("X");
		largeData.write("malware pattern", 1000000);
		largeData.write("virus signature", 2500000);
		largeData.write("trojan horse", 4000000);

		// Create data with many small matches
		const patternData = Buffer.alloc(1024 * 50); // 50KB
		for (let i = 0; i < patternData.length - 10; i += 100) {
			patternData.write("malware", i);
		}

		return {
			small: smallData,
			medium: mediumData,
			large: largeData,
			pattern: patternData,
		};
	}

	generateTestRules() {
		return {
			simple: `
        rule simple_rule {
          strings:
            $a = "malware"
            $b = "virus"
          condition:
            any of them
        }
      `,

			complex: `
        rule complex_rule {
          strings:
            $a1 = "pattern1"
            $a2 = "pattern2"
            $a3 = "pattern3"
            $a4 = "pattern4"
            $a5 = "pattern5"
            $b1 = "malware"
            $b2 = "virus"
            $b3 = "trojan"
            $b4 = "worm"
            $b5 = "ransomware"
          condition:
            (2 of ($a*)) and (1 of ($b*))
        }
      `,

			regex: `
        rule regex_rule {
          strings:
            $a = /mal[a-z]+/
            $b = /vir[a-z]+/
            $c = /[0-9]{3}-[0-9]{2}-[0-9]{4}/
            $d = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/
          condition:
            any of them
        }
      `,

			multiple: `
        rule rule1 {
          strings: $a = "malware"
          condition: $a
        }
        rule rule2 {
          strings: $a = "virus"
          condition: $a
        }
        rule rule3 {
          strings: $a = "trojan"
          condition: $a
        }
        rule rule4 {
          strings: $a = "worm"
          condition: $a
        }
        rule rule5 {
          strings: $a = "ransomware"
          condition: $a
        }
      `,

			heavy: `
        rule heavy_rule {
          strings:
            $s1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
            $s2 = { 50 45 00 00 4C 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
            $s3 = /\\x4d\\x5a[\\x00-\\xff]{58}\\x50\\x45/
            $s4 = "CreateProcess"
            $s5 = "WriteProcessMemory"
            $s6 = "VirtualAlloc"
            $s7 = "GetProcAddress"
            $s8 = "LoadLibrary"
          condition:
            ($s1 at 0) and ($s2 or $s3) and 3 of ($s4, $s5, $s6, $s7, $s8)
        }
      `,
		};
	}

	async runComprehensiveAnalysis() {
		console.log("Starting Comprehensive Performance Analysis");
		console.log("==========================================");

		const analysisResults = {
			timestamp: new Date().toISOString(),
			environment: this.getEnvironmentInfo(),
			tests: [],
		};

		// Test 1: Compilation Performance
		console.log("\nTesting Compilation Performance");
		for (const [ruleName, ruleSource] of Object.entries(this.testRules)) {
			const result = await this.profiler.profileOperation(
				`Compile ${ruleName} rule`,
				() => yarax.compile(ruleSource),
				{ iterations: 50, collectMemory: true, collectCPU: true },
			);
			analysisResults.tests.push(result);
		}

		// Test 2: Scanning Performance by Data Size
		console.log("\nTesting Scanning Performance by Data Size");
		const simpleScanner = yarax.compile(this.testRules.simple);

		for (const [dataName, data] of Object.entries(this.testData)) {
			const result = await this.profiler.profileOperation(
				`Scan ${dataName} data (${Math.round(data.length / 1024)}KB)`,
				() => simpleScanner.scan(data),
				{
					iterations: dataName === "large" ? 10 : 100,
					collectMemory: true,
					collectCPU: true,
					sampleInterval: 5,
				},
			);
			analysisResults.tests.push(result);
		}

		// Test 3: Rule Complexity Impact
		console.log("\nTesting Rule Complexity Impact");
		const mediumData = this.testData.medium;

		for (const [ruleName, ruleSource] of Object.entries(this.testRules)) {
			const scanner = yarax.compile(ruleSource);
			const result = await this.profiler.profileOperation(
				`Scan with ${ruleName} rule`,
				() => scanner.scan(mediumData),
				{ iterations: 50, collectMemory: true, collectCPU: true },
			);
			analysisResults.tests.push(result);
		}

		// Test 4: Memory Pressure Analysis
		console.log("\nTesting Memory Pressure");
		const heavyScanner = yarax.compile(this.testRules.heavy);

		const memoryPressureResult = await this.profiler.profileOperation(
			"Memory pressure test",
			() => heavyScanner.scan(this.testData.large),
			{
				iterations: 20,
				collectMemory: true,
				collectCPU: true,
				forceGCBetween: true,
				sampleInterval: 1,
			},
		);
		analysisResults.tests.push(memoryPressureResult);

		// Test 5: Allocation Pattern Analysis
		console.log("\nTesting Allocation Patterns");
		const allocationResult = await this.profiler.profileOperation(
			"Allocation pattern analysis",
			async () => {
				// Create and destroy multiple scanners to test allocation patterns
				for (let i = 0; i < 5; i++) {
					const scanner = yarax.compile(this.testRules.simple);
					scanner.scan(this.testData.small);
				}
			},
			{ iterations: 30, collectMemory: true, sampleInterval: 1 },
		);
		analysisResults.tests.push(allocationResult);

		// Save results
		const resultsFile = this.profiler.saveResults(
			analysisResults,
			"performance-analysis.json",
		);

		// Generate analysis report
		this.generateAnalysisReport(analysisResults);

		this.profiler.cleanup();
		return analysisResults;
	}

	getEnvironmentInfo() {
		return {
			nodeVersion: process.version,
			platform: process.platform,
			arch: process.arch,
			cpus: cpus().length,
			totalMemory: totalmem(),
			freeMemory: freemem(),
			loadAverage: loadavg(),
		};
	}

	generateAnalysisReport(results) {
		console.log("\n" + "=".repeat(60));
		console.log("PERFORMANCE ANALYSIS REPORT");
		console.log("=".repeat(60));

		// Find potential bottlenecks
		const bottlenecks = this.identifyBottlenecks(results.tests);

		console.log("\nIDENTIFIED BOTTLENECKS:");
		bottlenecks.forEach((bottleneck, index) => {
			console.log(
				`${index + 1}. ${bottleneck.type}: ${bottleneck.description}`,
			);
			console.log(`   Impact: ${bottleneck.impact}`);
			console.log(`   Recommendation: ${bottleneck.recommendation}\n`);
		});

		// Performance summary
		const summary = this.generatePerformanceSummary(results.tests);
		console.log("PERFORMANCE SUMMARY:");
		console.log(`   Average Scan Time: ${summary.avgScanTime.toFixed(3)} ms`);
		console.log(
			`   Average Throughput: ${summary.avgThroughput.toFixed(1)} ops/sec`,
		);
		console.log(
			`   Memory Efficiency: ${summary.memoryEfficiency.toFixed(2)} KB/ms`,
		);
		console.log(`   CPU Utilization: ${summary.cpuUtilization.toFixed(1)}%`);
		console.log(`   GC Overhead: ${summary.gcOverhead.toFixed(1)}%`);

		// Save detailed report
		const reportPath = join(__dirname, "performance-report.md");
		this.saveMarkdownReport(results, bottlenecks, summary, reportPath);
		console.log(`\nDetailed report saved to: ${reportPath}`);
	}

	identifyBottlenecks(tests) {
		const bottlenecks = [];

		tests.forEach((test) => {
			// High memory usage
			if (test.memory && test.memory.totalDelta.heapUsed > 50 * 1024 * 1024) {
				// 50MB
				bottlenecks.push({
					type: "Memory Usage",
					description: `${test.name} uses ${(test.memory.totalDelta.heapUsed / 1024 / 1024).toFixed(1)}MB heap`,
					impact: "High memory consumption may cause GC pressure",
					recommendation: "Investigate memory allocations in scanning logic",
				});
			}

			// High timing variance
			if (test.timing.cv > 0.3) {
				bottlenecks.push({
					type: "Timing Variance",
					description: `${test.name} has high variance (CV: ${test.timing.cv.toFixed(3)})`,
					impact: "Inconsistent performance",
					recommendation: "Investigate causes of timing inconsistency",
				});
			}

			// Low throughput
			if (test.timing.throughput < 100) {
				bottlenecks.push({
					type: "Low Throughput",
					description: `${test.name} has low throughput (${test.timing.throughput.toFixed(1)} ops/sec)`,
					impact: "Poor performance for high-volume scanning",
					recommendation: "Optimize scanning algorithm or rule compilation",
				});
			}

			// High GC overhead
			if (test.gc && test.gc.overhead > test.timing.total * 0.1) {
				bottlenecks.push({
					type: "GC Overhead",
					description: `${test.name} has high GC overhead (${((test.gc.overhead / test.timing.total) * 100).toFixed(1)}%)`,
					impact: "Garbage collection is impacting performance",
					recommendation: "Reduce allocations or improve memory management",
				});
			}
		});

		return bottlenecks;
	}

	generatePerformanceSummary(tests) {
		const scanTests = tests.filter((t) => t.name.includes("Scan"));

		return {
			avgScanTime:
				scanTests.reduce((sum, t) => sum + t.timing.mean, 0) / scanTests.length,
			avgThroughput:
				scanTests.reduce((sum, t) => sum + t.timing.throughput, 0) /
				scanTests.length,
			memoryEfficiency:
				scanTests
					.filter((t) => t.memory)
					.reduce((sum, t) => sum + t.memory.efficiency.memoryPerMs, 0) /
				scanTests.filter((t) => t.memory).length,
			cpuUtilization:
				scanTests
					.filter((t) => t.cpu)
					.reduce((sum, t) => sum + t.cpu.utilization.totalPercent, 0) /
				scanTests.filter((t) => t.cpu).length,
			gcOverhead:
				scanTests
					.filter((t) => t.gc)
					.reduce((sum, t) => sum + (t.gc.overhead / t.timing.total) * 100, 0) /
				scanTests.filter((t) => t.gc).length,
		};
	}

	saveMarkdownReport(results, bottlenecks, summary, filepath) {
		const report = `# YARA-X Performance Analysis Report

Generated: ${results.timestamp}

## Environment
- Node.js: ${results.environment.nodeVersion}
- Platform: ${results.environment.platform} ${results.environment.arch}
- CPUs: ${results.environment.cpus}
- Memory: ${(results.environment.totalMemory / 1024 / 1024 / 1024).toFixed(1)}GB total

## Performance Summary
- Average Scan Time: ${summary.avgScanTime.toFixed(3)} ms
- Average Throughput: ${summary.avgThroughput.toFixed(1)} ops/sec
- Memory Efficiency: ${summary.memoryEfficiency.toFixed(2)} KB/ms
- CPU Utilization: ${summary.cpuUtilization.toFixed(1)}%
- GC Overhead: ${summary.gcOverhead.toFixed(1)}%

## Identified Bottlenecks
${bottlenecks
	.map(
		(b, i) => `
### ${i + 1}. ${b.type}
**Description:** ${b.description}
**Impact:** ${b.impact}
**Recommendation:** ${b.recommendation}
`,
	)
	.join("\n")}

## Detailed Test Results
${results.tests
	.map(
		(test) => `
### ${test.name}
- **Iterations:** ${test.iterations}
- **Mean Time:** ${test.timing.mean.toFixed(3)} ms
- **Throughput:** ${test.timing.throughput.toFixed(1)} ops/sec
- **Memory Delta:** ${test.memory ? (test.memory.totalDelta.heapUsed / 1024 / 1024).toFixed(2) + " MB" : "N/A"}
- **CPU Usage:** ${test.cpu ? test.cpu.utilization.totalPercent.toFixed(1) + "%" : "N/A"}
`,
	)
	.join("\n")}
`;

		writeFileSync(filepath, report);
	}
}

// Run analysis if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
	const analyzer = new PerformanceRegressionAnalyzer();
	analyzer.runComprehensiveAnalysis().catch(console.error);
}

export default PerformanceRegressionAnalyzer;

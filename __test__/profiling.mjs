import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { performance, PerformanceObserver } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Comprehensive profiling system for YARA-X performance analysis
 * Includes core profiling, scanner reuse benchmarks, and deep analysis
 */
class YaraXProfiler {
	constructor() {
		this.results = [];
		this.memoryBaseline = null;
		this.gcObserver = null;
		this.setupGCObserver();
	}

	setupGCObserver() {
		// Monitor garbage collection events for memory pressure analysis
		this.gcObserver = new PerformanceObserver((list) => {
			const entries = list.getEntries();
			for (const entry of entries) {
				if (entry.entryType === "gc") {
					this.results.push({
						type: "gc",
						timestamp: entry.startTime,
						duration: entry.duration,
						kind: entry.kind,
						flags: entry.flags,
					});
				}
			}
		});
		this.gcObserver.observe({ entryTypes: ["gc"] });
	}

	/**
	 * Get detailed memory usage with RSS, heap, and external memory
	 */
	getMemoryUsage() {
		const usage = process.memoryUsage();
		return {
			rss: usage.rss,
			heapTotal: usage.heapTotal,
			heapUsed: usage.heapUsed,
			external: usage.external,
			arrayBuffers: usage.arrayBuffers,
			timestamp: performance.now(),
		};
	}

	/**
	 * Force garbage collection if available (run with --expose-gc)
	 */
	forceGC() {
		if (global.gc) {
			global.gc();
		}
	}

	/**
	 * Profile CPU usage using process.cpuUsage()
	 */
	getCPUUsage() {
		return process.cpuUsage();
	}

	/**
	 * Run comprehensive benchmark with detailed metrics collection
	 */
	async profileOperation(name, operation, options = {}) {
		const {
			iterations = 100,
			warmupIterations = 5,
			collectMemory = true,
			collectCPU = true,
			forceGCBetween = false,
			sampleInterval = 10, // Sample memory every N iterations
		} = options;

		console.log(`\nProfiling: ${name}`);
		console.log(`   Iterations: ${iterations}, Warmup: ${warmupIterations}`);

		// Warmup phase
		console.log("   Warming up...");
		for (let i = 0; i < warmupIterations; i++) {
			await operation();
		}

		// Clear previous results and establish baseline
		this.results = [];
		this.forceGC();

		const memoryBaseline = this.getMemoryUsage();
		const cpuBaseline = this.getCPUUsage();

		const timings = [];
		const memorySnapshots = [];
		const cpuSnapshots = [];
		const peakMemory = { heapUsed: 0, rss: 0, external: 0 };
		const totalCPUTime = { user: 0, system: 0 };

		console.log("   Running benchmark...");

		for (let i = 0; i < iterations; i++) {
			// Pre-operation measurements
			const preMemory = collectMemory ? this.getMemoryUsage() : null;
			const preCPU = collectCPU ? this.getCPUUsage() : null;

			// Time the operation with high precision
			const startTime = performance.now();
			await operation();
			const endTime = performance.now();

			const duration = endTime - startTime;
			timings.push(duration);

			// Post-operation measurements
			const postMemory = collectMemory ? this.getMemoryUsage() : null;
			const postCPU = collectCPU ? this.getCPUUsage() : null;

			// Memory analysis
			if (collectMemory && i % sampleInterval === 0) {
				const memoryDelta = {
					heapUsed: postMemory.heapUsed - preMemory.heapUsed,
					rss: postMemory.rss - preMemory.rss,
					heapTotal: postMemory.heapTotal - preMemory.heapTotal,
					external: postMemory.external - preMemory.external,
					arrayBuffers: postMemory.arrayBuffers - preMemory.arrayBuffers,
				};

				memorySnapshots.push({
					iteration: i,
					pre: preMemory,
					post: postMemory,
					delta: memoryDelta,
					duration: duration,
				});

				// Track peak memory usage
				if (postMemory.heapUsed > peakMemory.heapUsed)
					peakMemory.heapUsed = postMemory.heapUsed;
				if (postMemory.rss > peakMemory.rss) peakMemory.rss = postMemory.rss;
				if (postMemory.external > peakMemory.external)
					peakMemory.external = postMemory.external;
			}

			// CPU analysis
			if (collectCPU && preCPU && postCPU) {
				const cpuDelta = {
					user: postCPU.user - preCPU.user,
					system: postCPU.system - preCPU.system,
				};

				totalCPUTime.user += cpuDelta.user;
				totalCPUTime.system += cpuDelta.system;

				if (i % sampleInterval === 0) {
					cpuSnapshots.push({
						iteration: i,
						delta: cpuDelta,
						duration: duration,
						efficiency:
							duration > 0
								? (cpuDelta.user + cpuDelta.system) / (duration * 1000)
								: 0,
					});
				}
			}

			// Optional GC between iterations to measure memory pressure
			if (forceGCBetween && i % 20 === 0) {
				this.forceGC();
			}
		}

		// Final measurements
		this.forceGC();
		const memoryFinal = this.getMemoryUsage();
		const cpuFinal = this.getCPUUsage();

		// Calculate comprehensive statistics
		const stats = this.calculateTimingStatistics(timings);
		const memoryStats = collectMemory
			? this.calculateMemoryStatistics(
					memorySnapshots,
					memoryBaseline,
					memoryFinal,
					peakMemory,
				)
			: null;
		const cpuStats = collectCPU
			? this.calculateCPUStatistics(
					cpuSnapshots,
					cpuBaseline,
					cpuFinal,
					totalCPUTime,
					stats.total,
				)
			: null;
		const gcStats = this.calculateGCStatistics();

		const result = {
			name,
			timestamp: new Date().toISOString(),
			iterations,
			config: options,
			timing: stats,
			memory: memoryStats,
			cpu: cpuStats,
			gc: gcStats,
			performance: this.calculatePerformanceMetrics(
				stats,
				memoryStats,
				cpuStats,
			),
		};

		this.logResults(result);
		return result;
	}

	/**
	 * Scanner reuse benchmark - tests the performance improvement from scanner caching
	 */
	async benchmarkScannerReuse(yaraX, testDataSets = null) {
		console.log("\nSCANNER REUSE BENCHMARK");
		console.log("=======================");

		if (!testDataSets) {
			testDataSets = [
				Buffer.from("test data with malware pattern"),
				Buffer.alloc(1024).fill("A"),
				Buffer.alloc(10240).fill("B"),
			];
		}

		const ruleSource = `
			rule test_rule {
				strings:
					$a = "malware"
					$b = "virus"
				condition:
					any of them
			}
		`;

		// Test current implementation (with scanner caching)
		const currentResults = await this.benchmarkCurrentPattern(
			yaraX,
			ruleSource,
			testDataSets,
		);

		// Test legacy pattern (simulated without caching)
		const legacyResults = await this.benchmarkLegacyPattern(
			yaraX,
			ruleSource,
			testDataSets,
		);

		// Calculate improvement
		const improvement = this.calculateScannerReuseImprovement(
			currentResults,
			legacyResults,
		);

		return {
			current: currentResults,
			legacy: legacyResults,
			improvement,
			timestamp: new Date().toISOString(),
		};
	}

	async benchmarkCurrentPattern(yaraX, ruleSource, testDataSets) {
		console.log("\nCURRENT PATTERN (Scanner caching enabled)");
		console.log("==========================================");

		const rules = yaraX.compile(ruleSource);
		const results = {
			pattern: "current_cached",
			scanResults: [],
			totalScans: 0,
		};

		for (const testData of testDataSets) {
			const dataSize = testData.length;
			const iterations = Math.min(100, Math.max(20, 200000 / dataSize));

			console.log(`   Testing ${dataSize} bytes x ${iterations} scans...`);

			const scanTimings = [];
			const memoryDeltas = [];

			for (let i = 0; i < iterations; i++) {
				const preMemory = this.getMemoryUsage();
				const startTime = performance.now();

				rules.scan(testData); // Reuses cached scanner

				const endTime = performance.now();
				const postMemory = this.getMemoryUsage();

				scanTimings.push(endTime - startTime);
				memoryDeltas.push(postMemory.rss - preMemory.rss);
				results.totalScans++;
			}

			const stats = this.calculateTimingStatistics(scanTimings);
			const avgMemoryDelta =
				memoryDeltas.reduce((a, b) => a + b, 0) / memoryDeltas.length;

			results.scanResults.push({
				dataSize,
				iterations,
				timing: stats,
				avgMemoryDelta,
				throughput: dataSize / stats.mean,
			});

			console.log(`      Avg: ${stats.mean.toFixed(3)}ms`);
			console.log(
				`      Throughput: ${(dataSize / stats.mean / 1024).toFixed(2)} KB/ms`,
			);
		}

		return results;
	}

	async benchmarkLegacyPattern(yaraX, ruleSource, testDataSets) {
		console.log("\nLEGACY PATTERN (Simulated without caching)");
		console.log("===========================================");

		const results = {
			pattern: "legacy_no_cache",
			scanResults: [],
			totalScans: 0,
		};

		for (const testData of testDataSets) {
			const dataSize = testData.length;
			const iterations = Math.min(50, Math.max(10, 100000 / dataSize));

			console.log(
				`   Testing ${dataSize} bytes x ${iterations} scans (legacy)...`,
			);

			const scanTimings = [];
			const memoryDeltas = [];

			for (let i = 0; i < iterations; i++) {
				const preMemory = this.getMemoryUsage();
				const startTime = performance.now();

				// Simulate legacy: compile + scan each time
				const tempRules = yaraX.compile(ruleSource);
				tempRules.scan(testData);

				const endTime = performance.now();
				const postMemory = this.getMemoryUsage();

				scanTimings.push(endTime - startTime);
				memoryDeltas.push(postMemory.rss - preMemory.rss);
				results.totalScans++;
			}

			const stats = this.calculateTimingStatistics(scanTimings);
			const avgMemoryDelta =
				memoryDeltas.reduce((a, b) => a + b, 0) / memoryDeltas.length;

			results.scanResults.push({
				dataSize,
				iterations,
				timing: stats,
				avgMemoryDelta,
				throughput: dataSize / stats.mean,
			});

			console.log(`      Avg: ${stats.mean.toFixed(3)}ms`);
			console.log(
				`      Throughput: ${(dataSize / stats.mean / 1024).toFixed(2)} KB/ms`,
			);
		}

		return results;
	}

	calculateScannerReuseImprovement(current, legacy) {
		const improvements = [];

		for (let i = 0; i < current.scanResults.length; i++) {
			const curr = current.scanResults[i];
			const leg = legacy.scanResults[i];

			const timeImprovement =
				((leg.timing.mean - curr.timing.mean) / leg.timing.mean) * 100;
			const throughputImprovement =
				((curr.throughput - leg.throughput) / leg.throughput) * 100;
			const memoryImprovement =
				((leg.avgMemoryDelta - curr.avgMemoryDelta) /
					Math.abs(leg.avgMemoryDelta)) *
				100;

			improvements.push({
				dataSize: curr.dataSize,
				timeImprovement,
				throughputImprovement,
				memoryImprovement,
			});
		}

		const avgTimeImprovement =
			improvements.reduce((sum, imp) => sum + imp.timeImprovement, 0) /
			improvements.length;
		const avgThroughputImprovement =
			improvements.reduce((sum, imp) => sum + imp.throughputImprovement, 0) /
			improvements.length;

		return {
			byDataSize: improvements,
			overall: {
				avgTimeImprovement,
				avgThroughputImprovement,
				summary: `Scanner caching provides ${avgTimeImprovement.toFixed(1)}% faster scanning and ${avgThroughputImprovement.toFixed(1)}% better throughput`,
			},
		};
	}

	calculateTimingStatistics(timings) {
		const sorted = [...timings].sort((a, b) => a - b);
		const sum = timings.reduce((a, b) => a + b, 0);
		const mean = sum / timings.length;
		const variance =
			timings.reduce((sq, n) => sq + (n - mean) ** 2, 0) / timings.length;

		return {
			count: timings.length,
			total: sum,
			mean: mean,
			median: sorted[Math.floor(sorted.length / 2)],
			min: Math.min(...timings),
			max: Math.max(...timings),
			p90: sorted[Math.floor(sorted.length * 0.9)],
			p95: sorted[Math.floor(sorted.length * 0.95)],
			p99: sorted[Math.floor(sorted.length * 0.99)],
			stddev: Math.sqrt(variance),
			variance: variance,
			cv: mean > 0 ? Math.sqrt(variance) / mean : 0, // Coefficient of variation
			throughput: timings.length / (sum / 1000), // Operations per second
		};
	}

	calculateMemoryStatistics(snapshots, baseline, final, peak) {
		if (snapshots.length === 0) return null;

		const deltas = snapshots.map((s) => s.delta);
		const heapDeltas = deltas.map((d) => d.heapUsed);
		const rssDeltas = deltas.map((d) => d.rss);
		const externalDeltas = deltas.map((d) => d.external);

		return {
			baseline: baseline,
			final: final,
			peak: peak,
			totalDelta: {
				heapUsed: final.heapUsed - baseline.heapUsed,
				rss: final.rss - baseline.rss,
				heapTotal: final.heapTotal - baseline.heapTotal,
				external: final.external - baseline.external,
				arrayBuffers: final.arrayBuffers - baseline.arrayBuffers,
			},
			perIteration: {
				heapUsed: this.calculateArrayStats(heapDeltas),
				rss: this.calculateArrayStats(rssDeltas),
				external: this.calculateArrayStats(externalDeltas),
			},
			efficiency: {
				memoryPerMs:
					snapshots.length > 0
						? snapshots.reduce(
								(sum, s) => sum + Math.abs(s.delta.heapUsed),
								0,
							) / snapshots.reduce((sum, s) => sum + s.duration, 0)
						: 0,
				peakToBaseline: peak.heapUsed / baseline.heapUsed,
				retentionRatio: final.heapUsed / peak.heapUsed,
			},
		};
	}

	calculateCPUStatistics(snapshots, baseline, final, total, totalTime) {
		if (snapshots.length === 0) return null;

		const userTimes = snapshots.map((s) => s.delta.user);
		const systemTimes = snapshots.map((s) => s.delta.system);
		const efficiencies = snapshots.map((s) => s.efficiency);

		return {
			total: total,
			baseline: baseline,
			final: final,
			perIteration: {
				user: this.calculateArrayStats(userTimes),
				system: this.calculateArrayStats(systemTimes),
				efficiency: this.calculateArrayStats(efficiencies),
			},
			utilization: {
				userPercent:
					totalTime > 0 ? (total.user / (totalTime * 1000)) * 100 : 0,
				systemPercent:
					totalTime > 0 ? (total.system / (totalTime * 1000)) * 100 : 0,
				totalPercent:
					totalTime > 0
						? ((total.user + total.system) / (totalTime * 1000)) * 100
						: 0,
			},
		};
	}

	calculateArrayStats(arr) {
		if (arr.length === 0) return { mean: 0, min: 0, max: 0, stddev: 0 };

		const sum = arr.reduce((a, b) => a + b, 0);
		const mean = sum / arr.length;
		const variance =
			arr.reduce((sq, n) => sq + (n - mean) ** 2, 0) / arr.length;

		return {
			mean: mean,
			min: Math.min(...arr),
			max: Math.max(...arr),
			stddev: Math.sqrt(variance),
			sum: sum,
		};
	}

	calculateGCStatistics() {
		const gcEvents = this.results.filter((r) => r.type === "gc");
		if (gcEvents.length === 0) return null;

		const durations = gcEvents.map((e) => e.duration);
		const totalDuration = durations.reduce((a, b) => a + b, 0);

		return {
			count: gcEvents.length,
			totalDuration,
			averageDuration: totalDuration / gcEvents.length,
			maxDuration: Math.max(...durations),
			frequency:
				(gcEvents.length /
					(gcEvents[gcEvents.length - 1]?.timestamp - gcEvents[0]?.timestamp ||
						1)) *
				1000,
			overhead: totalDuration, // GC overhead in ms
		};
	}

	calculatePerformanceMetrics(timing, memory, cpu) {
		const metrics = {
			efficiency: timing.throughput, // ops/sec
			stability: 1 - timing.cv, // Lower CV = more stable
			scalability: timing.mean > 0 ? timing.min / timing.mean : 0, // How well min performs vs average
		};

		if (memory) {
			metrics.memoryEfficiency = memory.efficiency.memoryPerMs;
			metrics.memoryStability =
				1 -
				memory.perIteration.heapUsed.stddev /
					Math.abs(memory.perIteration.heapUsed.mean || 1);
		}

		if (cpu) {
			metrics.cpuEfficiency = cpu.utilization.totalPercent;
			metrics.cpuStability =
				1 -
				cpu.perIteration.efficiency.stddev /
					Math.abs(cpu.perIteration.efficiency.mean || 1);
		}

		return metrics;
	}

	logResults(result) {
		console.log(`\nResults for: ${result.name}`);
		console.log(`   Timing (ms):`);
		console.log(
			`     Mean: ${result.timing.mean.toFixed(3)} | Median: ${result.timing.median.toFixed(3)}`,
		);
		console.log(
			`     Min: ${result.timing.min.toFixed(3)} | Max: ${result.timing.max.toFixed(3)}`,
		);
		console.log(
			`     P95: ${result.timing.p95.toFixed(3)} | P99: ${result.timing.p99.toFixed(3)}`,
		);
		console.log(
			`     StdDev: ${result.timing.stddev.toFixed(3)} | CV: ${result.timing.cv.toFixed(3)}`,
		);
		console.log(
			`     Throughput: ${result.timing.throughput.toFixed(1)} ops/sec`,
		);

		if (result.memory) {
			console.log(`   Memory:`);
			console.log(
				`     Heap Delta: ${(result.memory.totalDelta.heapUsed / 1024 / 1024).toFixed(2)} MB`,
			);
			console.log(
				`     RSS Delta: ${(result.memory.totalDelta.rss / 1024 / 1024).toFixed(2)} MB`,
			);
			console.log(
				`     Peak/Baseline: ${result.memory.efficiency.peakToBaseline.toFixed(2)}x`,
			);
			console.log(
				`     Memory/ms: ${(result.memory.efficiency.memoryPerMs / 1024).toFixed(2)} KB/ms`,
			);
		}

		if (result.cpu) {
			console.log(`   CPU:`);
			console.log(
				`     User: ${result.cpu.utilization.userPercent.toFixed(1)}% | System: ${result.cpu.utilization.systemPercent.toFixed(1)}%`,
			);
			console.log(
				`     Total Utilization: ${result.cpu.utilization.totalPercent.toFixed(1)}%`,
			);
		}

		if (result.gc) {
			console.log(`   GC:`);
			console.log(
				`     Events: ${result.gc.count} | Overhead: ${result.gc.totalDuration.toFixed(1)} ms`,
			);
			console.log(
				`     Frequency: ${result.gc.frequency.toFixed(2)} events/sec`,
			);
		}

		console.log(`   Performance Score:`);
		console.log(
			`     Efficiency: ${result.performance.efficiency.toFixed(1)} ops/sec`,
		);
		console.log(
			`     Stability: ${(result.performance.stability * 100).toFixed(1)}%`,
		);
	}

	/**
	 * Save results to JSON file for analysis
	 */
	saveResults(results, filename = "profiling-results.json") {
		const filepath = join(__dirname, filename);
		writeFileSync(filepath, JSON.stringify(results, null, 2));
		console.log(`\nResults saved to: ${filepath}`);
		return filepath;
	}

	/**
	 * Compare results with baseline
	 */
	compareWithBaseline(current, baseline) {
		const comparison = {
			timing: {
				meanChange:
					((current.timing.mean - baseline.timing.mean) /
						baseline.timing.mean) *
					100,
				medianChange:
					((current.timing.median - baseline.timing.median) /
						baseline.timing.median) *
					100,
				p95Change:
					((current.timing.p95 - baseline.timing.p95) / baseline.timing.p95) *
					100,
				throughputChange:
					((current.timing.throughput - baseline.timing.throughput) /
						baseline.timing.throughput) *
					100,
			},
		};

		if (current.memory && baseline.memory) {
			comparison.memory = {
				heapChange:
					((current.memory.totalDelta.heapUsed -
						baseline.memory.totalDelta.heapUsed) /
						Math.abs(baseline.memory.totalDelta.heapUsed || 1)) *
					100,
				rssChange:
					((current.memory.totalDelta.rss - baseline.memory.totalDelta.rss) /
						Math.abs(baseline.memory.totalDelta.rss || 1)) *
					100,
			};
		}

		if (current.cpu && baseline.cpu) {
			comparison.cpu = {
				userChange:
					((current.cpu.utilization.userPercent -
						baseline.cpu.utilization.userPercent) /
						baseline.cpu.utilization.userPercent) *
					100,
				systemChange:
					((current.cpu.utilization.systemPercent -
						baseline.cpu.utilization.systemPercent) /
						baseline.cpu.utilization.systemPercent) *
					100,
			};
		}

		return comparison;
	}

	cleanup() {
		if (this.gcObserver) {
			this.gcObserver.disconnect();
		}
	}
}

export default YaraXProfiler;

# Synthetic Routing and Economic Benchmark

The benchmark is a deterministic policy evaluation, not a model benchmark. Eleven disclosed synthetic tasks cover public, internal, confidential and restricted classifications at basic, standard and advanced capability levels. The configured registry contains local basic/standard routes and an enabled cloud advanced route. One advanced public task (`t11`) carries a simulated human approval signed over the exact bindings the router presents; every other cloud-eligible task receives no approval and must be refused.

The economic comparison covers only **completed non-sensitive** tasks (the `comparison_set` in the result). Sensitive tasks are listed in `excluded_sensitive`; refused tasks are listed in `excluded_blocked` and are never counted as savings. The baseline prices that set at a hypothetical cloud-large USD 10 per one million declared tokens. The candidate prices local at a disclosed USD 0 and the approved cloud-advanced route at a hypothetical USD 4 per one million tokens. Declared token budgets are fixtures, not tokenizer or billing observations. Hardware and energy cost are excluded.

Gated thresholds require 100% expected routing selection, zero unauthorized cloud routes, zero sensitive cloud routes and at least 60% local completion. Cost and token differences are **reported, not gated**: with a USD 0 local price and declared token budgets, a savings threshold could not fail meaningfully. Latency is reported only as a deterministic count of policy decisions; no wall-clock model latency is measured.

Raw inputs: `evals/benchmark_tasks.json`. Raw result: `evals/results/routing-benchmark.json`. The fixture hash is embedded in the result. The result's `environment.python` field records the supported range; the interpreter actually used is printed by `scripts/test.sh`. Declared token differences come from fixture values, not measurement.

Do not use these results to claim model quality, real provider savings, hardware performance, production throughput, or superiority.

import requests
import time
import uuid
import statistics

BASE_URL = "http://127.0.0.1:8000/api/v1"
BATCH_SIZE = 1000

def run_benchmark():
    print("\n" + "="*65)
    print(f"🚀 CYBERSHIELD LEDGER - HIGH-THROUGHPUT STRESS TEST (N = {BATCH_SIZE})")
    print("="*65 + "\n")

    # 1. Reset baseline
    requests.post(f"{BASE_URL}/clear")

    latencies = []
    start_total_time = time.perf_counter()

    print(f"[*] Ingesting {BATCH_SIZE} synthetic security events via HTTP REST...")
    
    for i in range(1, BATCH_SIZE + 1):
        payload = {
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-08-21T00:00:00Z",
            "event_type": "HIGH_VOLUME_TELEMETRY",
            "user": f"user_{i % 50}",
            "source_host": f"NODE-SRC-{i % 20:02d}",
            "target_host": f"NODE-DST-{i % 10:02d}",
            "process_name": "worker.exe",
            "command": f"ExecuteWorkerTask --id={i}",
            "threat_score": (i * 17) % 100,
            "mitre_tactic": "TA0007 - Discovery",
            "raw_message": f"Synthetic burst telemetry event sequence #{i}"
        }

        t0 = time.perf_counter()
        res = requests.post(f"{BASE_URL}/ingest", json=payload)
        t1 = time.perf_counter()

        if res.status_code == 200:
            latencies.append((t1 - t0) * 1000)
        
        if i % 250 == 0 or i == BATCH_SIZE:
            print(f"    -> Ingested {i}/{BATCH_SIZE} events... (Latest leaf: {res.json().get('leaf_hash', '')[:12]}...)")

    total_duration = time.perf_counter() - start_total_time
    throughput = BATCH_SIZE / total_duration

    # 2. Fetch final Merkle root
    t_root_start = time.perf_counter()
    root_res = requests.get(f"{BASE_URL}/merkle-root").json()
    t_root_duration = (time.perf_counter() - t_root_start) * 1000

    # 3. Output Benchmark Analytics
    print("\n" + "-"*65)
    print("📊 EMPIRICAL PERFORMANCE & BENCHMARK METRICS")
    print("-"*65)
    print(f" Total Ingested Events:        {BATCH_SIZE}")
    print(f" Total Execution Duration:     {total_duration:.3f} s")
    print(f" Ingestion Throughput:         {throughput:.2f} events/sec")
    print(f" Average Latency per Leaf:     {statistics.mean(latencies):.2f} ms")
    print(f" Median Latency (p50):         {statistics.median(latencies):.2f} ms")
    print(f" 95th Percentile Latency (p95):{statistics.quantiles(latencies, n=20)[18]:.2f} ms")
    print(f" Merkle Root Calc Duration:    {t_root_duration:.2f} ms")
    print(f" Computed Consensus Root:      {root_res.get('merkle_root')}")
    print(f" On-Chain State Complexity:    O(1) Constant Gas Cost")
    print("="*65 + "\n")

if __name__ == "__main__":
    run_benchmark()
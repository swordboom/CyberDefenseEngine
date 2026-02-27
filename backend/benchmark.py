import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx


def run_single_request(client: httpx.Client, base_url: str, payload: dict, headers: dict) -> float:
    start = time.perf_counter()
    response = client.post(f"{base_url}/analyze", json=payload, headers=headers)
    response.raise_for_status()
    return (time.perf_counter() - start) * 1000


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberDefenseEngine /analyze load benchmark")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["X-API-Key"] = args.api_key
    payload = {
        "text": "Urgent: verify your account password now",
        "url": "http://secure-login-update.com/verify",
    }

    latencies: list[float] = []
    started = time.perf_counter()
    with httpx.Client(timeout=10.0) as client:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = [
                executor.submit(run_single_request, client, args.base_url, payload, headers)
                for _ in range(args.requests)
            ]
            for future in as_completed(futures):
                latencies.append(future.result())

    elapsed = time.perf_counter() - started
    rps = args.requests / elapsed if elapsed > 0 else 0.0
    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    print(f"requests={args.requests}")
    print(f"concurrency={args.concurrency}")
    print(f"elapsed_s={elapsed:.3f}")
    print(f"rps={rps:.2f}")
    print(f"latency_ms_avg={statistics.mean(latencies):.2f}")
    print(f"latency_ms_p95={p95:.2f}")
    print(f"latency_ms_max={max(latencies):.2f}")


if __name__ == "__main__":
    main()

"""Interactive HTTP probes for authorized WAF validation.

Created by Paul Penning.
HTTP responses are observations; confirm WAF decisions using WAF logs.

⚠️ For authorized security testing only.
Use only against systems you own or have explicit permission to test. This tool is not intended for malicious use. Use at your own risk.
"""

import csv
import math
import os
from pathlib import Path
import shutil
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4


# Menu option -> (short marker code, display name, query parameter payload).
# Keep probes in one place so individual tests and Run All use the same runner.
TESTS = {
    "1": ("SQLI", "SQL Injection", "1' OR '1'='1"),
    "2": ("PATH", "Path Traversal", "../../../../etc/passwd"),
    "3": ("XSS", "Cross-Site Scripting (XSS)", "<script>alert('XSS')</script>"),
    "4": ("CMD", "Command Injection", "; ls -la"),
}
# Every request, including failed requests and baselines, uses this CSV schema.
FIELDS = (
    "timestamp_utc", "target", "test", "request_number", "marker",
    "http_status", "baseline_status", "observation", "curl_exit_code",
    "remote_ip", "duration_seconds", "error",
)
# Separate curl's generated status/timing output from the response headers.
METADATA_PREFIX = "\nWAFTEST_RESULT\t"


def validate_url(value):
    """Validate a target without changing its path or query string."""
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("URL must not contain whitespace or control characters.")
    try:
        parsed = urlsplit(value)
        # Accessing .port also checks malformed and out-of-range port values.
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid host or port.") from exc
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a complete http:// or https:// URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not supported.")
    if parsed.fragment:
        raise ValueError("Remove the URL fragment (#...).")
    if port is not None and port < 1:
        raise ValueError("Port must be between 1 and 65535.")
    return value


def prompt_targets():
    """Collect up to three distinct targets, retrying invalid URL entries."""
    targets = []
    for number in range(1, 4):
        while True:
            value = input(f"Website {number} URL (blank to skip): ").strip()
            if not value:
                break
            try:
                target = validate_url(value)
            except ValueError as exc:
                print(exc)
                continue
            if target not in targets:
                targets.append(target)
            break
    return targets


def prompt_number(prompt, default, integer=False):
    """Require positive integer counts or finite, nonnegative delay values."""
    while True:
        value = input(f"{prompt} (default {default}): ").strip()
        try:
            number = (int(value) if integer else float(value)) if value else default
            if not math.isfinite(number) or number < (1 if integer else 0):
                raise ValueError
            return number
        except (ValueError, OverflowError):
            print("Enter a positive whole number." if integer else
                  "Enter a finite number of seconds, zero or greater.")


def send_probe(curl_path, target, test, payload, marker, request_number):
    """Send one GET probe and return a report row even if the request fails."""
    # Start with a failure result; change it only after receiving usable metadata.
    result = dict.fromkeys(FIELDS, "")
    result.update(timestamp_utc=datetime.now(timezone.utc).isoformat(),
                  target=target, test=test, request_number=request_number,
                  marker=marker, observation="request failed")
    # Pass an argument list directly to curl without a shell. Payload characters
    # stay request data, and --data-urlencode encodes both query parameters.
    # os.devnull selects /dev/null on Kali and the equivalent device on Windows.
    # Discard the body, capture headers, and append status/IP/timing metadata.
    # Redirects are not followed, so a redirect response is reported as received.
    command = [
        curl_path, "-sS", "-o", os.devnull, "-D", "-",
        "--connect-timeout", "10", "--max-time", "15",
        "--proto", "=http,https",
        "-H", "Accept: */*",
        "-H", "User-Agent: Hoppenbrouwers-WAF-Validation/1.0",
        "--get", "--data-urlencode", f"waf_test_id={marker}",
        "--data-urlencode", f"waf_probe={payload}",
        "-w", METADATA_PREFIX + "%{http_code}\t%{remote_ip}\t%{time_total}\n",
        "--url", target,
    ]
    started = time.monotonic()
    try:
        # The process timeout provides a fallback beyond curl's own timeout.
        # check=False lets us record curl errors and continue with other probes.
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=20,
                                   check=False)
        result["curl_exit_code"] = completed.returncode
        result["error"] = completed.stderr.strip()
        # Use the final delimiter so preceding response headers stay separate.
        headers, separator, metadata = completed.stdout.rpartition(METADATA_PREFIX)
        if separator:
            parts = metadata.strip().split("\t")
            if len(parts) == 3 and parts[0].isdigit():
                result.update(http_status=int(parts[0]), remote_ip=parts[1],
                              duration_seconds=parts[2])
        if completed.returncode == 0 and result["http_status"]:
            result["observation"] = "response received; check WAF logs"
        elif not result["error"]:
            result["error"] = "curl failed or returned no usable HTTP status."
    except FileNotFoundError:
        result["error"] = "curl executable was not found."
    except subprocess.TimeoutExpired:
        result["error"] = "Request exceeded the 20-second process timeout."
    except OSError as exc:
        result["error"] = str(exc)
    # If curl provided no timing, record the elapsed process time instead.
    if not result["duration_seconds"]:
        result["duration_seconds"] = f"{time.monotonic() - started:.3f}"
    return result


def compare_baseline(result, baseline):
    """Describe status differences without claiming a confirmed WAF decision."""
    # The application can also return errors; matching/different HTTP statuses
    # alone do not prove whether the WAF allowed or blocked a request.
    result["baseline_status"] = baseline["http_status"]
    if result["observation"] == "request failed":
        return
    if baseline["observation"] == "request failed":
        result["observation"] = "baseline failed; check WAF logs"
    elif result["http_status"] == baseline["http_status"]:
        result["observation"] = "same status as baseline; check WAF logs"
    else:
        result["observation"] = "different status from baseline; check WAF logs"


def run_tests(curl_path, targets, tests, transactions, interval, run_marker,
              report_directory):
    """Run one baseline per target and the chosen number of each probe.

    Write and flush each result so completed requests survive interruption.
    """
    # Each menu selection gets a separate marker and report within this run.
    batch_marker = f"{run_marker}-{uuid4().hex[:8]}"
    report_directory = Path(report_directory)
    report_directory.mkdir(parents=True, exist_ok=True)
    report_path = report_directory / f"{batch_marker}.csv"
    total = len(targets) * (1 + len(tests) * transactions)
    print(f"Sending {total} requests, including one baseline per target.")
    print(f"Report: {report_path}")
    counts = {"completed": 0, "failed": 0}
    first_request = True
    interrupted = False
    with report_path.open("w", newline="", encoding="utf-8") as report:
        writer = csv.DictWriter(report, fieldnames=FIELDS)
        writer.writeheader()
        report.flush()

        def execute(target, target_number, code, name, payload, number):
            # Pace every request after the first, including target transitions.
            nonlocal first_request
            if not first_request:
                time.sleep(interval)
            first_request = False
            # Include target, test, and sequence for individual log correlation.
            # Keep ANSI display formatting out of markers sent to the server.
            marker = f"{batch_marker}-T{target_number}-{code}-{number:04d}"
            return send_probe(curl_path, target, name, payload, marker, number)

        def record(result):
            # Flush each row promptly so Ctrl+C preserves completed results.
            writer.writerow(result)
            report.flush()
            # These counters track request completion, not WAF block/allow rates.
            failed = result["observation"] == "request failed"
            counts["failed" if failed else "completed"] += 1
            status = result["http_status"] or "unavailable"
            print(f"{result['marker']} | HTTP {status} | {result['observation']}")
            if result["error"]:
                print(f"  {result['error']}")

        try:
            for target_number, target in enumerate(targets, 1):
                print(f"Testing website: {target}")
                # Use the same endpoint and parameter names with harmless data.
                baseline = execute(target, target_number, "BASELINE", "Baseline",
                                   "normal-waf-validation", 1)
                record(baseline)
                # Apply the requested transaction count to every selected test.
                for code, name, payload in tests:
                    for number in range(1, transactions + 1):
                        result = execute(target, target_number, code, name,
                                         payload, number)
                        compare_baseline(result, baseline)
                        record(result)
        except KeyboardInterrupt:
            interrupted = True
            print("\nTesting interrupted. Completed results have been saved.")
    print(f"Summary: {counts['completed']} responses, {counts['failed']} failures.")
    print("Confirm block/allow decisions in WAF logs using the recorded markers.")
    return report_path, counts, interrupted


def main():
    """Collect settings, then run menu selections until exit or interruption."""
    print("""OWASP WAF Test Tool
Created by: Paul Penning | Created on: 2026-10-13
For authorized security testing only.
Use only against systems you own or have explicit permission to test.
""")
    # Support Windows and Linux/Kali using the executable available on PATH.
    curl_path = shutil.which("curl.exe") or shutil.which("curl")
    if not curl_path:
        print("curl was not found. Install curl or add it to PATH before testing.")
        return
    targets = prompt_targets()
    if not targets:
        print("No targets provided. Exiting.")
        return
    transactions = prompt_number("Number of transactions per test", 10, integer=True)
    interval = prompt_number("Delay between requests in seconds", 1.0)
    # UTC timestamps and a random suffix distinguish concurrent script runs.
    run_marker = f"WAFTEST-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid4().hex[:8]}"
    print(f"Your test marker: {run_marker}")
    # Store reports beside the script regardless of the launch directory.
    report_directory = Path(__file__).resolve().parent / "waf_test_results"
    while True:
        print("\n[1] SQL Injection\n[2] Path Traversal\n[3] Cross-Site Scripting (XSS)"
              "\n[4] Command Injection\n[5] Run All Tests\n[6] Exit")
        choice = input("Select an option (1-6): ").strip()
        if choice == "6":
            print("Exiting the program.")
            return
        if choice not in (*TESTS, "5"):
            print("Invalid option. Please select a valid option.")
            continue
        tests = list(TESTS.values()) if choice == "5" else [TESTS[choice]]
        try:
            _, _, interrupted = run_tests(curl_path, targets, tests, transactions,
                                          interval, run_marker, report_directory)
        except OSError as exc:
            print(f"Unable to write the report: {exc}")
            return
        if interrupted:
            return


# Importing this module exposes helpers without prompting or sending requests.
if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting the program.")

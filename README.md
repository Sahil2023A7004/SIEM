# Network Sensing Layer & JA4 Log Shipper

A multi-station network sensing and log shipping pipeline built for the Modular SIEM project. It captures live network traffic, reassembles fragmented TLS ClientHello handshakes, calculates RFC 8701 compliant JA4 client fingerprints, extracts SNI hostnames, caches sessions in RAM, and ships structured JSON logs asynchronously to the SIEM ingestion API.

---

## 1. Architecture Overview

The sensor is decoupled into four stations using a Producer-Consumer pattern to ensure live packet capture never freezes due to HTTP latency or backend lag.

| Station | File | Responsibility |
| :--- | :--- | :--- |
| **Station 1** | `capture.py` | Dual-stack IPv4/IPv6 verification and strict TCP gating. Drops non-TCP traffic. |
| **Station 2** | `ja4.py` | Extracts TCP/IP metadata, reassembles multi-segment MTU TLS ClientHellos, filters GREASE (RFC 8701), computes JA4 fingerprints, extracts SNI hostnames, and caches flows in a bidirectional session table. |
| **Station 3** | `shipper.py` | Thread-safe in-memory buffer (`Queue(maxsize=1000)`). Drops logs non-blocking on overflow and ships JSON via a background daemon thread (`requests.post`). |
| **Station 4** | `main.py` | Master launcher. Binds Scapy `sniff(store=0)` to the pipeline with graceful `Ctrl+C` termination and memory leak protection. |
| **Testing** | `mock_receiver.py` | Standalone zero-dependency HTTP server for testing log shipping independently on port `8431`. |

---

## 2. Ingestion API Contract

- **Endpoint:** `POST /api/v1/logs/ingest` (Configurable via `SIEM_INGEST_URL`)
- **Default Target:** `http://localhost:8431/api/v1/logs/ingest`
- **Source Type:** `network`

### Emitted JSON Schema
Matches the MongoEngine `LogEvent` document model 1:1:

```json
{
  "source_type": "network",
  "protocol": "tcp",
  "source_ip": "2409:40d5:46d:70d:2662:12ed:6d58:c47e",
  "dest_ip": "2001:4860:4827:7700::",
  "source_port": 52924,
  "dest_port": 443,
  "tcp_flags": "PA",
  "packet_size": 496,
  "ja4": "t13d9013h2_c6771aded2ed_7b6eb23b1f16",
  "event_type": "TCP",
  "metadata": {
    "time_to_live": 254,
    "sni": "www.google.com"
  }
}
```

### Key Technical Mechanisms
1. **TCP MTU Reassembly:** Kyber/ML-KEM post-quantum TLS handshakes exceed standard 1500 MTU. Handshakes split across segments are reassembled in memory before computing the JA4 hash.
2. **Stateful Session Caching:** JA4 is computed once during the ClientHello. Subsequent encrypted data packets in the TCP flow retrieve the cached JA4 and SNI in O(1) time using a sorted 4-tuple key.
3. **Decoupled Shipper:** Live packet capture inserts into an in-memory queue (`put_nowait`). The background worker ships batches with a 3-second timeout, ensuring zero packet drops during capture.

---

## 3. Prerequisites & Dependencies

- Python 3.10+
- Linux with root privileges (or Kali Linux VM)
- Required packages:
  ```bash
  pip install scapy requests
  ```

---

## 4. How to Run

### Step 1: Start Mock Receiver (Independent Testing)
```bash
python3 mock_receiver.py
```

### Step 2: Run Network Sensor
```bash
sudo python3 main.py
```

### Step 3: Run Against Remote SIEM Server
```bash
SIEM_INGEST_URL="http://<SERVER_IP>:8431/api/v1/logs/ingest" sudo -E python3 main.py
```

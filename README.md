
# SLPH-MVP

Hybrid Protocol Analysis Framework (HPAF) – MVP Implementation

---

## Overview

SLPH-MVP is a hybrid protocol analysis system designed to infer the structure of unknown or undocumented network protocols.

It combines:

- Network traffic analysis (PCAP parsing, clustering, sequence alignment)
- Dynamic binary tracing (Frida-based instruction tracing)
- Heuristic feature extraction and classification

The system is implemented as a modular pipeline using microservices and message queues.

---

## Architecture

```

Upload (PCAP + Binary)
↓
Ingestion Service (FastAPI)
↓
RabbitMQ (Task Queue)
↓
Correlation Service (Worker)
↓
MongoDB (Results) + MinIO (Artifacts)

````

---

## Components

### Ingestion Service
- Accepts PCAP and binary uploads
- Stores files in MinIO
- Registers project in MongoDB
- Queues analysis task

### Correlation Service
Executes the analysis pipeline:

1. Extracts application-layer payloads from PCAP
2. Clusters messages using LDA
3. Performs sequence alignment (MAFFT)
4. Infers static and variable regions
5. Runs dynamic binary tracing (Frida)
6. Aggregates results into a protocol model

### Tracer
- Hooks `recv`, `recvfrom`, `recvmsg`
- Captures instruction-level execution traces
- Outputs JSONL logs

---

## Tech Stack

- Python (FastAPI, Scapy, sklearn)
- Frida (dynamic tracing)
- MongoDB (metadata storage)
- MinIO (object storage)
- RabbitMQ (task queue)
- Docker (infrastructure)

---

## Prerequisites

- Python 3.9+
- Docker + Docker Compose
- MAFFT (required for sequence alignment)

Install MAFFT:

```bash
sudo apt install mafft
````

---

## Setup

### 1. Clone Repository

```bash
git clone https://github.com/Rakshitchaturvedi/slph-mvp.git
cd slph-mvp
```

---

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Start Infrastructure Services

```bash
docker-compose up -d
```

This starts:

* MongoDB → `localhost:27017`
* MinIO → `http://localhost:9001`
* RabbitMQ → `http://localhost:15672`

Default credentials:

* MinIO: `minioadmin / minioadmin`
* RabbitMQ: `guest / guest`

---

### 4. Start Correlation Service (Worker)

```bash
cd services/correlation_service
python main.py
```

---

### 5. Start Ingestion Service

```bash
(in root folder)
uvicorn services.ingestion_service.main:app --reload --port 8000
```

API available at:

```
http://localhost:8000
```

---

## Usage

### Start Server
```bash
python test_artifacts/echo_server.py
```

### Start Packet Capture
```bash
sudo tcpdump -i lo -w echo.pcap port 12345
```

### Run Client
```bash
python test_artifacts/echo_client.py
```

### Stop capture
Press Ctrl + C in tcpdum
Now you have: echo.pcap

### Upload PCAP + Binary

```bash
curl -X POST "http://localhost:8000/upload" \
  -F "pcap_file=@echo.pcap" \
  -F "binary_file=@test_artifacts/echo_server.py"
```

Response:

```json
{
  "project_id": "...",
  "status": "processing_queued"
}
```

---

## Pipeline Details

Once uploaded:

1. Files stored in MinIO

2. Metadata stored in MongoDB

3. Task published to RabbitMQ

4. Correlation service executes:

   * Payload extraction from PCAP
   * Message clustering (LDA)
   * Sequence alignment (MAFFT)
   * Protocol structure inference
   * Binary execution tracing
   * Instruction frequency aggregation

5. Results stored in MongoDB

---

## Tracer Testing (Optional)

Test dynamic tracing independently.

### Start Echo Server

```bash
python test_artifacts/echo_server.py
```

### Run Tracer

```bash
python tools/fridatracer/frida_tracer.py --output trace.jsonl -- python test_artifacts/echo_server.py
```

### Trigger Traffic

```bash
python test_artifacts/echo_client.py
```

This produces execution traces in `trace.jsonl`.

---

## Output

Results are stored in MongoDB:

Database:

```
slph_projects
```

Collection:

```
projects
```

Each document includes:

* Raw payloads
* Clustered messages
* Inferred protocol structure
* Binary trace summary

---

## Limitations

* No TCP stream reconstruction (packet-level payloads only)
* LDA clustering requires sufficient data volume
* No deep binary analysis (no taint tracking)
* Limited semantic inference
* Designed as a prototype, not a production tool

---

## Summary

SLPH-MVP demonstrates a hybrid approach to protocol analysis by combining:

* Statistical traffic analysis
* Sequence-based structure inference
* Runtime execution tracing

The focus is on building a reproducible, modular analysis pipeline rather than achieving full protocol reconstruction.

---
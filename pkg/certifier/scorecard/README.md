# Scorecard Fetcher Integration with GUAC

This document explains how to use the enhanced GUAC scorecard certifier with flag-based selection between local and API-based scorecard fetching.

## Overview

The GUAC scorecard certifier now supports two different fetcher types:

1. **API Fetcher** (`--scorecard-fetcher-type=api`) - Default
   - Uses the OpenSSF Scorecard REST API to fetch pre-computed results
   - No authentication required
   - Faster and more efficient for large-scale operations

2. **Local Fetcher** (`--scorecard-fetcher-type=local`)
   - Uses the OpenSSF Scorecard library to clone repositories and run checks locally
   - Requires GitHub authentication token
   - More comprehensive but resource-intensive

## Usage Examples

### API-Based Scorecard Fetcher (Default)

```bash
# Use API-based fetcher with default settings (no need to specify --scorecard-fetcher-type=api)
guaccollect scorecard \
  --gql-addr=http://localhost:8080/query \
  --pubsub-addr=nats://localhost:4222 \
  --blob-addr=file:///tmp/guac-blob

# Or explicitly specify the API fetcher
guaccollect scorecard \
  --gql-addr=http://localhost:8080/query \
  --pubsub-addr=nats://localhost:4222 \
  --blob-addr=file:///tmp/guac-blob \
  --scorecard-fetcher-type=api

# Use API-based fetcher with custom settings
guaccollect scorecard \
  --gql-addr=http://localhost:8080/query \
  --pubsub-addr=nats://localhost:4222 \
  --blob-addr=file:///tmp/guac-blob \
  --scorecard-fetcher-type=api \
  --scorecard-api-base=https://api.securityscorecards.dev \
  --scorecard-domain-prefix=github.com \
  --scorecard-http-timeout=60s
```

### Local Scorecard Fetcher

```bash
# Use local scorecard library
guaccollect scorecard \
  --gql-addr=http://localhost:8080/query \
  --pubsub-addr=nats://localhost:4222 \
  --blob-addr=file:///tmp/guac-blob \
  --scorecard-fetcher-type=local
```

## Configuration Options

### Common Options

| Flag | Description | Default |
|------|-------------|---------|
| `--gql-addr` | GraphQL endpoint URL | `http://localhost:8080/query` |
| `--pubsub-addr` | NATS pubsub address | `nats://localhost:4222` |
| `--blob-addr` | Blob storage address | `file:///tmp/guac-blob` |
| `--interval` | Polling interval | `5m` |
| `--service-poll` | Enable polling mode | `true` |

### Scorecard-Specific Options

| Flag | Description | Default |
|------|-------------|---------|
| `--scorecard-fetcher-type` | Fetcher type: `local` or `api` | `api` |
| `--scorecard-api-base` | API base URL (API fetcher only) | `https://api.securityscorecards.dev` |
| `--scorecard-domain-prefix` | Domain prefix for repos (API fetcher only) | `github.com` |
| `--scorecard-http-timeout` | HTTP timeout (API fetcher only) | `30s` |

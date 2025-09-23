# Scorecard Fetcher Integration with GUAC

This document explains how to use the enhanced GUAC scorecard certifier with flag-based selection between local and API-based scorecard fetching.

## Overview

The GUAC scorecard certifier now supports two different fetcher types:

1. **Local Fetcher** (`--scorecard-fetcher-type=local`) - Default
   - Uses the OpenSSF Scorecard library to clone repositories and run checks locally
   - Requires GitHub authentication token
   - More comprehensive but resource-intensive

2. **API Fetcher** (`--scorecard-fetcher-type=api`) - New Feature
   - Uses the OpenSSF Scorecard REST API to fetch pre-computed results
   - No authentication required
   - Faster and more efficient for large-scale operations
   - Based on the `ccs-sentinel-scorecard-fetcher` implementation

## Usage Examples

### Local Scorecard Fetcher (Default)

```bash
# Standard usage with local scorecard library
guaccollect scorecard \
  --gql-addr=http://localhost:8080/query \
  --pubsub-addr=nats://localhost:4222 \
  --blob-addr=file:///tmp/guac-blob \
  --scorecard-fetcher-type=local
```

### API-Based Scorecard Fetcher

```bash
# Use API-based fetcher with default settings
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
| `--scorecard-fetcher-type` | Fetcher type: `local` or `api` | `local` |
| `--scorecard-api-base` | API base URL (API fetcher only) | `https://api.securityscorecards.dev` |
| `--scorecard-domain-prefix` | Domain prefix for repos (API fetcher only) | `github.com` |
| `--scorecard-http-timeout` | HTTP timeout (API fetcher only) | `30s` |

## Environment Variables

The following environment variables can be used instead of command-line flags:

```bash
export GUAC_GQL_ADDR=http://localhost:8080/query
export GUAC_PUBSUB_ADDR=nats://localhost:4222
export GUAC_BLOB_ADDR=file:///tmp/guac-blob
export GUAC_SCORECARD_FETCHER_TYPE=api
export GUAC_SCORECARD_API_BASE=https://api.securityscorecards.dev
export GUAC_SCORECARD_DOMAIN_PREFIX=github.com
export GUAC_SCORECARD_HTTP_TIMEOUT=60s
```

## Comparison: Local vs API Fetcher

| Aspect | Local Fetcher | API Fetcher |
|--------|---------------|-------------|
| **Authentication** | Requires GITHUB_AUTH_TOKEN | No authentication needed |
| **Performance** | Slower (clones repos) | Faster (REST API calls) |
| **Resource Usage** | High (disk, CPU, memory) | Low (network only) |
| **Data Freshness** | Real-time analysis | Pre-computed (may be older) |
| **Rate Limiting** | GitHub API limits | Scorecard API limits |
| **Offline Support** | Limited | None |
| **Customization** | Full control over checks | Limited to API capabilities |

## Architecture Integration

### API Fetcher Flow

1. **Source Query**: GUAC queries GraphQL for source repositories
2. **API Request**: For each repo, fetcher calls OpenSSF Scorecard API
3. **Response Processing**: API response converted to standard GUAC format
4. **Document Creation**: Scorecard data formatted as processor document
5. **Event Publishing**: Document published to NATS for ingestion
6. **Blob Storage**: Document stored in configured blob store
7. **GUAC Ingestion**: guacingest processes the scorecard data

### Error Handling

The API fetcher includes robust error handling:

- **Retry Logic**: Automatic retries with exponential backoff
- **Rate Limiting**: Respects API rate limits and retry-after headers
- **Graceful Degradation**: Continues processing other repos on individual failures
- **Comprehensive Logging**: Detailed logging for troubleshooting

## Migration from Standalone Fetcher

If you're currently using the standalone `ccs-sentinel-scorecard-fetcher`, you can migrate to the integrated GUAC version:

### Before (Standalone)
```bash
# Run standalone fetcher
DB_DSN=postgres://user:pass@host:5432/db ./scorecard-fetcher
```

### After (GUAC Integrated)
```bash
# Run as GUAC certifier
guaccollect scorecard --scorecard-fetcher-type=api
```

### Benefits of Migration

1. **Unified Pipeline**: Integration with GUAC's event-driven architecture
2. **Blob Storage**: Automatic document storage and retrieval
3. **GraphQL Integration**: Direct querying of GUAC's knowledge graph
4. **Event Streaming**: Real-time processing through NATS
5. **Standardized Format**: Consistent data format across all GUAC certifiers

## Troubleshooting

### Common Issues

1. **API Rate Limiting**
   ```bash
   # Increase timeout and add delays
   --scorecard-http-timeout=60s --certifier-latency=1s
   ```

2. **Network Timeouts**
   ```bash
   # Increase HTTP timeout
   --scorecard-http-timeout=120s
   ```

3. **Repository Not Found**
   ```
   Error: repository not found in scorecard database
   ```
   - Not all repositories are available in the OpenSSF Scorecard database
   - Consider using local fetcher for private or newer repositories

4. **Authentication Issues (Local Fetcher)**
   ```bash
   # Ensure GitHub token is set
   export GITHUB_AUTH_TOKEN=your_token_here
   ```

## Performance Tuning

### API Fetcher Optimization

```bash
# Increase batch size for better throughput
--certifier-batch-size=100

# Add artificial latency to respect rate limits
--certifier-latency=500ms

# Use longer polling intervals for large datasets
--interval=30m
```

### Monitoring

Monitor the following metrics:

- API response times
- Rate limit usage
- Error rates
- Processing throughput
- Blob storage usage

## Next Steps

1. **Test the Integration**: Start with small batches to verify functionality
2. **Monitor Performance**: Track API usage and response times
3. **Tune Configuration**: Adjust timeouts and batch sizes based on workload
4. **Scale Horizontally**: Run multiple instances with different intervals if needed

For more information, see the GUAC documentation at https://docs.guac.sh/
# Alerting Guide

Podtrace includes alerting system that sends real-time notifications when critical issues are detected. This guide covers how to configure and use the alerting feature.

## Overview

The alerting system monitors:
- **Resource Limits**: CPU, Memory, and I/O utilization violations (≥80% warning, ≥90% critical, ≥95% emergency)
- **Error Rates**: High connection failure rates and network issues
- **Exporter Failures**: OTLP, Jaeger, and Splunk export failures
- **Fatal Errors**: Application crashes and critical system errors
- **Diagnostic Issues**: Problems detected during diagnostic analysis

## Quick Start

### Enable Alerting

Alerting is disabled by default. Enable it with:

```bash
export PODTRACE_ALERTING_ENABLED=true
```

### Configure Notification Channel

Choose one or more notification channels:

#### Webhook

```bash
export PODTRACE_ALERT_WEBHOOK_URL=https://alerts.example.com/webhook
```

#### Slack

```bash
export PODTRACE_ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
export PODTRACE_ALERT_SLACK_CHANNEL="#alerts"
```

#### Splunk

```bash
export PODTRACE_ALERT_SPLUNK_ENABLED=true
```

### Run Podtrace

```bash
./bin/podtrace -n production my-pod
```

Alerts will be sent automatically when issues are detected.

## Configuration

### Basic Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PODTRACE_ALERTING_ENABLED` | `false` | Enable/disable alerting system |
| `PODTRACE_ALERT_MIN_SEVERITY` | `warning` | Minimum severity to alert (fatal, critical, warning, error) |

### Webhook Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PODTRACE_ALERT_WEBHOOK_URL` | (empty) | Webhook URL for generic HTTP alerts |


### Slack Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PODTRACE_ALERT_SLACK_WEBHOOK_URL` | (empty) | Slack webhook URL |
| `PODTRACE_ALERT_SLACK_CHANNEL` | `#alerts` | Slack channel to send alerts to |


### Splunk Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PODTRACE_ALERT_SPLUNK_ENABLED` | `false` | Enable Splunk alerting |
| `PODTRACE_SPLUNK_ENDPOINT` | (from tracing config) | Splunk HEC endpoint |
| `PODTRACE_SPLUNK_TOKEN` | (from tracing config) | Splunk HEC token |

**Note**: Splunk alerts use the same endpoint as tracing but with `sourcetype=Podtrace:alert` instead of `Podtrace:trace`.

### Advanced Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PODTRACE_ALERT_DEDUP_WINDOW` | `5m` | Time window for alert deduplication |
| `PODTRACE_ALERT_RATE_LIMIT` | `10` | Maximum alerts per minute |
| `PODTRACE_ALERT_HTTP_TIMEOUT` | `10s` | HTTP request timeout |
| `PODTRACE_ALERT_MAX_RETRIES` | `3` | Maximum retry attempts for failed sends |
| `PODTRACE_ALERT_MAX_PAYLOAD_SIZE` | `1048576` | Maximum payload size in bytes (1MB) |

## Alert Severity Levels

Alerts are categorized by severity:

- **Fatal**: Application crashes, system failures requiring immediate attention
- **Critical**: Resource exhaustion (≥90%), emergency conditions (≥95%)
- **Warning**: Resource warnings (≥80%), high error rates, exporter failures
- **Error**: General errors and issues

Filter alerts by severity using `PODTRACE_ALERT_MIN_SEVERITY`:

```bash
# Only alert on critical and fatal issues
export PODTRACE_ALERT_MIN_SEVERITY=critical

# Alert on all issues (warning and above)
export PODTRACE_ALERT_MIN_SEVERITY=warning
```

## Alert Types

### Resource Limit Alerts

Triggered when resource utilization exceeds thresholds:

- **Warning**: ≥80% utilization
- **Critical**: ≥90% utilization
- **Emergency**: ≥95% utilization

**Example Alert**:
```json
{
  "severity": "critical",
  "title": "Resource Limit Critical",
  "message": "Memory utilization: 92% (limit: 500000000 bytes, usage: 460000000 bytes)",
  "source": "resource_monitor",
  "context": {
    "resource_type": "memory",
    "utilization_percent": 92.0,
    "usage_bytes": 460000000,
    "limit_bytes": 500000000
  },
  "recommendations": [
    "Check for memory leaks",
    "Review memory limits",
    "Consider scaling up pod resources"
  ]
}
```

### Error Rate Alerts

Triggered when connection failure rates exceed thresholds:

**Example Alert**:
```json
{
  "severity": "warning",
  "title": "High Connection Failure Rate",
  "message": "Connection failure rate: 15.2% (threshold: 10%)",
  "source": "error_detector",
  "context": {
    "error_count": 45,
    "total_connections": 296,
    "error_rate_percent": 15.2
  },
  "recommendations": [
    "Check network connectivity",
    "Review target service health",
    "Check DNS resolution"
  ]
}
```

### Exporter Failure Alerts

Triggered when trace exporters fail to send data:

**Example Alert**:
```json
{
  "severity": "warning",
  "title": "OTLP Exporter Failure",
  "message": "Failed to export traces to OTLP: connection refused",
  "source": "exporter",
  "context": {
    "exporter": "otlp",
    "endpoint": "http://otel-collector:4318",
    "error": "connection refused"
  },
  "recommendations": [
    "Check OTLP endpoint connectivity",
    "Verify endpoint configuration",
    "Check network connectivity"
  ]
}
```

### Fatal Error Alerts

Triggered when fatal errors occur:

**Example Alert**:
```json
{
  "severity": "fatal",
  "title": "Podtrace Fatal Error",
  "message": "Failed to attach eBPF program to cgroup",
  "source": "logger",
  "context": {
    "cgroup_path": "/sys/fs/cgroup/kubepods/...",
    "error": "permission denied"
  },
  "recommendations": [
    "Check CAP_SYS_ADMIN capability",
    "Verify cgroup path exists",
    "Check Podtrace permissions"
  ]
}
```

## Alert Deduplication

The alerting system automatically deduplicates alerts to prevent alert storms. If the same alert (same severity, source, pod, namespace, and title) is sent within the deduplication window, it will be suppressed.

Configure the deduplication window:

```bash
export PODTRACE_ALERT_DEDUP_WINDOW=5m
```

## Rate Limiting

Rate limiting prevents overwhelming notification systems. By default, a maximum of 10 alerts per minute are sent.

Configure rate limiting:

```bash
export PODTRACE_ALERT_RATE_LIMIT=20
```

## Retry Logic

Failed alert deliveries are automatically retried with exponential backoff:

- Initial retry: 1 second
- Second retry: 2 seconds
- Third retry: 4 seconds
- Maximum backoff: 30 seconds

Configure retries:

```bash
export PODTRACE_ALERT_MAX_RETRIES=5
```

## Examples

### Complete Webhook Setup

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_WEBHOOK_URL=https://alerts.example.com/webhook
export PODTRACE_ALERT_MIN_SEVERITY=warning
export PODTRACE_ALERT_DEDUP_WINDOW=5m
export PODTRACE_ALERT_RATE_LIMIT=10

./bin/podtrace -n production my-pod
```

### Complete Slack Setup

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
export PODTRACE_ALERT_SLACK_CHANNEL="#Podtrace-alerts"
export PODTRACE_ALERT_MIN_SEVERITY=critical

./bin/podtrace -n production my-pod
```

### Splunk Alerts (Reusing Existing Config)

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_SPLUNK_ENABLED=true
export PODTRACE_SPLUNK_ENDPOINT=https://splunk.example.com:8088/services/collector
export PODTRACE_SPLUNK_TOKEN=your-token-here

./bin/podtrace -n production my-pod
```

### Multi-Channel Setup

You can enable multiple channels simultaneously:

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_WEBHOOK_URL=https://pagerduty.example.com/webhook
export PODTRACE_ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
export PODTRACE_ALERT_SLACK_CHANNEL="#alerts"
export PODTRACE_ALERT_SPLUNK_ENABLED=true

./bin/podtrace -n production my-pod
```

## Integration Examples

### PagerDuty Integration

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_WEBHOOK_URL=https://events.pagerduty.com/v2/enqueue
export PODTRACE_ALERT_MIN_SEVERITY=critical
```

Configure PagerDuty to accept the webhook payload format.

### Opsgenie Integration

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_WEBHOOK_URL=https://api.opsgenie.com/v1/json/Podtrace
export PODTRACE_ALERT_MIN_SEVERITY=warning
```

### Custom Alerting System

```bash
export PODTRACE_ALERTING_ENABLED=true
export PODTRACE_ALERT_WEBHOOK_URL=https://your-alerting-system.com/webhook
export PODTRACE_ALERT_HTTP_TIMEOUT=15s
export PODTRACE_ALERT_MAX_RETRIES=5
```

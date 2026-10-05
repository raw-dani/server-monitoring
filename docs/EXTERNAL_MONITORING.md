# External Monitoring & Heartbeat Integration

SHSM integrates seamlessly with external uptime and heartbeat monitoring tools, such as **Uptime Kuma**, **Better Stack**, **Healthchecks.io**, or custom webhook ingestors.

---

## 1. Why External Heartbeats?

If a server experiences complete catastrophic failure (such as total kernel panic, network disconnect, power failure, or VPS hypervisor crash), a self-hosted monitoring system running exclusively on that server cannot send an alert email.

External heartbeats solve this by having SHSM periodically "ping" an external monitoring service. If the external monitor fails to receive a ping within the expected window (e.g. 2 minutes), it alerts the administrator that the server is down.

---

## 2. Configuration

Enable external monitoring in `/etc/shsm/config.yaml`:

```yaml
external_monitoring:
  enabled: true
  provider: "uptime_kuma_push"      # uptime_kuma_push | generic_webhook
  heartbeat_url: "https://kuma.example.com/api/push/<PUSH_TOKEN>"
  interval_seconds: 60              # Heartbeat frequency
  timeout_seconds: 10
  token_file: "/etc/shsm/secrets/external_token"  # Optional bearer token for generic webhook
```

---

## 3. Supported Providers

### 1. Uptime Kuma Push Monitor
- In Uptime Kuma, create a new monitor of type **Push**.
- Copy the provided Push URL (e.g., `https://kuma.example.com/api/push/<PUSH_TOKEN>`).
- Set `external_monitoring.heartbeat_url` to this URL.
- SHSM automatically appends:
  - `?status=up&msg=OK&ping=<LATENCY_MS>`
  - If the server health score degrades below threshold (< 75), SHSM flags the status degraded: `status=down&msg=Degraded+Health`.

### 2. Generic HTTPS Webhook
- Sends an HTTPS POST request containing JSON metadata:
  ```json
  {
    "server_name": "vps-production-01",
    "timestamp": "2026-10-05T04:30:00Z",
    "health_score": 96.5,
    "security_score": 92.0,
    "active_critical_findings": 0,
    "open_findings": 1
  }
  ```
- If `token_file` (or environment variable `SHSM_EXTERNAL_TOKEN`) is configured, requests include:
  `Authorization: Bearer <token>`

---

## 4. Manual Testing & Operations

### Test Heartbeat Connection Manually
Send an immediate test heartbeat to verify network connectivity and token acceptance:
```bash
sudo -u shsm shsm external test
```

### Trigger Scheduled Heartbeat Send
Manually execute the heartbeat routine that runs via systemd timer:
```bash
sudo -u shsm shsm external send
```

### Inspect Heartbeat Timer Status
```bash
systemctl status shsm-external-heartbeat.timer
journalctl -u shsm-external-heartbeat.service -n 20 --no-pager
```

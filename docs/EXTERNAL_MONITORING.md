# External Monitoring & Heartbeat Integration

SHSM integrates seamlessly with external uptime and heartbeat monitoring tools, such as **Uptime Kuma**, **Better Stack**, **Healthchecks.io**, or custom webhook ingestors.

---

## 1. Why External Heartbeats?

If a server experiences complete catastrophic failure (such as total kernel panic, network disconnect, or power failure), a self-hosted monitoring system running exclusively on that server cannot send an alert email.

External heartbeats solve this by having SHSM periodically "ping" an external monitoring service. If the external monitor fails to receive a ping within the expected window (e.g. 2 minutes), it alerts the administrator that the server is down.

---

## 2. Configuration

Enable external monitoring in `/etc/shsm/config.yaml`:

```yaml
external_monitoring:
  enabled: true
  provider: "uptime_kuma_push"      # uptime_kuma_push | generic_webhook
  heartbeat_url: "https://kuma.example.com/api/push/key123"
  interval_seconds: 60              # Heartbeat frequency
  timeout_seconds: 10
  token_file: "/etc/shsm/secrets/external_token"  # Optional bearer token
```

---

## 3. Supported Providers

### 1. Uptime Kuma Push Monitor
- Set up a **Push** monitor in Uptime Kuma.
- Copy the provided URL (e.g., `https://kuma.example.com/api/push/<TOKEN>`).
- Paste into `external_monitoring.heartbeat_url`.
- SHSM appends `?status=up&msg=OK&ping=<LATENCY>` automatically.
- If health score is degraded (< 75), SHSM sets `status=down&msg=Degraded+Health`.

### 2. Generic HTTPS Webhook
- Sends an HTTPS POST request containing JSON metadata:
  ```json
  {
    "server_name": "vps-production-01",
    "timestamp": "2026-10-05T02:30:00Z",
    "health_score": 96.5,
    "security_score": 92.0,
    "active_critical_findings": 0,
    "open_findings": 1
  }
  ```
- If `token_file` (or `SHSM_EXTERNAL_TOKEN`) is provided, requests include:
  `Authorization: Bearer <token>`

---

## 4. Manual Testing

Test the external heartbeat push manually:
```bash
shsm external-check
```
Verify the response status and latency output.

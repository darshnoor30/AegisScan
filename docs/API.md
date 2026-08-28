# Local API

The dependency-free dashboard server exposes a deliberately small same-origin API.

## Health

`GET /api/health`

```json
{"status":"ok","service":"AegisScan","version":"1.0.0"}
```

## Start scan

`POST /api/scans` with `Content-Type: application/json`

```json
{
  "targets": ["127.0.0.1"],
  "ports": "22,80,443,8000-8010",
  "timeout": 0.8,
  "concurrency": 150,
  "environment": "production",
  "asset_criticality": "high",
  "authorized": true,
  "fingerprint": true
}
```

Returns HTTP 202 with a job ID and status URL. Public targets are rejected unless both the request
contains `"allow_public": true` and the server was launched with `AEGISSCAN_ALLOW_PUBLIC=true`.
Allowed environments are `unknown`, `development`, `staging`, and `production`. Allowed
criticalities are `low`, `standard`, `high`, and `critical`.

## Scan status

`GET /api/scans/{job_id}`

Status is `queued`, `running`, `complete`, or `failed`. Complete jobs contain the canonical result.

## Recent history

`GET /api/scans`

Returns up to 20 recent persisted scans, newest first.

## HTML report

`GET /reports/{job_id}.html` or `GET /reports/{scan_id}.html`

All API responses are no-store and include content-type, frame, referrer, permissions, and CSP
protections. Cross-site scan requests are rejected, and at most two dashboard scans run concurrently.

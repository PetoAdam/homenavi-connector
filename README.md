# Homenavi Connector

Local Homenavi integration for Connector / Motionblinds-compatible smart blinds.

## Features

- Local LAN control without cloud dependency
- Native Homenavi device sync through the `connector` protocol
- Best-effort local realtime updates via Motionblinds-style UDP multicast, with polling fallback
- Setup page for gateway host and 16-character Connector API key
- Overview and single-device widgets for blind control
- MQTT HDP bridge for native device state, metadata and commands

## Setup

1. Open the Connector app.
2. Navigate to the About screen.
3. Tap the screen five times to reveal the 16-character local API key.
4. Install the integration and open the setup page.
5. Enter the gateway bridge IP/hostname and API key, then save.

Notes:

- The API key must include the `-` characters exactly as shown in the app, for example `12ab345c-d67e-8f`.
- If you have a separate Connector bridge, the gateway host is its LAN address, not your phone and not an external cloud hostname.
- If you do not have a separate bridge and your blinds are direct Wi-Fi models, enter their LAN IPs as a comma-separated list.
- A polling interval of about `60` seconds is the recommended baseline fallback. When multicast push is available, state updates can arrive earlier without waiting for the next poll.

## Development

- Validate the manifest with `go run ./cmd/validate-manifest`
- Run the backend with `go run ./src/backend/cmd/integration`
- Local Docker development uses [compose/docker-compose.dev.yml](compose/docker-compose.dev.yml):

	`HOMENAVI_ROOT=/path/to/homenavi docker compose -f compose/docker-compose.dev.yml up -d --build`

## Notes

- The integration targets Connector gateways compatible with the Motionblinds local LAN protocol.
- Home Assistant handles Motionblinds primarily as local push over UDP multicast, with polling as fallback. This integration now follows the same general approach on a best-effort basis.
- Pairing is intentionally not implemented; devices already paired in the Connector app are discovered from the gateway.
- The vendor-local workflow is API-key based. A documented third-party email/password auth flow was not found.

# Basic Message Storage

## Description

- v1_0:
    - Uses a middleware wrapper around the existing basicmessage `connections/{id}/send-message` api, and will persist the sent message.
    - Messages between all agents/connections can be fetched via `GET /basicmessages` with optional query params for `connection_id` and `state`.
    - single messages can be deleted via `DELETE /basicmessages/{message_id}`
    - subwallets can disable message storages by setting `extra_settings:{"basicmessage-storage":{"wallet_enabled":false}}` in the body of `/multitenancy/wallet/{wallet_id}`

## Configuration

- No additional configuration required.

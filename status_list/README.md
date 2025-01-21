# Status List Plugin for ACA-Py

This plugin implements [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) and [IETF Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/). The plugin is under active development, please consider this plugin experimental.

## Architecture

### Components
```mermaid
architecture-beta
    group ongov(server)[Ontario Gov]
    group azure(cloud)[Azure Cloud]

    service issuer(server)[Issuer]
    service apim(cloud)[APIM] in azure
    service acapy(server)[ACAPy with Status List Plugin] in ongov
    service askar(database)[Askar] in ongov
    service int_store(disk)[Internal Storage for W3C and IETF Lists] in ongov
    service pub_store(disk)[Public Storage for W3C and IETF Lists] in ongov
    service blob_store(disk)[Azure Blob Storage] in azure
    service azure_cdn(cloud)[Azure Frontdoor and CDN] in azure
    service public(internet)[Public Access]

    issuer:R --> L:apim
    apim:B --> T:acapy
    acapy:B --> T:askar
    acapy:R --> L:int_store
    int_store:R --> L:pub_store
    blob_store:B <-- T:pub_store
    azure_cdn:B <-- T:blob_store
    public:L --> R:azure_cdn
```

### Data Model
```mermaid
erDiagram
    SupportedCredential ||--o{ OID4VCIExchangeRecord : has
    SupportedCredential ||--o{ StatusListDef : has
    SupportedCredential {
        string supported_cred_id PK
    }
    OID4VCIExchangeRecord }o--o{ StatusListCred : "relates to"
    OID4VCIExchangeRecord {
        string exchange_id PK
        string supported_cred_id FK "SupportedCredential.PK"
    }
    StatusListDef ||--o{ StatusListShard : has
    StatusListDef }o--o{ StatusListCred : "relates to"
    StatusListDef {
        string id PK
        string supported_cred_id FK "SupportedCredential.PK"
        string status_purpose
        enum status_message
        int status_size
        int shard_size
        int list_size
        string list_seed
        int list_number
        int list_index
        int next_list_number
    }
    StatusListShard {
        str id PK
        str definition_id FK "StatusListDef.PK"
        str list_number
        str shard_number
        int shard_size
        int status_size
        str status_encoded
        str mask_encoded
    }
    StatusListCred {
        str id PK
        str definition_id FK "StatusListDef.PK"
        str credential_id FK "OID4VCIExchangeRecord.PK"
        str list_number
        str list_index
    }
```

The plugin adds three records to ACA-Py, `StatusListDef`, `StatusListShard` and `StatusListCred`.

### Admin Routes

The Admin API Routes can be found under `/api/docs` of the Admin Server in the `status-list` section.

### How it works

#### Credential Issuance

```mermaid
sequenceDiagram
autonumber

actor user as User
participant holder as Wallet
participant controller as Controller
box ACA-Py
    participant oid4vci as OpenID4VCI Plugin
    participant status_list as Status List Plugin
    participant acapy as ACA-Py Core
end

controller ->> status_list: POST /status-list/status-list-defs
activate status_list
Note over controller, status_list: Create status list definition with supported_cred_id
status_list -->> controller: status list definition created
deactivate status_list

user ->> holder: Scan cred offer
holder ->> oid4vci: credential request (access token)
activate oid4vci

oid4vci ->> acapy: recall cred values
activate acapy
acapy -->> oid4vci: return cred values
deactivate acapy
oid4vci ->> status_list: assign status entries
activate status_list
Note over oid4vci, status_list: (supported_cred_id, exchange_id)
status_list ->> acapy: store status list credential relations
activate acapy
Note over status_list, acapy: (definition_id, credential_id, <br>list_number, list_index)
acapy -->> status_list: relations stored
deactivate acapy
status_list -->> oid4vci: status entries assigned
deactivate status_list
acapy ->> controller: POST /topic/status_list (entry-assigned)

oid4vci ->> acapy: jwt sign
activate acapy
acapy -->> oid4vci: signed cred
deactivate acapy
oid4vci ->> acapy: store exchange result
activate acapy
acapy -->> oid4vci: exchange result stored
deactivate acapy
oid4vci -->> holder: credential response
deactivate oid4vci
acapy ->> controller: POST /topic/oid4vci (issued)
```

#### Status List Assignment

When a new status list definition is created, two status lists are generated simultaneously. The assignment flow outlined below assumes this behavior.

```mermaid
flowchart TD
    START@{ shape: circle, label: "Start" } --> A(Assign entries for supported_cred_id)
    A --> B(Search StatusListDefs)
    B --> C{Next<br>Definition?}
    C -- Yes --> D(Lock list_index get, increment and save)
    D --> E{Is current<br>list full?}
    E -- Yes --> F(Move onto the next list, create a new spare and reset list_index to 0)
    E -- No --> G(Feistel unique random from list_index)
    F --> G
    G --> H(Calculate shard number and index from random number)
    H --> I(Update entry mask)
    I --> J(Return assigned entry)
    J --> END@{ shape: stadium, label: "End" }
```

## Usage

### Configuration

The Plugin expects the following configuration options. These options can either be set by environment variable (`STATUS_LIST_*`) or by plugin config value (`-o status_list.*`).

- `STATUS_LIST_SIZE` or `status_list.list_size`
    - Number of status entries of the status list
- `STATUS_LIST_SHARD_SIZE` or `status_list.shard_size`
    - Number of status entries of each shard
- `STATUS_LIST_BASE_URL` or `status_list.base_url`
    - Base URL of published status lists
- `STATUS_LIST_BASE_DIR` or `status_list.base_dir`
    - Base directory of the local storage
- `STATUS_LIST_PATH_TEMPLATE` or `status_list.path_template`
    - Template string format of status list's sub path

## Contributing

This project is managed using Poetry. To get started:

```shell
poetry install
poetry run pre-commit install
poetry run pre-commit install --hook-type commit-msg
```

### Unit Tests

To run unit tests:

```shell
poetry run pytest tests/
```

### Integration Tests

This plugin includes two sets of integration tests:

- Tests against a minimal OpenID4VCI Client written in Python
- Tests against AFJ + OpenID4VCI Client Package (not complete!)

AFJ has an active PR working on adding support for Draft 11 version of the OpenID4VCI specification. Until that PR is in and available in a release, these tests are incomplete and ignored.

To run the integration tests:

```shell
cd status_list/integration
docker compose build
docker compose run tests
docker compose down -v  # Clean up
```

For Apple Silicon, the `DOCKER_DEFAULT_PLATFORM=linux/amd64` environment variable will be required.

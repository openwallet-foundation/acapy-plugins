# Status List Plugin for ACA-Py

This plugin implements the [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/), a standard for efficiently managing and verifying the status of credentials using bitstring-based lists. It also supports the [IETF Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), which provides a mechanism for maintaining the status of OAuth tokens in a scalable and interoperable manner.

The plugin is designed to facilitate streamlined status management for various use cases, including credential revocation, token expiration, and state tracking. However, as it is still under active development, it should be considered experimental and may undergo significant changes. Feedback and contributions are welcome to help improve its functionality and stability.

## Architecture

### Example Deployment
```mermaid
architecture-beta
    group openshift(server)[OpenShift]
    group azure(cloud)[Azure Cloud]

    service issuer(server)[Issuer]
    service apim(cloud)[APIM] in azure
    service acapy(server)[ACAPy with Status List Plugin] in openshift
    service askar(database)[Askar] in openshift
    service int_store(disk)[Internal Storage for W3C and IETF Lists] in openshift
    service pub_store(disk)[Public Storage for W3C and IETF Lists] in openshift
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

The plugin adds three records to ACA-Py, `StatusListDef`, `StatusListShard` and `StatusListCred`.

```mermaid
erDiagram
    SupportedCredential ||--o{ OID4VCIExchangeRecord : "1:n"
    SupportedCredential ||--o{ StatusListDef : "1:n"
    SupportedCredential {
        string supported_cred_id PK
    }
    OID4VCIExchangeRecord }o--o{ StatusListCred : "1:n"
    OID4VCIExchangeRecord {
        string exchange_id PK
        string supported_cred_id FK "SupportedCredential.PK"
    }
    StatusListDef ||--o{ StatusListShard : "1:n"
    StatusListDef ||--o{ StatusListCred : "1:n"
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
    START((Start)) --> A(Assign entries for supported_cred_id)
    A --> B(Search StatusListDefs)
    B --> C{Next Definition?}
    C -- Yes --> D(Lock list_index, increment, and save)
    D --> E{Is current list full?}
    E -- Yes --> F(Move to next list<br>Generate spare list<br>Reset list_index to 0)
    E -- No --> G(Generate unique random using Feistel permutation)
    F --> G
    G --> H(Calculate shard number and index from random number)
    H --> I(Update entry mask)
    I --> J(Return assigned entry)
    J --> END((End))
```

#### Performance Considerations

- **Spare List**  
    The plugin maintains a spare status list as a backup to ensure seamless transitions. When the current status list becomes full, the plugin automatically switches to the spare list. Simultaneously, it generates a new spare list in the background, ensuring there is always a backup available and minimizing downtime.

- **Sharding**  
    Sharding is used to optimize performance and manage data efficiently by dividing it into smaller segments. 
    - **Single bit per record**: Each record uses one bit, minimizing space but limiting functionality.  
    - **All bits per record**: All bits are allocated per record, allowing more granular tracking or states.  
    - **Configurable number of bits per record**: The plugin allows flexibility to balance between space efficiency and the need for additional functionality.

- **Deterministic Randomization**  
    A Feistel permutation algorithm is employed with a unique seed assigned to each status list. This ensures that randomization is deterministic and reproducible, reducing collisions and maintaining consistent performance.

- **Entry Lock and Release**  
    The `list_index` serves as the single access point for assignments. Instead of locking the entire assignment process, which could lead to performance bottlenecks, the plugin implements incremental locking. This ensures that only the necessary portion of the operation is locked, improving concurrency and reducing delays.


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


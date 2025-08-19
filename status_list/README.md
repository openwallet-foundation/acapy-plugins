# Status List Plugin for ACA-Py

This plugin implements the [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/), a standard for efficiently managing and verifying credential statuses using bitstring-based lists. It also supports the [IETF Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), enabling scalable and interoperable OAuth token status management.

Designed for streamlined status tracking, the plugin facilitates credential revocation, token expiration, and other state management use cases. As it remains under active development, it is considered experimental and subject to change. Feedback and contributions are encouraged to enhance its functionality and stability.

## Architecture

### Example Deployment

```mermaid
graph TD;
    subgraph OpenShift [OpenShift]
        acapy[ACAPy with Status List Plugin]
        askar[Askar Database]
        int_store[Internal Storage for W3C & IETF Lists]
        pub_store[Public Storage for W3C & IETF Lists]
    end

    subgraph Azure Cloud [Azure Cloud]
        apim[APIM]
        blob_store[Azure Blob Storage]
        azure_cdn[Azure Frontdoor & CDN]
    end

    issuer[Issuer] -->|R| apim
    apim -->|B| acapy
    acapy -->|B| askar
    acapy -->|R| int_store
    int_store -->|R| pub_store
    pub_store -->|T| blob_store
    blob_store -->|T| azure_cdn
    public[Public Access] -->|L| azure_cdn
```

### Data Model

The plugin adds three records to ACA-Py, `StatusListDef`, `StatusListShard` and `StatusListCred`.

```mermaid
erDiagram
    StatusListDef ||--o{ StatusListShard : "1:n"
    StatusListDef ||--o{ StatusListCred : "1:n"

    StatusListDef {
        string id PK
        string supported_cred_id FK
        string status_purpose
        list status_message
        int status_size
        int shard_size
        int list_size
        string list_seed
        int list_number
        int list_index
        int next_list_number
        list list_numbers
    }

    StatusListShard {
        string id PK
        string definition_id FK "StatusListDef.PK"
        string list_number
        string shard_number
        int shard_size
        int status_size
        string status_encoded
        string mask_encoded
    }

    StatusListCred {
        string id PK
        string definition_id FK "StatusListDef.PK"
        string credential_id FK
        string list_number
        string list_index
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
Note over controller, status_list: Create status list definition<br>with supported_cred_id
status_list -->> controller: Status list definition created
deactivate status_list

user ->> holder: Scan credential offer
holder ->> oid4vci: Credential request (access token)
activate oid4vci

oid4vci ->> acapy: Recall credential values
activate acapy
acapy -->> oid4vci: Return credential values
deactivate acapy

oid4vci ->> status_list: Assign status entries
activate status_list
Note over oid4vci, status_list: (supported_cred_id, exchange_id)

status_list ->> acapy: Store status list credential relations
activate acapy
Note over status_list, acapy: (definition_id, credential_id,<br>list_number, list_index)
acapy -->> status_list: Relations stored
deactivate acapy

status_list -->> oid4vci: Status entries assigned
deactivate status_list
acapy ->> controller: POST /topic/status_list (entry-assigned)

oid4vci ->> acapy: JWT sign
activate acapy
acapy -->> oid4vci: Signed credential
deactivate acapy

oid4vci ->> acapy: Store exchange result
activate acapy
acapy -->> oid4vci: Exchange result stored
deactivate acapy

oid4vci -->> holder: Credential response
deactivate oid4vci

acapy ->> controller: POST /topic/oid4vci (issued)
```

#### Status List Assignment

When a new status list definition is created, two status lists are generated simultaneously. The assignment flow outlined below assumes this behavior.

```mermaid
flowchart TD
    START((Start)) --> A[Search StatusListDefs for supported_cred_id]

    A --> B{Definitions Found?}
    B -- No --> END((End))

    B -- Yes --> C{List Full?}

    C -- Yes --> D[Move to Next List<br>& Create Spare]
    C -- No --> E[Generate Unique Random Index with Feistel]

    D --> E
    E --> F[Locate Shard<br>& Assign Entry]

    F --> G{More Definitions?}
    G -- Yes --> C
    G -- No --> H[Return Assigned Entries]

    H --> END((End))
```

#### Performance Considerations

- **Spare List**  
  The plugin maintains a spare status list to ensure seamless transitions. When the current list is full, it automatically switches to the spare while generating a new one in the background. This guarantees continuous availability and minimizes downtime.

- **Sharding**  
  Sharding improves performance by dividing data into smaller, manageable segments. The plugin supports configurable bits per shard, allowing a balance between space efficiency and functionality.

- **Deterministic Randomization**  
  A Feistel permutation algorithm, seeded uniquely for each status list, ensures deterministic and reproducible randomization. This reduces collisions and maintains consistent performance.

- **Entry Locking & Concurrency**  
  The `list_index` serves as the access point for assignments. Instead of locking the entire process—risking performance bottlenecks—the plugin uses **incremental locking**, ensuring only necessary operations are locked. This improves concurrency and reduces delays.

## Usage

### Configuration

The plugin requires the following configuration options, which can be set either as environment variables (`STATUS_LIST_*`) or as plugin configuration values (`-o status_list.*`).

| **Environment Variable** | **Plugin Config Option** | **Description**                                                                                           |
| ------------------------ | ------------------------ | --------------------------------------------------------------------------------------------------------- |
| `STATUS_LIST_SIZE`       | `status_list.list_size`  | Number of status entries in each status list.                                                             |
| `STATUS_LIST_SHARD_SIZE` | `status_list.shard_size` | Number of status entries in each shard.                                                                   |
| `STATUS_LIST_PUBLIC_URI` | `status_list.public_uri` | Template URI for published status lists with placeholders like {tenant_id} and {list_number}.             |
| `STATUS_LIST_FILE_PATH`  | `status_list.file_path`  | Template local file path for published status lists with placeholders like {tenant_id} and {list_number}. |

### Unit Tests

To run unit tests:

```shell
poetry run pytest tests/
```

### Integration Tests

To run integration tests, execute the following commands:

```shell
cd integration
docker compose build
docker compose up
```

## Contributing

This project is managed using Poetry. To get started:

```shell
poetry install
poetry run pre-commit install
poetry run pre-commit install --hook-type commit-msg
```

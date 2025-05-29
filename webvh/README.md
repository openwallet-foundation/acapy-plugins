# DID WebVH Plugin

## Description

This plugin provides support for the webvh did method. It provides a controller role that interacts with a did webvh server to resolve and create dids, and a witness role that interacts with the did controller to sign did registrations and updates.

## Architecture

```mermaid
graph TD;
    subgraph ACAPY [ACAPY]
        witness[Witness Tenant]
        controller[Controller Tenant]
    end
    
    
    server[WebVH Server]
    
    controller <-->|DID Registrations| witness
    controller -->|W| server
```

### Components
 - `server` - The server component is responsible for handling requests from the did controller and witness components. It is responsible for verifying the upload requests are signed by proof a trusted source and hosting the did.json and did.jsonl files.
 - `controller` - The controller is the agent or tenant that is responsible for the did. It can create and update webvh dids and anoncreds objects and interact with other agents. The controller does not have the ability to sign with the key that is verified by the server, and needs to get a proof from an agent which does have the correct key(s).
- `witness` - The witness is the agent or tenant that is responsible for signing requests from the controller. The witness has the ability to sign with the key that is verified by the server, and can provide a proof to the controller that it is a trusted source. It can also create dids and anoncreds objects itself and act as a controller by self signing the upload requests with the server.

#### Server
The server used by this plugin is located at [DIF](https://github.com/decentralized-identity/didwebvh-server-py). For a witness signature to be approved, the witness key needs to be registered as a `known-witness` by the server administration. It will only allow dids to be created where the original request is signed by a `known-witness`. After the initial did is created the update key from the controller is obtained from the original request and stored by the server. This update key must be used in the initial log entry.

## Flow

### Creating a new DID
```mermaid
sequenceDiagram
    participant WebVH Server
    participant Controller Tenant
    participant Witness Tenant
    Controller Tenant->>WebVH Server: Request a DID location.
    WebVH Server->>Controller Tenant: Provide a Data Integrity Proof configuration.
    Controller Tenant->>Controller Tenant: Create new update key.
    Controller Tenant->>Controller Tenant: Create new verification method.
    Controller Tenant->>Controller Tenant: Create DID document and sign with update key.
    Controller Tenant->>Witness Tenant: Request registration signature.
    Witness Tenant->>Witness Tenant: Verify and sign DID registration.
    Witness Tenant->>Controller Tenant: Return approved DID registration.
    Controller Tenant->>WebVH Server: Send approved DID registration.
    WebVH Server->>WebVH Server: Verify approved DID registration.
    Controller Tenant->>Controller Tenant: Generate preliminary DID log entry.
    Controller Tenant->>Controller Tenant: Transform and sign initial DID log entry.
    Controller Tenant->>WebVH Server: Send initial DID log entry.
    WebVH Server->>WebVH Server: Verify initial DID log entry & publish DID.
```

## Configuration

The first step is to configure the plugin for your wallet / subwallet. You can configure it as a Witness or a Controller.
The configuration endpoint takes the following parameters:
 - auto_attest - If true the witness will automatically sign any requests from the controller. If false the witness will need to sign the requests manually.
 - server_url - The url of the server that the witness is using.
 - witness - If true the agent will be setup as a witness agent.
 - witness_key - If a public multikey is provided it will be used instead as the witness signing key.
 - witness_invitation - An invitation provided by a witness.

A Witness will be able to self witness transactions and also act as a Controller. 
A Controller will need a Witness connection to witness it's transactions.

Controllers create DIDs, Witness approve DID registrations and updates.

### Configure a Witness instance

To configure a witness, you need to provide the webvh server url. 
The witness key that is used by the server to authenticate any new dids.

`POST /did/webvh/configuration`
```json
{
    "server_url": "https://example.com",
    "witness": true
}
```

In the response, you will get the public multikey value of the witness. This key must then be registered as a known-witness on the webvh server instance.
You can then create a witness invitation.

`POST /did/webvh/witness/invitations`
```json
{
  "alias": "<alias for the remote controller>",
  "label": "<label for the witness service>"
}
```

In the response, you will get the `invitation_url` which can be forwarded to a controller for its configuration.

### Configure a Controller instance

To configure a controller, you need to provide the webvh server url and a witness invitation,

`POST /did/webvh/configuration`
```json
{
    "server_url": "https://example.com",
    "witness_invitation": "<invitation_url>"
}
```

You should get a status success response and the controller logs should say `Connected to witness agent`

### Creating a DID

When creating a did, you need to provide at the minimum a namespace. An identifier can optionally be provided otherwise a random uuid will be generated.

The resulting did will use these values as such:
`did:webvh:<SCID>:<server_url_domain>:<namespace>:<identifier>`

Given a `server_url` of `https://example.com`, a full example for the `demo` `namespace` and the `01` `identifier` would look like:
`did:webvh:<SCID>:example.com:demo:01`

The parameters values can be opted out to their default.

`POST /did/webvh/controller/create`
```json
{
  "options": {
    "identifier": "01",
    "namespace": "demo"
  }
}
```

 - identifier - The identifier for the did. If this isn't provided it will be a randomly generated uuid.
 - namespace - This is required and is the root identifier for the did.
 - parameters - This is an optional object that can be used to set the did to be portable or prerotated. If portable is true the did will be able to be moved to another server. If prerotation is true the did will be able to be rotated by the controller.

#### Auto attest response

This setting should be used with caution as it will automatically sign any requests from the controller. If you are using this setting it should be for testing purposes, or you should be sure any agent that creates a connection with the witness agent is trusted.

Response - Unless there's a problem connecting with the witness or server you should get a success response with the did document.
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/ns/cid/v1"
  ],
  "id": "did:webvh:{SCID}:example.com:demo:01",
  "authentication": [
    "did:webvh:{SCID}:example.com:demo:01#z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
  ],
  "assertionMethod": [
    "did:webvh:{SCID}:example.com:demo:01#z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
  ],
  "verificationMethod": [
    {
      "id": "did:webvh:{SCID}:example.com:demo:01#z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4",
      "type": "Multikey",
      "controller": "did:webvh:{SCID}:example.com:demo:01",
      "publicKeyMultibase": "z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
    }
  ]
}
```

#### Manual attest response

```json
{
  "status": "pending",
  "message": "The witness is pending."
}
```

Witness get pending registrations - `GET /did/webvh/witness/registrations`
```json
{
  "results": [
    {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      "id": "did:web:example.com:demo:01",
      "verificationMethod": [
        {
          "id": "did:web:example.com:demo:01#z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4",
          "type": "Multikey",
          "controller": "did:web:example.com:demo:01",
          "publicKeyMultibase": "z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
        }
      ],
      "authentication": [
        "did:web:example.com:demo:01#z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
      ],
      "assertionMethod": [
        "did:web:example.com:demo:01#z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
      ],
      "proof": [
        {
          "type": "DataIntegrityProof",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:key:z6MkkiMtuEqx8NJcJTTWANmwfpAxZM54jy9Sv867xCN63tpT#z6MkkiMtuEqx8NJcJTTWANmwfpAxZM54jy9Sv867xCN63tpT",
          "cryptosuite": "eddsa-jcs-2022",
          "expires": "2025-02-20T22:43:40+00:00",
          "domain": "example.com",
          "challenge": "6c0bbc23-be56-5f35-b873-3313c33b319b",
          "proofValue": "z9T5HpCDZVZ1c3LgM5ctrYPm2erJR8Ww9o369577beiHc4Dz49See8t78VioPDt76AbRP7r2DnesezY4dBxYTVQ7"
        }
      ]
    }
  ]
}
``` 
Gets a list of pending did docs that need to be attested. 

Witness - Attest a did doc - `POST /did/webvh/witness/registrations?id=did:web:example.com:demo:01`
```json
{
  "status": "success",
  "message": "Witness successful."
}
```

Controller - The controller gets a message `Received witness response: attested` and will finish creating the did. The did should now be resolvable and available in local storage.

### Updating a DID

When updating a DID, you will usually modify the webvh parameters, add/remove a verification method or edit the services.

#### Updating the verification methods

`POST /did/webvh/controller/verification-methods`
```json
{
    "type": "Multikey",
    "relationships": [
        "authentication",
        "assertionMethod"
    ]
}
```

 - `id` - An optional key id to use, defaults to a public multikey or jwk thumbprint depending on the type.
 - `type` - The key representation in the DID document, can be `Multikey` or `JsonWebKey`.
 - `multikey` - Optionally use an existing local keypair. Otherwise create a new one.
 - `relationships` - Add the relationships for this key. Refer to the DID core specification for more information about relationships.
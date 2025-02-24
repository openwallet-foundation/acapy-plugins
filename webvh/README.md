# did:webvh Plugin

## Description

This plugin provides support for the webvh did method. It provides a controller role that interacts with a did webvh server to resolve and create dids, and a witness role that interacts with the did controller to sign did requests.

### Components
 - `server` - The server component is responsible for handling requests from the did controller and witness components. It is responsible for verifying the upload requests are signed by proof a trusted source and hosting the did.json and did.jsonl files.
 - `controller` - The controller is the agent that is responsible for the did. It can create and update webvh dids and anoncreds objects and interact with other agents. The controller does not have the ability to sign with the key that is verified by the server, and needs to get a proof from an agent which does have the correct key(s).
- `witness` - The witness is the agent that is responsible for signing requests from the controller. The witness has the ability to sign with the key that is verified by the server, and can provide a proof to the controller that it is a trusted source. It can also create dids and anoncreds objects itself and act as a controller by self signing the upload requests with the server.

#### Server
The server currently used by the plugin is located at https://github.com/decentralized-identity/didwebvh-server-py. The server currently contains a single public multikey that is created from the witness agent. It will only allow dids to be created where the original request is signed by that key. After the initial did is created the public multikey from the controller is obtained from the original request and stored by  the server. Any updates to the did must be signed by the controller key.
Other implementations of the server are very much possible, but any servers the use this plugin much have the same API and verification process.

## Configuration

### Create the witness signing key
The first thing to do is setup the witness key that is used by the server to authenticate any new dids. In the witness agent it is identified using a key id (kid) `webvh:{server domain}@witnessKey`. You can create the key manually or it will be created automatically when using the `POST /did/webvh/configuration` endpoint.

Witness - `POST /did/webvh/configuration`
```json
{
    "auto_attest": true,
    "server_url": "https://id.test-suite.app",
    "witness": true
}
```
 - auto_attest - If true the witness will automatically sign any requests from the controller. If false the witness will need to sign the requests manually.
 - server_url - The url of the server that the witness is using.
 - witness - If true the agent will be setup as a witness agent.
 - witness_key - If a public multikey is provided it will be used instead as the witness signing key.

### Connect the witness and controller agents

Create an invitation from the witness agent and accept it from the controller agent.

Witness - `POST /out-of-bound/create-invitation`
```json
{
  "handshake_protocols": [
    "https://didcomm.org/didexchange/1.1"
  ]
}
```
This is the most basic invitation that can be created. It is using didexchange 1.1 as the handshake protocol. 

Response
```json
{
  "state": "initial",
  "trace": false,
  "invi_msg_id": "e66babc0-420c-4d77-8f9b-82a3400eda78",
  "oob_id": "7eea7ce9-4dbe-4b72-bb4d-af24c16d77a0",
  "invitation": {
    "@type": "https://didcomm.org/out-of-band/1.1/invitation",
    "@id": "e66babc0-420c-4d77-8f9b-82a3400eda78",
    "label": "webvh-witness",
    "handshake_protocols": [
      "https://didcomm.org/didexchange/1.1"
    ],
    "services": [
      {
        "id": "#inline",
        "type": "did-communication",
        "recipientKeys": [
          "did:key:z6MkqPPz5BSZrPr3se95qMToWeMa4ExeK9hu7JNfxnHtP7WB#z6MkqPPz5BSZrPr3se95qMToWeMa4ExeK9hu7JNfxnHtP7WB"
        ],
        "serviceEndpoint": "http://localhost:3000"
      }
    ]
  },
  "invitation_url": "http://localhost:3000?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJlNjZiYWJjMC00MjBjLTRkNzctOGY5Yi04MmEzNDAwZWRhNzgiLCAibGFiZWwiOiAid2Vidmgtd2l0bmVzcyIsICJoYW5kc2hha2VfcHJvdG9jb2xzIjogWyJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLzEuMSJdLCAic2VydmljZXMiOiBbeyJpZCI6ICIjaW5saW5lIiwgInR5cGUiOiAiZGlkLWNvbW11bmljYXRpb24iLCAicmVjaXBpZW50S2V5cyI6IFsiZGlkOmtleTp6Nk1rcVBQejVCU1pyUHIzc2U5NXFNVG9XZU1hNEV4ZUs5aHU3Sk5meG5IdFA3V0IjejZNa3FQUHo1QlNaclByM3NlOTVxTVRvV2VNYTRFeGVLOWh1N0pOZnhuSHRQN1dCIl0sICJzZXJ2aWNlRW5kcG9pbnQiOiAiaHR0cDovL2xvY2FsaG9zdDozMDAwIn1dfQ"
}
```
The controller will use the base64 encoded invitation_url to accept the invitation. In an application this could be provided as a QR code or a deep link.

The connection is identified in the controller by an alias. You are able to set this up manually or via command line. The easiest way is by providing it when configuring the controller.

Controller - `POST /did/webvh/configuration`
```json
{
    "server_url": "https://id.test-suite.app",
    "witness": false,
    "witness_invitation": "http://localhost:3000?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJlNjZiYWJjMC00MjBjLTRkNzctOGY5Yi04MmEzNDAwZWRhNzgiLCAibGFiZWwiOiAid2Vidmgtd2l0bmVzcyIsICJoYW5kc2hha2VfcHJvdG9jb2xzIjogWyJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLzEuMSJdLCAic2VydmljZXMiOiBbeyJpZCI6ICIjaW5saW5lIiwgInR5cGUiOiAiZGlkLWNvbW11bmljYXRpb24iLCAicmVjaXBpZW50S2V5cyI6IFsiZGlkOmtleTp6Nk1rcVBQejVCU1pyUHIzc2U5NXFNVG9XZU1hNEV4ZUs5aHU3Sk5meG5IdFA3V0IjejZNa3FQUHo1QlNaclByM3NlOTVxTVRvV2VNYTRFeGVLOWh1N0pOZnhuSHRQN1dCIl0sICJzZXJ2aWNlRW5kcG9pbnQiOiAiaHR0cDovL2xvY2FsaG9zdDozMDAwIn1dfQ"
}
```
You should get a status success response and the controller logs should say `Connected to witness agent`

### Auto attest

This setting should be used with caution as it will automatically sign any requests from the controller. If you are using this setting it should be for testing purposes, or you should be sure any agent that creates a connection with the witness agent is trusted.

Controller - `POST /did/webvh/create`
```json
{
  "options": {
    "identifier": "accounting",
    "namespace": "finance",
    "parameters": {
      "portable": false,
      "prerotation": false
    }
  }
}
```
 - identifier - The identifier for the did. If this isn't provided it will be a randomly generated uuid.
 - namespace - This is required and is the root identifier for the did.
 - parameters - This is an optional object that can be used to set the did to be portable or prerotated. If portable is true the did will be able to be moved to another server. If prerotation is true the did will be able to be rotated by the controller.

Response - Unless there's a problem connecting with the witness or server you should get a success response with the did document.
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:webvh:QmQ3m3nAL8Ds7bpnHHbiPZsSs9x6RmMJXomNYHgMrmghnU:id.test-suite.app:finance:accounting",
  "authentication": [
    "did:webvh:QmQ3m3nAL8Ds7bpnHHbiPZsSs9x6RmMJXomNYHgMrmghnU:id.test-suite.app:finance:accounting#key-01"
  ],
  "assertionMethod": [
    "did:webvh:QmQ3m3nAL8Ds7bpnHHbiPZsSs9x6RmMJXomNYHgMrmghnU:id.test-suite.app:finance:accounting#key-01"
  ],
  "verificationMethod": [
    {
      "id": "did:webvh:QmQ3m3nAL8Ds7bpnHHbiPZsSs9x6RmMJXomNYHgMrmghnU:id.test-suite.app:finance:accounting#key-01",
      "type": "Multikey",
      "controller": "did:webvh:QmQ3m3nAL8Ds7bpnHHbiPZsSs9x6RmMJXomNYHgMrmghnU:id.test-suite.app:finance:accounting",
      "publicKeyMultibase": "z6Mknsk9KAs7UofpuZsuSzBkmxZjo63WRwAAj1mnifkVLhqh"
    }
  ]
}
```

### Manual attest

Controller - Create did:webvh same as above

```json
{
  "status": "pending",
  "message": "The witness is pending."
}
```

Witness get pending - `GET /did/webvh/pending`
```json
{
  "results": [
    {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      "id": "did:web:id.test-suite.app:finance:cfbac7a9-0e0c-4bd8-af71-05e33f9e47a5",
      "verificationMethod": [
        {
          "id": "did:web:id.test-suite.app:finance:cfbac7a9-0e0c-4bd8-af71-05e33f9e47a5#key-01",
          "type": "Multikey",
          "controller": "did:web:id.test-suite.app:finance:cfbac7a9-0e0c-4bd8-af71-05e33f9e47a5",
          "publicKeyMultibase": "z6Mkv4ZvmGpzfkxH9xvNq5mA3zwZoHuBisiQUyfCgXCfHeh4"
        }
      ],
      "authentication": [
        "did:web:id.test-suite.app:finance:cfbac7a9-0e0c-4bd8-af71-05e33f9e47a5#key-01"
      ],
      "assertionMethod": [
        "did:web:id.test-suite.app:finance:cfbac7a9-0e0c-4bd8-af71-05e33f9e47a5#key-01"
      ],
      "proof": [
        {
          "type": "DataIntegrityProof",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:key:z6MkkiMtuEqx8NJcJTTWANmwfpAxZM54jy9Sv867xCN63tpT#z6MkkiMtuEqx8NJcJTTWANmwfpAxZM54jy9Sv867xCN63tpT",
          "cryptosuite": "eddsa-jcs-2022",
          "expires": "2025-02-20T22:43:40+00:00",
          "domain": "id.test-suite.app",
          "challenge": "6c0bbc23-be56-5f35-b873-3313c33b319b",
          "proofValue": "z9T5HpCDZVZ1c3LgM5ctrYPm2erJR8Ww9o369577beiHc4Dz49See8t78VioPDt76AbRP7r2DnesezY4dBxYTVQ7"
        }
      ]
    }
  ]
}
``` 
Gets a list of pending did docs that need to be attested. 

Witness - Attest a did doc - `POST /did/webvh/attest?id=did:web:id.test-suite.app:finance:cfbac7a9-0e0c-4bd8-af71-05e33f9e47a5`
```json
{
  "status": "success",
  "message": "Witness successful."
}
```

Controller - The controller gets a message `Received witness response: attested` and will finish creating the did. The did should now be resolvable and available in local storage.
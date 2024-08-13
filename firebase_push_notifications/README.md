# Firebase Push Notifications

## Description

Only to be used with a mediator agent.

Allows mobile agents to send firebase tokens to the mediator service. The mediator service creates a connection with the firebase server and will relay push notifications to the mobile agent on mediator forwarding events on the event_bus.

### Initialization

``` mermaid
sequenceDiagram
participant Mobile
participant Mediator
Note left of Mobile: Logs In
Note left of Mobile: Checks if already registered
Mobile->>Mediator: Do you support firebase protocol?
Mediator->>Mobile: No
Note left of Mobile: Do Nothing
Mediator->>Mobile: Yes
Note left of Mobile: Open notification Permission Modal
Mobile->>Mobile: User says "not now"
Note left of Mobile: Close Modal and set user denied to true
Mobile->>Mobile: User says "Allow"
Mobile->>Mediator: Send device token
Note right of Mediator: Save device token for conenction
Mobile->>Mobile: OS permissions popup
Note left of Mobile: Approve or deny OS level permission
```

### New Message

``` mermaid
sequenceDiagram
participant Agent (Faber)
participant Mediator
participant Mobile (Alice)
participant Firebase
Note left of Agent (Faber): Wants to send message to Mobile (Alice)
Agent (Faber)->>Mediator: Message
Mediator->>Mobile (Alice): Message
Mediator->>Mediator: Receives Forwarding event in aca-py
Note right of Mediator: Get device token for connection
Mediator->>Mediator: token is blank or None
Note right of Mediator: Do nothing
Mediator->>Mediator: message sent withing 'n' minutes
Note right of Mediator: Do nothing
Mediator->>Mediator: Token exists
Mediator->>Firebase: Request: Send OS notification to token
Firebase->>Mobile (Alice): Sends OS notification
```

### Disable/Enable

``` mermaid
sequenceDiagram
participant Mobile
participant Mediator
Mobile->>Mediator: Sends blank token
Note right of Mediator: Saves blank token (disabled)
Mobile->>Mediator: Sends device token
Note right of Mediator: Saves device token (enabled)
```

## Configuration

To use the push notification protocol plugin you must have a firebase project to send the notifications to and a service account json file with `Firebase Service Management Service Agent` roles.

In the project .env file you need to supply the information in the `Firebase Plugin Configuration` section.

```bash
USE_FIREBASE_PLUGIN=true
FIREBASE_PROJECT_ID=287275049656
FIREBASE_NOTIFICATION_TITLE=You have important information in your digital wallet
FIREBASE_NOTIFICATION_BODY=Please open your wallet
FIREBASE_SERVICE_ACCOUNT={ flattend service account json }
```

- `FIREBASE_PROJECT_ID` can be found in the firebase console
- `FIREBASE_NOTIFICATION_TITLE` and `FIREBASE_NOTIFICATION_BODY` is the information displayed in the push notification

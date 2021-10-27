# Aca-py Eventbus messages

Aca-py eventbus has several different possible events which subscribers will be notified of.
The kafka_queue plugin provides configuration to subscribe a kafka producer to specific webhook
events and the kafka topic to be produced. kafka webhook producers are configured with the aca-py
event and the string template to be produced in kafka. The string templates have access to the
`wallet_id` for additional flexibility in topic string building.

## Webhook Events


`^acapy::webhook::(.*)$` with `topic` groups matching

- basicmessages
- problem_report
- ping
- actionmenu
- get-active-menu
- perform-menu-action
- forward

## Record Events

`^acapy::record::([^:]*)(?:::.*)?$` with `topic` and `state` groups matching

- connections
  - init
  - invitation
  - request
  - response
  - active
  - error
- endorse_transaction
  - init
  - transaction_created
  - request_sent
  - request_received
  - transaction_endorsed
  - transaction_refused
  - transaction_resent
  - transaction_resent_received
  - transaction_cancelled
  - transaction_acked
- issue_credential
  - roposal_sent
  - proposal_received
  - offer_sent
  - offer_received
  - request_sent
  - request_received
  - credential_issued
  - credential_received
  - credential_acked
- issue_credential_v2_0
  - proposal-sent
  - proposal-received
  - offer-sent
  - offer-received
  - request-sent
  - request-received
  - credential-issued
  - credential-received
  - done
- issue_credential_v2_0_indy
- issue_credential_v2_0_ld_proof
- oob_invitation
  - initial
  - await_response
  - done
- present_proof
  - proposal_sent
  - proposal_received
  - request_sent
  - request_received
  - presentation_sent
  - presentation_received
  - verified
  - presentation_acked
- present_proof_v2_0
  - proposal-sent
  - proposal-received
  - request-sent
  - request-received
  - presentation-sent
  - presentation-received
  - done
  - abandoned
- issuer_cred_rev
  - issued
  - revoked
- revocation_registry
  - init
  - generated
  - posted
  - active
  - full

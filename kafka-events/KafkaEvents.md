# ACA-Py Kafka Events


### Author
Daniel Bluhm [<daniel@indicio.tech\>](mailto:daniel@indicio.tech)
Luis Gomez, [Luis-GA](https://github.com/Luis-GA)

### Introduction
In order to scale processing of ACA-Py events without the use of a "middleman" webhook listener, we want to push ACA-Py events directly to a Kafka Queue.

### Context
ACA-Py uses webhooks to publish asynchronous events (generally) to a controller which then can make business decisions based on the event, trigger further action, store the result, etc. etc. When scaling in a multi-tenanted agent, a single webhook listener is infeasible and unlikely to preform as needed under high load. Scaling the listener with a load balancer would work in theory but introduces unnecessary complexity. To simplify infrastructure, we want ACA-Py to push events to a Kafka Queue where it will later be processed by a separate consumer.

### Why Kafka?

- Message system (**Transport**): 
    - High performance
    - Native data partition
    - Replication
    - Fault tolerant
- Activity tracer (**Analytics, Monitoring & Security**)
    - Rebuild an activity tracking pipeline
    - Operational surveillance

#### Quality atributes through kafka implementation
Due CAP theorem, Kafka has only:
* Consistency
* Availability

The implementation of Kafka in ACA-Py should enable the following Quality Atributes:

* accountability (log register)
* auditability (log register)
* compatibility (backwards compatibility due it is a plugin)
* configurability (through plugin config-file to define QoS)
* fault-tolerance (Kafka implementation atribute)
* credibility (Due persistent)
* distributability (Due the kafka broker)
* efficiency (Due high performance)
* flexibility (Different topics)
* interoperability (Via Kafka consumers & producers)
* recoverability (Due Kafka queue persistent)
* scalability (**Pending to clarify**)
* ubiquity (Rely on a kafka broker for message communication)

### Goals 

- describe the user-driven impact of your project
- specify how to measure success using metrics
- Define a QoS for kafka consumers (At least one, almost one, exactly one)

### Non-Goals

- Define here what's out of scope

### Proposed Solution (Technical Architecture)
- we could replace message transport with event bus(via plugin)
- 
#### Alternative Solutions
*Other solutions that you have consider during your evaluation. Pros and cons, etc...*

### Open Questions 
- What events will be exposed to the event bus?
- how will this effect the current message transport?
- Depends on the QoS, the strategy should be taken.
- In a multi-instance deployment, what should be the strategy?
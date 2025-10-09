# Admin event logging plugin

The **Admin Events Plugin** provides secure, tamper-evident logging of administrative events using a hash chain
algorithm. Each event is stored in a
database with a cryptographic hash that links it to the previous event, ensuring integrity and traceability.

## Features

- Logs admin events with timestamps
- Secures event integrity using a hash chain (SHA-256)
- Detects tampering by chaining each event to the previous one
- Easy retrieval and display of logged events

# Implementation

The main code is implemented in the class `AdminEventLoggerProvider`, which handles the logging of Keycloak admin
events,
creating hashes and storing the data.

## Data Model

Each event log entry contains:

- `id`: Unique identifier
- `event`: Description of the event
- `timestamp`: Time of the event
- `previousHash`: Hash of the previous event
- `hash`: Hash of the current event (includes previous hash)

## Integrity Verification

The hash chain ensures that any modification to a previous event will break the chain, making tampering detectable.

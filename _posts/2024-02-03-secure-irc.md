---
title: Secure IRC
description: An RFC-Style document for my take on securing the IRC protocol
date: 2025-02-03 00:00:00 +0000
categories: []
tags: [security]
---


## 1.0 Abstract


SIRC (Secure IRC) is a client-server protocol designed for secure, real-time communication. Inspired by the traditional IRC protocol (RFC 1459) and retaining its room-based communication model, SIRC modernises communication by introducing end-to-end encryption to ensure confidentiality, integrity, and forward secrecy. The protocol supports user authentication, identity verification, key rotation, and secure session key distribution. SIRC integrates mechanisms to mitigate replay attacks and denial-of-service (DoS) attacks, leveraging timestamps and message identifiers to ensure message authenticity.


## 2.0 Introduction


### 2.1 Background


Traditional IRC is lightweight and widely used for real-time text-based communication. However, IRC lacks mechanisms to ensure message confidentiality and authenticity, leaving users vulnerable to interception and replay attacks.

SIRC aims to address these shortcomings by introducing modern cryptographic techniques. Messages between users are encrypted end-to-end, meaning that only intended recipients can read them. Forward secrecy is achieved by regularly rotating session keys and user authentication ensures that only verified users can join rooms and communicate.

Identity verification is a critical component of secure communication, addressing vulnerabilities like impersonation and man-in-the-middle attacks. SIRC introduces a public-key-based identity verification mechanism, ensuring that users can reliably prove their identity. 

SIRC incorporates mechanisms to maintain user identity across sessions. To balance security and usability, a lightweight PIN-based reactivation system is used for recovering inactive keys. This ensures that user identities are protected from impersonation without requiring manual fingerprint and key verification for reactivation.

This document specifies the requirements for implementing SIRC. The following key terms are used throughout this document as defined in RFC 2119:

- MUST: indicates a mandatory requirement that all implementations must adhere to for compliance with the protocol
- SHOULD: indicates a recommended practice that improves security, performance, or usability but is not mandatory.
- MAY: indicates an optional feature that is permissible but not required.


### 2.2 Goals


The primary goals are SIRC are:

1. Protect all messages with end-to-end encryption and forward secrecy, as outlined in section 2.1.
2. Maintain the simplicity and extensibility of traditional IRC.
3. Enable room-based communication for small and medium-sized groups.
4. Mitigate replay attacks and denial-of-service (DoS) risks by using timestamps, message verification, and session key rotation.


## 3.0 Language


- Client - a user or application connecting to the SIRC server to participate in communication
- Server - the central entity that manages user connections, room metadata, and message distribution.
- Room - a virtual channel for communication between users. Each room has unique identifier and a list of participants.
- Public Key (Pub) - a cryptographic key shared publicly, used to encrypt session keys.
- Private Key (Priv) - a cryptographic key kept secret by the owner, used to decrypt session keys.
- Session key - a temporary symmetric key used to encrypt and decrypt messages between participants.
- Forward Secrecy - ensuring that the compromise of long-term keys does not compromise past communications.
- Replay Attack - an attack where an adversary intercepts and replays a message to mimic the original sender.
- Public Key Registry - a server-maintained global mapping of usernames to their public keys, used for verifying identities and encrypting session keys.
- Fingerprint - a unique, user-friendly hash derived from a public key, allowing users to verify each other’s identity.
- Key Change Warning - a notification issues by the server when a user’s public key changes unexpectedly.
- PIN (Personal Identification Number) - a user-defined numerical code required to re-activate inactive keys.
- Inactive key - a public key that has been temporarily disabled due to prolonged user inactivity. Inactive keys cannot be used for authentication until reactivated with the correct PIN.


## 4.0 Protocol Overview


### 4.1 Key Features


#### 4.1.1 End to End Encryption


Messages MUST be encrypted at the client-side using AES-GCM with a minimum key size of 256 bits. Implementations SHOULD support ChaCha20-Poly1305 as an alternative for environments without hardware acceleration for AES. This ensures that only the intended recipients can decrypt messages.


#### 4.1.2 Forward Secrecy


Session keys MUST be unique per session and SHOULD be rotated after seventy-five (75) messages or five (5) minutes of use, whichever occurs first. Implementations SHOULD allow configurable rotation intervals to accommodate different operational requirements.

Session keys MUST be securely discarded after rotation to maintain forward secrecy. While session keys are active, they MAY be reused for multiple messages within the defined thresholds.

Implementations SHOULD proactively monitor both message counts and time thresholds to trigger key rotation proactively, ensuring minimal disruption to communication. When a session key is rotated, the new session key MUST be securely distributed to all participants by encrypting it with each participant’s public key.


#### 4.1.3 Timestamping and Unique Identifiers


Each message MUST include a timestamp in the ISO 8601 format and a unique message identifier. Servers MUST validate timestamps and reject messages older than sixty (60) seconds. 

Implementations SHOULD allow a grace period of up to five (5) seconds to account for clock drift.

Implementations SHOULD periodically synchronise clocks with a reliable time source (e.g., NTP) to minimise clock drift.


### 4.2 Connection Workflow


#### 4.2.1 Client-Server Handshake


Clients MUST connect to the server over a secure transport layer (e.g. TLS). During the handshake, the client and server negotiate encryption parameters and establish a secure channel for communication.


#### 4.2.2 First-Time Registration


The client MUST authenticate using public / private key pairs. Upon the first connection, the client generates a key pair locally. The public key is sent to the server and is stored in the public key registry along with the client’s username. The private key remains locally on the client and MUST never be shared.

The client MUST also set a PIN, which is sent securely to the server and stored as a hash. The PIN is required for key reactivation in case the key becomes inactive. The PIN MUST be at least 4 digits in length, and SHOULD not be sequential (e.g., 1234) or repetitive (e.g., 1111).

The server MUST store the user’s public key and PIN in the public key registry and associate it with their username. The public key MUST be automatically trusted under the Trust on First Use (TOFU) principle.


#### 4.2.3 Subsequent Connections


When a user reconnects, the server retrieves their public key from the public key registry and validates it against the public key provided by the client. If the public keys match, and the key is marked as active, key-based authentication proceeds as normal. If the public keys do not match:

- The server MUST issue a key change warning to all users who are participants in the same room(s) as the client. The warning MAY include:
    - The user’s previous fingerprint.
    - The user’s new fingerprint.
- The server SHOULD notify the client of their own key change to ensure they are aware
- Users MAY choose to verify the new fingerprint out of band (e.g., by phone or in person) if they suspect the key change to be illegitimate. Verification is OPTIONAL and at the user’s discretion. Implementations MAY support a built-in verification mechanism, such as scanning a QR code containing the fingerprint.

If the public key is marked as inactive, the server MUST prompt the user to enter their PIN to reactivate the key. If the PIN is correct, the key is reactivated, the activity timestamp is updated, and authentication proceeds. If the PIN is incorrect after multiple attempts (e.g., 3 failures), the server MUST temporarily deny further reactivation attempts (e.g., for 3 days) to mitigate brute-force attacks. 

Communication SHOULD NOT be blocked following a key change. Users SHOULD be informed of the change and MAY proceed at their discretion.

The server MUST send a key change notification to all other room participants so that communications can continue.


#### 4.2.4 Key Expiration and Inactivity


Public keys are marked as inactivate if the user has not connected for a configurable period (e.g., 6 months). Inactive keys cannot be used for authentication until reactivated. Reactivation requires the following steps:

1. Reactivation with PIN:
    1. The server prompts the user to enter their PIN.
    2. If the PIN is correct, the server reactivates the key, updates the activity timestamp and the user regains access to their identity and associated keys.
    3. If the PIN is incorrect, the server denies reactivation and MAY enforce a temporary lockout after multiple failed attempts.
2. PIN Recovery:
    1. If the user forgets their PIN, the server MUST deny reactivation and the user MUST re-register with a new public/private key pair. During re-registration, the inactive key MUST be securely deleted from the registry.


### 4.3 Room-Based Communication


Room-based communication is SIRC, like in IRC, allows users to participate in group discussions by joining virtual rooms. Rooms are created dynamically when a user attempts to join a room that does not yet exist, and the user becomes the “operator” of the newly created room, allowing them to perform administrative commands within that room.


#### 4.3.1 Joining a Room


A client first sends a request to join a room, providing the unique identifier to specify the room. Upon receiving this request, the server verified that the specified room exists. If the room exists, the server retrieves the user’s public key from the public key registry, verifies the public key against any cached keys for that users, and finally distributes the user’s public key and fingerprint to all room participants.

If a public key mismatch is detected, the server MUST issue a key change warning, as outlined in section 4.2.3 “Public Key Exchange”.

The server MUST respond to the join request with a payload containing all of the room’s participants’ public keys.

The server MUST inform all other room participants that a new user joined, as well as distributing the new user’s public key and username.


#### 4.3.2 Leaving a Room


A client MUST send a request to the server specifying the identifier of the room to leave.

The server MUST inform other room participants that a user has left the room.


#### 4.3.3 Creating a Room


If a user attempts to join a room that does not exist, the server creates the room, assigns the user as the operator, and adds the user to the room’s participants list. Room operators have elevated privileges as described in Section 4.3.4.


#### 4.3.4 Room Creation Rules


Rooms are created dynamically when a user joins a non-existent room. Room names MUST be unique and case-insensitive (e.g., “GeneralChat” and “generalchat” refer to the same room). Room names must be between 1 and 64 alphanumeric characters. The default room type is public, meaning that any authenticated user with the room identifier can join the room.

Users SHOULD NOT be allowed to create more than 10 rooms within a 5-minute windows. Servers MAY adjust this threshold based on resource constraints.


#### 4.3.5 Operator Privileges


A room operator can be seen as an administrator - they have permissions to assign or remove other operators, kick users from the room, and change room metadata (e.g., topic). If the operator leaves the room, the server MUST automatically transfer operator status to the next participant (based on join order). If the operator is the only one in the room and they leave the room, the server MUST delete the room instance.


#### 4.3.6 Room Expiry


Rooms persist as long as they have 1 or more participants. If there are no participants in the room, the server MUST delete the room instance. 

When a room is deleted, all associated metadata (e.g., participant lists) MUST also be deleted.


#### 4.3.7 Message Workflow


When a user sends a message to a room:

1. The sender generates a random session key for the message (symmetric, used to encrypt / decrypt the message).
2. The session key is encrypted with the public keys for all recipients
3. The message is encrypted using the session key
4. The server distributes the encrypted message and session keys to the recipients.


#### 4.3.8 Receiving Messages


First, the recipient decrypts the session key (encrypted by the sender, using the recipient’s public key). Then the recipient uses the decrypted session key to decrypt the message.


### 4.4 Example Workflow


While this example workflow uses JSON format for payloads, the actual format of the payload is not restricted to JSON and is left implementation-agnostic.


#### 4.4.1 User Registration and Public Key Exchange


- The client generates a public / private key pair locally before connecting to the SIRC server:
    
    ```json
    public_key, private_key = GeneratePrivateKey(size=2048)
    ```
    
- The client sends the public key to the server during registration.
    
    ```json
    {
    	"command": "REGISTER",
    	"username": "AnonymousUser123",
    	"pub_key": "<public_key>"
    }
    ```
    
- The server stores the public key in the public key registry along with the client’s chosen username. The server then computes the public key’s fingerprint (e.g. using SHA256) and provides it to the user
    
    ```json
    user_registry = {"AnonymousUser123", "<public_key>"}
    fingerprint = calculate_fingerprint(public_key)
    send_to_user(fingerprint)
    ```
    
- The client application displays the fingerprint to User A for potential out-of-band verification.


#### 4.4.2 Key Change Warning


- If User A’s public key changes (e.g., due to new client installation), the server:
    - Detects the key change when validating the public key
    - Issues a key change warning to all users that share a room with the unverified user, providing the new and old fingerprints for comparison.
        
        ```json
        Warning: User A's fingerprint has changed:
        	Old Fingerprint: 12:34:56...
        	New Fingerprint: 65:43:21...
        ```
        


#### 4.4.3 Key Reactivation with PIN


- User reconnects after a time period longer than the configurable expiry period
- The server prompts the user for their PIN, which they set up during registration
- If the correct PIN is provided, the key is reactivated and authentication proceeds
- If the PIN is incorrect, the server denies reactivation and a temporary lockout may be applied
- If the user forgets their PIN, the server prompts the user to re-register, and securely deletes the user’s inactive key from the public key registry.


#### 4.4.4 User Joins a Room


- User sends a JOIN request to server, specifying the room name.
- Upon receiving the request, the server responds to the user with a success / failure message. If successful, the server includes all other room participants’ public keys in the response
- The server sends a USER_JOINED message containing the new user’s username and public key to all other participants in the room, allowing them to store the new user’s information in their local cache.


#### 4.4.5 User Sends a Message


- User A generates a session key: `SessionKey_ABC`.
- User A encrypts the session key for each recipient in the room
    
    ```python
    EncryptedKey_B = Encrypt(PubB, SessionKey_ABC)
    EncryptedKey_C = Encrypt(PubC, SessionKey_ABC)
    ```
    
- User A encrypts the message using the session key
    
    ```python
    CipherText = Encrypt(SessionKey_ABC, "Hello to the room")
    ```
    
- User A sends a payload to the server, containing the encrypted session keys, the ciphertext, and a note of the sender.
    
    ```python
    {
    	"sender": "UserA",
    	"ciphertext": CipherText,
    	"keys": {
    		"UserB": EncryptedKey_B,
    		"UserC": EncryptedKey_C
    	}
    }
    ```
    


#### 4.4.5 Server Relays the Message


- The server receives the message and relays the following to each recipient:
    
    ```python
    To User B: {ciphertext: CipherText, key: EncryptedKey_B}
    To User C: {ciphertext: CipherText, key: EncryptedKey_C}
    ```
    


#### 4.4.6 Recipients Decrypt the Message


- User B decrypts the session key:
    
    ```python
    SessionKey_ABC = Decrypt(PrivB, EncryptedKey_B)
    ```
    
- User B decrypts the message using the decrypted session key from the previous step
    
    ```python
    Message = Decrypt(SessionKey_ABC, CipherText)
    ```
    
- User C performs the same decryption process.


## 5.0 Message Formats


While the examples within this section use JSON format, the actual format of the message payload is not restricted to JSON and is left implementation-agnostic.


### 5.1 General Structure


#### 5.1.1 Request Payloads


All client requests MUST include:

- command - specifies the operation being performed (e.g., JOIN, SEND_MESSAGE)
- timestamp - the ISO 8601-formatted timestamp of the request
- message_id - a unique identifier for tracking the request, this MUST be UUIDv4.


#### 5.1.2 Response Payloads


All server responses MUST include:

- status - indicates success or failure, acceptable values are “SUCCESS” or “ERROR”.
- message_id - matches the message ID from the corresponding client request
- details - optional field for additional information, such as error codes and messages.


### 5.2 Request Payload Formats


#### 5.2.1 REGISTER


Used to register a new user with a public key and PIN

```json
{
  "command": "REGISTER",
  "username": "<username>",
  "public_key": "<public_key>",
  "pin": "<chosen_pin>",
  "timestamp": "<current_datetime>",
  "message_id": "<uuid_v4>"
}
```


#### 5.2.2 LOGIN


#### 5.2.3 REACTIVATE_KEY


Used to re-activate an inactive key using the user’s PIN

```json
{
  "command": "REACTIVATE_KEY",
  "username": "<username>",
  "pin": "<chosen_pin>",
  "timestamp": "<current_datetime>",
  "message_id": "<uuid_v4>"
}
```


#### 5.2.4 JOIN


Used to join an existing room or create a new one

```json
{
  "command": "JOIN",
  "room_name": "<room_name>",
  "timestamp": "<current_datetime>",
  "message_id": "<uuid_v4>"
}
```


#### 5.2.5 LEAVE


```json
{
  "command": "LEAVE",
  "room_id": "<room_id>",
  "timestamp": "<current_datetime>",
  "message_id": "<uuid_v4>"
}
```


### 5.3 Timestamp and Identifier Standards


#### 5.3.1 Timestamp Format


- Timestamps must follow the ISO 8601 format:
    
    ```json
    YYYY-MM-DDTHH:MM:SSZ (e.g., 2020-04-14T14:07:00Z)
    ```
    
- All timestamps are in UTC.
- Clients and servers must validate timestamps against their local system clock.


#### 5.3.2 Unique Identifier Format


Message IDs must be UUIDs (v4 preferred) to ensure uniqueness.


## 6.0 References


[RFC2119] Bradner, S., “Key words for use in RFCs to Indicate Requirement Levels”, RFC 2119, March 1997.

[RFC1459] Oikarinen, J., “Internet Relay Chat Protocol”, RFC 1459, May 1993.
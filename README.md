# SAML

## The core SAML rule (by design)

**SAML is an authentication *federation* protocol, not a credential-passing protocol.**

That means:

* The **SP never sees user credentials**
* The **IdP is the only party allowed to authenticate the user**
* The SP only receives a **signed assertion** saying *“this user is authenticated”*

This separation is the entire security value of SAML.

---

## What an SP is allowed to do

### ✅ What *is* allowed (standard SP-initiated login)

1. SP redirects the browser to the IdP SSO endpoint with an **AuthnRequest**
2. IdP decides *how* to authenticate the user
3. IdP returns a **SAMLResponse** to the SP

The IdP may authenticate the user via:

* Username/password UI
* MFA
* Smart card
* Kerberos / Windows Integrated Auth
* Existing IdP session (SSO)
* Any other IdP-controlled mechanism

But the **SP never supplies credentials**.

---

## What is *not* allowed in standard SAML

### ❌ SP posting credentials to IdP

There is **no supported way** for an SP to do:

```http
POST /idp/login
username=alice
password=secret
```

and get back a SAML assertion.

Why:

* SAML bindings (Redirect, POST, Artifact) **do not define credential parameters**
* IdPs intentionally reject this to prevent credential harvesting
* It would collapse the trust boundary SAML exists to enforce

If an IdP allowed this, it would be a serious security smell.

---

## “But surely there must be exceptions?”

There are — but they’re **specialised profiles**, not the normal web SSO flow.

### 1. **ECP (Enhanced Client or Proxy) – rare**

* Designed for **non-browser clients**
* Uses SOAP, not redirects
* SP ↔ client ↔ IdP exchange XML directly
* Credentials may be handled by the *client*, not the SP
* Almost never used in modern web apps

If you’re building a browser app: **ignore ECP**.

---

### 2. **IdP-initiated login**

* User starts at the IdP UI
* IdP redirects to SP with a SAMLResponse
* Still **no credential injection by the SP**

This is just a different starting point, not credential passing.

---

### 3. **Kerberos / IWA (Windows Integrated Authentication)**

* User has already authenticated to the IdP via domain login
* No login UI appears
* But the SP still **never passes credentials**

The IdP authenticates silently using environment trust, not SP input.

---

### 4. **Non-SAML APIs (important distinction)**

Some IdPs expose **non-SAML APIs** where credentials *can* be exchanged:

* OAuth2 Resource Owner Password Credentials (ROPC)
* LDAP bind
* Custom REST login endpoints

But these are **not SAML** and do **not produce SAML assertions** directly.

Many platforms support both:

* **SAML** for browser SSO
* **OAuth / LDAP** for API-style authentication

Different protocols, different trust models.

---

## Why your instinct matters (and is correct)

You’re thinking like an API designer:

> “In Node.js APIs we verify credentials and return the result to the frontend”

That model is **explicitly what SAML avoids**.

In SAML:

* Credential handling is **outsourced**
* Risk is **centralised in the IdP**
* The SP becomes a consumer of *claims*, not credentials

This is why enterprises like SAML.

---

## The only correct way for an SP to “trigger login”

The SP can only say:

> “I need the user authenticated”

and the IdP decides:

* whether to show UI
* which factors to require
* whether the user is already authenticated

The SP cannot say:

> “Authenticate *this* user with *these* credentials”

---

## Practical conclusion for your architecture

* ✅ **Frontend** redirects user to `/login` on your SP
* ✅ **SP** redirects browser to IdP SSO endpoint
* ✅ **IdP** authenticates user (UI or silent)
* ✅ **SP** receives assertion and creates session/JWT

If you ever find yourself wanting to pass credentials to the IdP:

* you either want **OAuth**, **OIDC**, or **LDAP**
* or you’re solving a different problem than SAML is meant for

---

## One-line rule to remember

> **If the SP knows the user’s password, you are no longer doing SAML.**

## SAML its not “magic redirects” its **formal contract** between two systems. I’ll do this in two parts:

1. **Walk through the metadata line-by-line** and explain *exactly* what the IdP learns from it
2. **Provide a compact glossary** of the SAML metadata elements and how SPs/IdPs use them

I’ll also correct or nuance a couple of assumptions along the way.

[Our reference SAML](#metadataSAML)


```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://localhost:3000/metadata" ID="_5889bfa5ce180985b47f0dbe6777bb93f9d6f234">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIDtTCCAp2gAwIBAgIUfxO2zKI+znJ5ZOb0T9hzhlukfOkwDQYJKoZIhvcNAQEL
                    BQAwdTELMAkGA1UEBhMCR0IxGDAWBgNVBAgMD05vcnRoIFlvcmtzaGlyZTEUMBIG
                    A1UEBwwLU2NhcmJvcm91Z2gxFTATBgNVBAoMDERldiBTQU1MIExhYjELMAkGA1UE
                    CwwCU1AxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjAyMDkxNTM5MzdaFw0yODA1
                    MTQxNTM5MzdaMHUxCzAJBgNVBAYTAkdCMRgwFgYDVQQIDA9Ob3J0aCBZb3Jrc2hp
                    cmUxFDASBgNVBAcMC1NjYXJib3JvdWdoMRUwEwYDVQQKDAxEZXYgU0FNTCBMYWIx
                    CzAJBgNVBAsMAlNQMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
                    AQUAA4IBDwAwggEKAoIBAQDn5lGbHsWO6l9dJRKFX8xE7D4AYlUR//Kz4fs7QAM/
                    PQLHUzwtH6/J+EIef7gPHSawQnJ0J7btu5PODIntVHpFwWGkySirg9Gat7xjfkD0
                    SMq9a1mBvyS8wVZKOCszTFmTqJy9urtPrUfwu0Y3yf6VRFLamdB09C16kqJwr9Kz
                    MbSRK2X9Ds8nsx5An1Rf6rJ9nUAHsgQNLDrFD1AnOpl51ajnp1G6Y96ff1tdeGAl
                    3YI+BytO2Yx1IxCnHUEWLRxIWlrEbg6OARzWkxpQm5rzyfh/NIxSob0aibLnLq/p
                    +HmytXsLi6ffoFrdljw+aG5KtuHTYGBqI3XCvUwvxToBAgMBAAGjPTA7MBoGA1Ud
                    EQQTMBGCCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQUphOfakyapWUV8AO21Mt9
                    4H30yIUwDQYJKoZIhvcNAQELBQADggEBAKtHk7e20icH+zh5r4yF6p2ujlvlT3f6
                    Xk1OT1IMSMCoXLpbD3tfGfpcYEPpw5fRwXi8tH6wdmMsSqdFg8Ed8rjB68yO4fuA
                    k9txXkOF2WRgN9PmjuoUFFGfEtuKnKiRyrMqiMlUvhkdi/MY9BP/sH7eoVGl5la0
                    cl+cyXe6U24V+hdax3ioZgb+FnRV/eKRiuvayXEEvjqjXPcJgp818ZfAl7wJoPog
                    pHU33blBWlpRB1tFI1RWgE19ipeijoj3uSI2Y9IY0BMHRu0zCmqxk8o4pN08floj
                    ad+/NIxJq7AwRxhpyM1t7MBbuuDlsVvGe6DIdgpK7d5x2Lbvaqn2Cmw=
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIDtTCCAp2gAwIBAgIUTh4xuG1g/ovgUSj69O+8g7rTreUwDQYJKoZIhvcNAQEL
                    BQAwdTELMAkGA1UEBhMCR0IxGDAWBgNVBAgMD05vcnRoIFlvcmtzaGlyZTEUMBIG
                    A1UEBwwLU2NhcmJvcm91Z2gxFTATBgNVBAoMDERldiBTQU1MIExhYjELMAkGA1UE
                    CwwCU1AxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjAyMDkxNTM5NTNaFw0yODA1
                    MTQxNTM5NTNaMHUxCzAJBgNVBAYTAkdCMRgwFgYDVQQIDA9Ob3J0aCBZb3Jrc2hp
                    cmUxFDASBgNVBAcMC1NjYXJib3JvdWdoMRUwEwYDVQQKDAxEZXYgU0FNTCBMYWIx
                    CzAJBgNVBAsMAlNQMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
                    AQUAA4IBDwAwggEKAoIBAQCpHI2zckYCxvKvW0/8Z6qlqoh25AOFBfr5PN+RrpPa
                    hfsNt4VfpLOHTy1HYla7EKVN9U/EkCYew/bw1GT14D+yjyLaf3u5bW7FSMMXrMJp
                    q67efADppM/dHe0lzSLijVo32O8+Sr5TjEz0c5xTDiXSmXrzCN/Z5btTALFTVCBh
                    17//L3RP2lkxSKbJZUrj5LWMg+9rEjbUUBXl7feLLWUdXa41uy9z3TdYxUbVq0WY
                    wRGLmtOnOUjE9Iz3l4y9h8MUUWUFMsTUtZy7WCBZWxK4Ld3x1svqLxZGVIxin/A7
                    BtbwT1A6E9TXJJT6fwbliaqqQpMMCLSfqytHioprq641AgMBAAGjPTA7MBoGA1Ud
                    EQQTMBGCCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQUab3o66hzqaOTypWfLMz8
                    v43aWDgwDQYJKoZIhvcNAQELBQADggEBAEjdBPEp/I8uqjgfEhMh7PhiQOaneh24
                    6mMrr13AE5wZNtQpS6XwIow2ZEkRVO6JhU+EyMW/Qp+IYpggmGpQ9Ql5lTKeCaN9
                    xmVYNKFinzEM7m3J9Nc63CD4ECN39tunaNTF8nxv9kUu/Fq+UBrfLctqccmY8w3Z
                    ANr7Q8+z1CJIENvlxED6ImkN0QmqWE5JmMRyKlZMVb6wN1N6Trk+xzPzZwGc05fQ
                    z3Z0LwstyQkzMryefUCbvfOottQH3MHi41tpgvAUhfUjl6/Yn2X06AQsF3ST1aJn
                    +Zd/pbvfTRDO1+6BBj70iJXHjrpFEONZBwL2ZVmi2J8DrM0Z+hZmxsk=
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
            <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:3000/login/callback"/>
    </SPSSODescriptor>
</EntityDescriptor>

```

---

# Part 1 — Explaining *your* SP metadata, element by element

Think of SP metadata as:

> **“This is who I am, how to talk to me, and which cryptographic keys you may trust from me.”**

Nothing here is secret.

---

## `<EntityDescriptor …>`

```xml
<EntityDescriptor
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="http://localhost:3000/metadata"
  ID="_5889bfa5ce180985b47f0dbe6777bb93f9d6f234">
```

### Purpose

This is the **root identity of the SP**.

### Key attributes

* **`entityID`**

  * The **global identifier** of your SP
  * Must be **stable** and **unique**
  * Used by the IdP as:

    * Audience restriction
    * Trust anchor
    * Lookup key for configuration
  * Does *not* have to be a resolvable URL (but often is)

* **`ID`**

  * Internal XML identifier
  * Rarely used outside XML signature contexts

### What the IdP learns

> “This SP is called `http://localhost:3000/metadata`. Any assertions I issue to it must be scoped to that identifier.”

---

## `<SPSSODescriptor …>`

```xml
<SPSSODescriptor
  protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
  AuthnRequestsSigned="true"
  WantAssertionsSigned="true">
```

### Purpose

Declares that this entity acts as a **Service Provider for SAML SSO**.

### Attributes

* **`protocolSupportEnumeration`**

  * Says: “I speak SAML 2.0”
  * (Almost always this value)

* **`AuthnRequestsSigned="true"`**

  * You are telling the IdP:

    > “When I send AuthnRequests, I will sign them.”
  * If the IdP enforces this, it must have your **signing certificate**.

* **`WantAssertionsSigned="true"`**

  * You are telling the IdP:

    > “I require assertions to be signed.”
  * This is a **security requirement**, not a preference.

### What the IdP learns

> “I must verify SP-signed requests, and I must sign assertions I issue to this SP.”

---

## `<KeyDescriptor use="signing">`

```xml
<KeyDescriptor use="signing">
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>…</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</KeyDescriptor>
```

### Purpose

Publishes your **SP signing public key**.

### How it’s used

* IdP uses this key to:

  * Verify **signed AuthnRequests**
  * Verify **signed LogoutRequests** (if SLO used)

### Important clarifications

* This is **not** a TLS cert
* This is **not** a secret
* The IdP stores it and trusts signatures made by your private key

### What the IdP learns

> “If a SAML message claims to be from this SP and verifies with this cert, I trust it.”

---

## `<KeyDescriptor use="encryption">`

```xml
<KeyDescriptor use="encryption">
  …
  <ds:X509Certificate>…</ds:X509Certificate>
  …
  <EncryptionMethod Algorithm="…"/>
</KeyDescriptor>
```

### Purpose

Publishes your **SP encryption public key**.

### How it’s used

* IdP uses this key to:

  * Encrypt assertions
  * Encrypt NameIDs (optional)

### EncryptionMethod elements

These advertise **which symmetric algorithms** your SP can handle:

* `aes256-gcm`
* `aes128-gcm`
* `aes256-cbc`
* `aes128-cbc`

The IdP chooses one it supports.

### What the IdP learns

> “If I encrypt assertions for this SP, I must use this public key and one of these algorithms.”

---

## `<NameIDFormat>`

```xml
<NameIDFormat>
  urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
</NameIDFormat>
```

### Purpose

Declares **which subject identifier formats you support**.

### Important nuance

This is:

* A **capability advertisement**, not a guarantee
* The IdP may still choose a different format if configured so

Common values:

* `emailAddress`
* `persistent`
* `transient`
* `unspecified`

### What the IdP learns

> “This SP can accept an email-address NameID.”

---

## `<AssertionConsumerService …>`

```xml
<AssertionConsumerService
  index="1"
  isDefault="true"
  Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  Location="http://localhost:3000/login/callback"/>
```

### Purpose

Tells the IdP **where and how** to send the SAMLResponse.

### Attributes

* **`Binding`**

  * HTTP-POST (most common, safest)
* **`Location`**

  * Your ACS endpoint
  * Must match exactly what your SP accepts
* **`index` / `isDefault`**

  * Supports multiple ACS endpoints (rare today)

### What the IdP learns

> “After authenticating the user, POST the SAMLResponse to this URL.”

---

# Part 2 — SAML Metadata Glossary (SP-focused)

Below is a concise glossary of the major metadata concepts and how they’re used.

---

## Core identity concepts

| Field                 | Meaning                  | Used by                      |
| --------------------- | ------------------------ | ---------------------------- |
| `entityID`            | Global identifier of SP  | IdP (audience, trust lookup) |
| `Issuer` (runtime)    | Who issued a message     | SP & IdP                     |
| `AudienceRestriction` | Who the assertion is for | SP validation                |

---

## Cryptography

| Field                            | Purpose                       | Direction |
| -------------------------------- | ----------------------------- | --------- |
| `KeyDescriptor use="signing"`    | Verify SP-signed requests     | IdP ← SP  |
| `KeyDescriptor use="encryption"` | Encrypt assertions            | IdP → SP  |
| `AuthnRequestsSigned`            | SP promises to sign requests  | SP → IdP  |
| `WantAssertionsSigned`           | SP requires signed assertions | IdP → SP  |

---

## Endpoints

| Field                      | Purpose                             |
| -------------------------- | ----------------------------------- |
| `AssertionConsumerService` | Where IdP posts SAMLResponse        |
| `SingleLogoutService`      | Where logout messages go (optional) |
| `Binding`                  | How messages are transported        |

---

## Subject identifiers

| Field          | Meaning                         |
| -------------- | ------------------------------- |
| `NameIDFormat` | Type of subject identifier      |
| `persistent`   | Stable, SP-scoped ID            |
| `transient`    | One-time, privacy-preserving ID |
| `emailAddress` | Human-readable ID               |

---

## Runtime SAML fields (not in metadata)

| Field          | Purpose                                 |
| -------------- | --------------------------------------- |
| `SAMLRequest`  | AuthnRequest from SP                    |
| `SAMLResponse` | Assertion bundle from IdP               |
| `RelayState`   | Opaque state preserved across redirects |
| `InResponseTo` | Correlates response to request          |
| `SessionIndex` | Used for Single Logout                  |

---

# Final mental model (important)

Metadata is **not an API**.
It is a **trust contract**.

* It is exchanged **out-of-band**
* It enables **runtime messages to be trusted**
* It rarely changes
* It contains **no secrets**

Once exchanged, runtime SAML flows only reference:

* `entityID`
* endpoints
* keys

---

If you want, next we can:

* compare this SP metadata to **Ping / ForgeRock / ADFS UI fields**
* show how IdPs internally map this XML into config objects
* design **multi-tenant SP metadata** (per-customer entityIDs)
* or map SAML concepts to **OIDC equivalents** for intuition

Just say where you want to go next.


# Our SAML App setup


## Running our example in docker

Note: we're using 18080 and 19443 as on the test system ports 8080 and 8443 were already in use.  Our SP (nodejs application) is available on port 3000
```
docker run --platform linux/amd64 --rm --name saml-idp -p 18080:8080 -p 19443:8443 -e SIMPLESAMLPHP_SP_ENTITY_ID=http://localhost:3000/metadata -e SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE=http://localhost:3000/login/callback -e SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE=http://localhost:3000/logout/callback kristophjunge/test-saml-idp
```

Running our Nodejs SP app
```
npx ts-node-dev src/index.ts
```

Terminal should respond with: 
```
[INFO] 16:19:11 ts-node-dev ver. 2.0.0 (using ts-node ver. 10.9.2, typescript ver. 5.9.3)
SP listening on http://localhost:3000
```

## How the keys were generated

For packages Passport.js will be using: `@node-saml/passport-saml@5.1.0` / `@node-saml/node-saml@5.1.0`

* **publish** both SP certs in metadata via `generateServiceProviderMetadata(decryptionCert, signingCert)`
* **actually use** them at runtime by adding:

  * `privateKey` (signing key)
  * `decryptionPvk` (decryption private key)
---

## 1) Generate cert/key files (signing + encryption)

From project root:

```bash
mkdir -p saml-certs
cd saml-certs
```

Create an OpenSSL config `openssl-localhost.cnf`:

```conf
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = GB
ST = North Yorkshire
L  = Scarborough
O  = Dev SAML Lab
OU = SP
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
```

### Signing keypair

```bash
openssl genrsa -out sp-signing.key 2048
openssl req -new -key sp-signing.key -out sp-signing.csr -config openssl-localhost.cnf
openssl x509 -req -in sp-signing.csr -signkey sp-signing.key \
  -out sp-signing.crt -days 825 -sha256 -extensions req_ext -extfile openssl-localhost.cnf
```

### Encryption keypair

```bash
openssl genrsa -out sp-encryption.key 2048
openssl req -new -key sp-encryption.key -out sp-encryption.csr -config openssl-localhost.cnf
openssl x509 -req -in sp-encryption.csr -signkey sp-encryption.key \
  -out sp-encryption.crt -days 825 -sha256 -extensions req_ext -extfile openssl-localhost.cnf
```

You now have:

* `saml-certs/sp-signing.key` + `saml-certs/sp-signing.crt`
* `saml-certs/sp-encryption.key` + `saml-certs/sp-encryption.crt`

---

## 2) Update your `PassportSamlConfig` (runtime signing + decryption)

```ts
const signingKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.key"), "utf8");
const signingCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.crt"), "utf8");

const decryptionKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.key"), "utf8");
const decryptionCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.crt"), "utf8");

export const passportSamlConfig: PassportSamlConfig = {
  ...
  // ✅ SP signing (used to sign AuthnRequests if you enable signing)
  privateKey: signingKey,
  signatureAlgorithm: "sha256",
  digestAlgorithm: "sha256",

  // ✅ SP decryption (used to decrypt encrypted assertions if IdP encrypts)
  decryptionPvk: decryptionKey,
  ...
};
```

## 3) Publish both certs in SP metadata

In your `/metadata` route, pass **public certs** (the `.crt` files):

```ts
app.get("/metadata", (_req, res) => {
  res.type("application/xml");
  res.send(samlStrategy.generateServiceProviderMetadata(decryptionCert, signingCert));
});
```

That produces metadata containing:

* `<KeyDescriptor use="encryption">…</KeyDescriptor>`
* `<KeyDescriptor use="signing">…</KeyDescriptor>`

---


## Calling the endpoints
Viewing metadata -> ```http://localhost:3000/metadata```

Code that executes, generates the SAML <a name="metadataSAML">seen previously</a>

```ts
app.get("/metadata", (_req, res) => {
  res.type("application/xml");
  res.send(samlStrategy.generateServiceProviderMetadata(decryptionCert, signingCert));
});
```



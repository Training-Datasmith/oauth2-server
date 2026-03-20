# oauth2-server Architecture

## Purpose

league/oauth2-server is an RFC 6749/RFC 7519 compliant OAuth 2.0 authorisation server library. It is framework-agnostic (PSR-7 HTTP messages), persistence-agnostic (repository interfaces), and supports all standard grant types plus Device Code (RFC 8628).

## Directory Structure

```
src/
  Authorization_Server.php          — Entry point: enable grants, validate/complete auth requests
  Resource_Server.php               — Validates Bearer tokens on resource endpoints
  Crypt_Key.php                     — RSA/EC key loader with filesystem permission check
  Crypt_Key_Interface.php           — get_key_contents(), get_key_path(), get_pass_phrase()
  Crypt_Trait.php                   — encrypt/decrypt helpers (Defuse symmetric encryption)
  Grant/
    Abstract_Grant.php              — Base: token issuance, client validation, PKCE, scopes
    Auth_Code_Grant.php             — Authorization Code (+ PKCE, RFC 7636)
    Client_Credentials_Grant.php    — Client Credentials
    Implicit_Grant.php              — Implicit (legacy, not recommended)
    Password_Grant.php              — Resource Owner Password Credentials (legacy)
    Refresh_Token_Grant.php         — Refresh Token
    Device_Code_Grant.php           — Device Authorization (RFC 8628)
  AuthorizationValidators/
    Bearer_Token_Validator.php      — JWT verification via lcobucci/jwt (RS256)
  CodeChallengeVerifiers/
    S256Verifier.php                — PKCE S256 verifier (SHA-256 code challenge)
    Plain_Verifier.php              — PKCE plain verifier (discouraged)
  RedirectUriValidators/
    Redirect_Uri_Validator.php      — Exact-match redirect URI validation
  Entities/                         — Interfaces for AccessToken, AuthCode, Client, Scope, …
  Entities/Traits/                  — Default implementations of entity interfaces
  Repositories/                     — Interfaces: persist/revoke tokens, validate clients
  ResponseTypes/
    Bearer_Token_Response.php       — Builds the JSON token response; signs JWT with private key
    Device_Code_Response.php
  RequestTypes/
    Authorization_Request.php       — Carries validated state through the auth code flow
  Exception/
    O_Auth_Server_Exception.php     — RFC 6749 error responses (invalid_client, invalid_scope, …)
  EventEmitting/                    — Optional PSR-14-style event emission hooks
```

## Token Format

Access tokens are signed JWTs (RS256 by default):

```
Header.Payload.Signature
Payload: { iss, aud (client_id), jti (token_id), iat, nbf, exp, sub (user_id), scopes }
```

Refresh tokens and auth codes are encrypted with Defuse symmetric encryption (`Crypt_Trait`) and stored as opaque strings.

## Key Design Decisions

- **RS256 JWT access tokens**: `Authorization_Server` requires an RSA/EC private key; `Resource_Server` requires the corresponding public key. Key material never crosses the wire.
- **Constant-time JWT validation**: lcobucci/jwt uses `hash_equals` internally; `Bearer_Token_Validator` also checks revocation status via the repository.
- **PKCE enforcement**: `Auth_Code_Grant` enforces `code_challenge` / `code_verifier`; S256 is strongly preferred over `plain`.
- **Redirect URI exact-match**: `Redirect_Uri_Validator` performs exact-string comparison (no wildcard), preventing open-redirect attacks.
- **Confidential client secret validation**: `Abstract_Grant::validate_client()` rejects confidential clients that omit a `client_secret`.
- **`#[SensitiveParameter]`**: Private keys and encryption keys are annotated so they are redacted from stack traces.
- **Key permission warnings**: `Crypt_Key` emits `E_USER_NOTICE` when key file permissions are broader than 660 (Unix only).
- **Refresh token revocation**: Controlled per-server via `revoke_refresh_tokens(bool)`.

## Extension Points

- Implement the `Repositories\*_Interface` contracts to wire in any persistence backend (Doctrine, PDO, Redis, …).
- Implement `Grant_Type_Interface` for custom grant types.
- Implement `Authorization_Validator_Interface` to replace JWT with opaque-token introspection.
- Implement `Response_Type_Interface` for custom token response formats.
- Implement `Code_Challenge_Verifier_Interface` for additional PKCE methods.

## Dependency Flow

```
Authorization_Server
    └─ Grant\Abstract_Grant  (client validation, scope validation, token issuance)
          ├─ Repositories\*  (persist/revoke — caller implements)
          ├─ Crypt_Trait      (Defuse encrypt/decrypt for refresh tokens / auth codes)
          └─ Entities\*      (AccessToken, RefreshToken, AuthCode — caller implements)
    └─ ResponseTypes\Bearer_Token_Response
          └─ lcobucci/jwt    (JWT signing with Crypt_Key private key)

Resource_Server
    └─ Bearer_Token_Validator
          └─ lcobucci/jwt    (JWT verification with Crypt_Key public key)
          └─ Repositories\Access_Token_Repository_Interface  (revocation check)
```

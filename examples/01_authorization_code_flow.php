<?php

declare(strict_types=1);

/**
 * Example: Authorization Code Grant flow (conceptual skeleton).
 *
 * This file demonstrates how to wire up an Authorization_Server for the
 * Authorization Code grant.  It uses in-memory stub implementations of the
 * repository interfaces so it can be read without a database.
 *
 * Security notes:
 *  - Generate private/public keys with a strong algorithm:
 *      openssl genrsa -out private.key 4096
 *      openssl rsa -in private.key -pubout -out public.key
 *  - Store private key files with mode 600 (owner-read only).
 *    Crypt_Key will emit E_USER_NOTICE if permissions are too broad (Unix).
 *  - ALWAYS enable PKCE (Auth_Code_Grant::enable_code_exchange_proof_key())
 *    for public clients.  S256 is required; "plain" is discouraged.
 *  - The encryption key (Defuse Key) encrypts auth codes and refresh tokens
 *    stored as opaque strings.  Rotate it to invalidate all outstanding tokens.
 *  - Access tokens are signed JWTs (RS256); resource servers need only the
 *    public key — never share the private key with resource servers.
 *
 * @security Never log access tokens, refresh tokens, or auth codes.
 *           They are bearer credentials — possession equals authorisation.
 */

// This example shows the wiring; running it requires a full PSR-7 environment.
// See https://oauth2.thephpleague.com/authorization-server/auth-code-grant/

/*
use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;

// 1. Load keys.
$private_key = new CryptKey('file:///path/to/private.key', null, true);
// Encryption key for auth codes / refresh tokens (Defuse\Crypto\Key).
$encryption_key = Key::loadFromAsciiSafeString(getenv('OAUTH_ENCRYPTION_KEY'));

// 2. Instantiate the server.
$server = new AuthorizationServer(
    $client_repository,       // implements ClientRepositoryInterface
    $access_token_repository, // implements AccessTokenRepositoryInterface
    $scope_repository,        // implements ScopeRepositoryInterface
    $private_key,
    $encryption_key,
);

// 3. Enable the Authorization Code grant with PKCE (mandatory for public clients).
$auth_code_grant = new AuthCodeGrant(
    $auth_code_repository,    // implements AuthCodeRepositoryInterface
    $refresh_token_repository,// implements RefreshTokenRepositoryInterface
    new DateInterval('PT10M') // auth codes expire after 10 minutes
);
$auth_code_grant->enableCodeExchangeProofKey(); // enforce PKCE
$server->enableGrantType($auth_code_grant, new DateInterval('PT1H')); // tokens last 1 hour

// 4. Handle the /authorize endpoint (validate and redirect).
try {
    $auth_request = $server->validateAuthorizationRequest($psr7_request);
    $auth_request->setUser($current_user);      // your user entity
    $auth_request->setAuthorizationApproved(true);
    $response = $server->completeAuthorizationRequest($auth_request, $psr7_response);
} catch (OAuthServerException $e) {
    $response = $e->generateHttpResponse($psr7_response);
}

// 5. Handle the /token endpoint.
try {
    $response = $server->respondToAccessTokenRequest($psr7_request, $psr7_response);
} catch (OAuthServerException $e) {
    $response = $e->generateHttpResponse($psr7_response);
}
*/

echo 'Authorization Code flow example — see comments for implementation details.' . PHP_EOL;

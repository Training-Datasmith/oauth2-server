<?php

declare(strict_types=1);

/**
 * Example: Validating a Bearer token on a resource server.
 *
 * The Resource_Server validates the JWT signature against the public key and
 * checks revocation status via the Access_Token_Repository.  No private key
 * material is required on the resource server.
 *
 * Security notes:
 *  - Resource servers only need the RSA/EC PUBLIC key, never the private key.
 *  - JWTs are validated for: correct signature (RS256), expiry (exp), and
 *    not-before (nbf).  A configurable leeway can accommodate clock skew.
 *  - Always check the revocation status of tokens via the repository — a
 *    cryptographically valid token may have been explicitly revoked.
 *  - The validated request attributes (oauth_access_token_id, oauth_client_id,
 *    oauth_user_id, oauth_scopes) are injected by Bearer_Token_Validator and
 *    should be the only source of identity data on the resource server.
 *  - Validate required scopes yourself after validation:
 *      $scopes = $validated_request->getAttribute('oauth_scopes');
 *
 * @security Clock-skew leeway is configurable but should be kept small
 *           (seconds, not minutes) to limit the window for replayed tokens.
 */

/*
use DateInterval;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;

// Only the public key is needed here.
$public_key = new CryptKey('file:///path/to/public.key');

$resource_server = new ResourceServer(
    $access_token_repository,  // implements AccessTokenRepositoryInterface
    $public_key,
    null,                      // optional: custom AuthorizationValidatorInterface
);

// Optionally configure clock-skew tolerance (e.g., 30 seconds):
// $leeway_validator = new BearerTokenValidator($access_token_repository, new DateInterval('PT30S'));
// $resource_server = new ResourceServer($access_token_repository, $public_key, $leeway_validator);

try {
    $validated_request = $resource_server->validateAuthenticatedRequest($psr7_request);

    $user_id   = $validated_request->getAttribute('oauth_user_id');
    $client_id = $validated_request->getAttribute('oauth_client_id');
    $scopes    = $validated_request->getAttribute('oauth_scopes'); // array

    // Enforce required scopes.
    if (!in_array('read:profile', $scopes, true)) {
        // Return 403 Forbidden.
    }
} catch (OAuthServerException $e) {
    $response = $e->generateHttpResponse($psr7_response);
    // Return 401 Unauthorized.
}
*/

echo 'Resource server validation example — see comments for implementation details.' . PHP_EOL;

<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server;

use DateInterval;
use Defuse\Crypto\Key;
use League\O_Auth2\Server\Event_Emitting\Emitter_Aware_Interface;
use League\O_Auth2\Server\Event_Emitting\Emitter_Aware_Polyfill;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Grant\Grant_Type_Interface;
use League\O_Auth2\Server\Repositories\Access_Token_Repository_Interface;
use League\O_Auth2\Server\Repositories\Client_Repository_Interface;
use League\O_Auth2\Server\Repositories\Scope_Repository_Interface;
use League\O_Auth2\Server\Request_Types\Authorization_Request_Interface;
use League\O_Auth2\Server\Response_Types\Abstract_Response_Type;
use League\O_Auth2\Server\Response_Types\Bearer_Token_Response;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use Psr\Http\Message\Response_Interface;
use Psr\Http\Message\Server_Request_Interface;
use Sensitive_Parameter;
class Authorization_Server implements Emitter_Aware_Interface
{
    use Emitter_Aware_Polyfill;
    /**
     * @var GrantTypeInterface[]
     */
    protected array $enabled_grant_types = [];
    /**
     * @var DateInterval[]
     */
    protected array $grant_type_access_token_ttl = [];
    protected Crypt_Key_Interface $private_key;
    protected Crypt_Key_Interface $public_key;
    protected Response_Type_Interface $response_type;
    private string $default_scope = '';
    private bool $revoke_refresh_tokens = true;
    /**
     * Creates a new Authorization_Server instance.
     *
     * @security The $private_key is used to sign JWT access tokens (RS256 by
     *           default).  It must be an RSA or EC private key of at least 2048
     *           bits.  Both $private_key and $encryption_key are annotated with
     *           #[SensitiveParameter] so they are redacted from PHP stack traces.
     *
     * @param Client_Repository_Interface     $client_repository       Validates client credentials and fetches client entities.
     * @param Access_Token_Repository_Interface $access_token_repository Persists and revokes access tokens.
     * @param Scope_Repository_Interface      $scope_repository        Resolves scope identifiers to scope entities.
     * @param Crypt_Key_Interface|string      $private_key             RSA/EC private key (object or file:// path / PEM string).
     *                                                                  Key file should have mode 600.
     * @param string|Key                      $encryption_key          Defuse symmetric key used to encrypt auth codes and
     *                                                                  refresh tokens stored as opaque strings.
     * @param Response_Type_Interface|null    $response_type           Custom response type; defaults to Bearer_Token_Response.
     */
    public function __construct(
        private Client_Repository_Interface $client_repository,
        private Access_Token_Repository_Interface $access_token_repository,
        private Scope_Repository_Interface $scope_repository,
        #[Sensitive_Parameter]
        Crypt_Key_Interface|string $private_key,
        #[Sensitive_Parameter]
        private string|Key $encryption_key,
        Response_Type_Interface|null $response_type = null
    )
    {
        if ($private_key instanceof Crypt_Key_Interface === false) {
            $private_key = new Crypt_Key($private_key);
        }
        $this->private_key = $private_key;
        if ($response_type === null) {
            $response_type = new Bearer_Token_Response();
        } else {
            $response_type = clone $response_type;
        }
        $this->response_type = $response_type;
    }
    /**
     * Enable a grant type on the server.
     *
     * Injects all server-level dependencies (repositories, keys, encryption key,
     * default scope) into the grant type before registering it.
     *
     * @security Each grant type receives the private key for JWT signing.  Only
     *           enable grant types that are appropriate for your application:
     *           - Disable Implicit and Password grants for new applications (RFC 6749
     *             recommends against both).
     *           - Always call Auth_Code_Grant::enable_code_exchange_proof_key() to
     *             enforce PKCE for public clients.
     *
     * @param Grant_Type_Interface  $grant_type       The grant type to register, e.g. Auth_Code_Grant.
     * @param DateInterval|null     $access_token_ttl How long access tokens issued by this grant are valid.
     *                                                Defaults to PT1H (1 hour) if null.
     *
     * @return void
     */
    public function enable_grant_type(Grant_Type_Interface $grant_type, DateInterval|null $access_token_ttl = null): void
    {
        if ($access_token_ttl === null) {
            $access_token_ttl = new DateInterval('PT1H');
        }
        $grant_type->set_access_token_repository($this->access_token_repository);
        $grant_type->set_client_repository($this->client_repository);
        $grant_type->set_scope_repository($this->scope_repository);
        $grant_type->set_default_scope($this->default_scope);
        $grant_type->set_private_key($this->private_key);
        $grant_type->set_emitter($this->get_emitter());
        $grant_type->set_encryption_key($this->encryption_key);
        $grant_type->revoke_refresh_tokens($this->revoke_refresh_tokens);
        $this->enabled_grant_types[$grant_type->get_identifier()] = $grant_type;
        $this->grant_type_access_token_ttl[$grant_type->get_identifier()] = $access_token_ttl;
    }
    /**
     * Validates an incoming authorization request and returns a hydrated Authorization_Request.
     *
     * Iterates through enabled grant types and delegates to the first grant that
     * can respond to the request.  The returned Authorization_Request must be
     * stored (e.g., in the session) between the initial redirect and the user
     * approval step.
     *
     * @security The state parameter is not validated here; callers MUST validate
     *           the CSRF state parameter themselves before calling this method to
     *           prevent cross-site request forgery on the authorization endpoint.
     *           The redirect_uri is validated against pre-registered URIs by the
     *           grant type (exact-match comparison).
     *
     * @param Server_Request_Interface $request The incoming PSR-7 authorization request.
     *
     * @throws O_Auth_Server_Exception with error=unsupported_grant_type if no grant matches.
     *
     * @return Authorization_Request_Interface A validated, partially populated authorization request.
     */
    public function validate_authorization_request(Server_Request_Interface $request): Authorization_Request_Interface
    {
        foreach ($this->enabled_grant_types as $grant_type) {
            if ($grant_type->can_respond_to_authorization_request($request)) {
                return $grant_type->validate_authorization_request($request);
            }
        }
        throw O_Auth_Server_Exception::unsupported_grant_type();
    }
    /**
     * Complete an authorization request
     */
    public function complete_authorization_request(Authorization_Request_Interface $auth_request, Response_Interface $response): Response_Interface
    {
        return $this->enabled_grant_types[$auth_request->get_grant_type_id()]->complete_authorization_request($auth_request)->generate_http_response($response);
    }
    /**
     * Respond to device authorization request
     *
     * @throws OAuthServerException
     */
    public function respond_to_device_authorization_request(Server_Request_Interface $request, Response_Interface $response): Response_Interface
    {
        foreach ($this->enabled_grant_types as $grant_type) {
            if ($grant_type->can_respond_to_device_authorization_request($request)) {
                return $grant_type->respond_to_device_authorization_request($request)->generate_http_response($response);
            }
        }
        throw O_Auth_Server_Exception::unsupported_grant_type();
    }
    /**
     * Complete a device authorization request
     */
    public function complete_device_authorization_request(string $device_code, string $user_id, bool $user_approved): void
    {
        $this->enabled_grant_types['urn:ietf:params:oauth:grant-type:device_code']->complete_device_authorization_request($device_code, $user_id, $user_approved);
    }
    /**
     * Return an access token response.
     *
     * @throws OAuthServerException
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Interface $response): Response_Interface
    {
        foreach ($this->enabled_grant_types as $grant_type) {
            if (!$grant_type->can_respond_to_access_token_request($request)) {
                continue;
            }
            $token_response = $grant_type->respond_to_access_token_request($request, $this->get_response_type(), $this->grant_type_access_token_ttl[$grant_type->get_identifier()]);
            return $token_response->generate_http_response($response);
        }
        throw O_Auth_Server_Exception::unsupported_grant_type();
    }
    /**
     * Get the token type that grants will return in the HTTP response.
     */
    protected function get_response_type(): Response_Type_Interface
    {
        $response_type = clone $this->response_type;
        if ($response_type instanceof Abstract_Response_Type) {
            $response_type->set_private_key($this->private_key);
        }
        $response_type->set_encryption_key($this->encryption_key);
        return $response_type;
    }
    /**
     * Set the default scope for the authorization server.
     */
    public function set_default_scope(string $default_scope): void
    {
        $this->default_scope = $default_scope;
    }
    /**
     * Sets whether to revoke refresh tokens or not (for all grant types).
     */
    public function revoke_refresh_tokens(bool $revoke_refresh_tokens): void
    {
        $this->revoke_refresh_tokens = $revoke_refresh_tokens;
    }
}
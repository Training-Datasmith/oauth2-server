<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Grant;

use function array_key_exists;
use function array_keys;
use function array_map;
use function count;
use DateInterval;
use DateTimeImmutable;
use Exception;
use function hash_algos;
use function implode;
use function in_array;
use InvalidArgumentException;
use function is_array;
use function json_decode;
use function json_encode;
use League\O_Auth2\Server\Code_Challenge_Verifiers\Code_Challenge_Verifier_Interface;
use League\O_Auth2\Server\Code_Challenge_Verifiers\Plain_Verifier;
use League\O_Auth2\Server\Code_Challenge_Verifiers\S256Verifier;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\User_Entity_Interface;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Repositories\Auth_Code_Repository_Interface;
use League\O_Auth2\Server\Repositories\Refresh_Token_Repository_Interface;
use League\O_Auth2\Server\Request_Access_Token_Event;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Request_Refresh_Token_Event;
use League\O_Auth2\Server\Request_Types\Authorization_Request_Interface;
use League\O_Auth2\Server\Response_Types\Redirect_Response;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use LogicException;
use function preg_match;
use function property_exists;
use Psr\Http\Message\Server_Request_Interface;
use function sprintf;
use stdClass;
use function time;
class Auth_Code_Grant extends Abstract_Authorize_Grant
{
    private bool $require_code_challenge_for_public_clients = true;
    /**
     * @var CodeChallengeVerifierInterface[]
     */
    private array $code_challenge_verifiers = [];
    /**
     * @throws Exception
     */
    public function __construct(Auth_Code_Repository_Interface $auth_code_repository, Refresh_Token_Repository_Interface $refresh_token_repository, private readonly DateInterval $auth_code_ttl)
    {
        $this->set_auth_code_repository($auth_code_repository);
        $this->set_refresh_token_repository($refresh_token_repository);
        $this->refresh_token_ttl = new DateInterval('P1M');
        if (in_array('sha256', hash_algos(), true)) {
            $s256Verifier = new S256Verifier();
            $this->code_challenge_verifiers[$s256Verifier->get_method()] = $s256Verifier;
        }
        $plain_verifier = new Plain_Verifier();
        $this->code_challenge_verifiers[$plain_verifier->get_method()] = $plain_verifier;
    }
    /**
     * Disable the requirement for a code challenge for public clients.
     */
    public function disable_require_code_challenge_for_public_clients(): void
    {
        $this->require_code_challenge_for_public_clients = false;
    }
    /**
     * Respond to an access token request.
     *
     * @throws OAuthServerException
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Type_Interface $response_type, DateInterval $access_token_ttl): Response_Type_Interface
    {
        $client = $this->validate_client($request);
        $encrypted_auth_code = $this->get_request_parameter('code', $request);
        if ($encrypted_auth_code === null) {
            throw O_Auth_Server_Exception::invalid_request('code');
        }
        try {
            $auth_code_payload = json_decode($this->decrypt($encrypted_auth_code));
            $this->validate_authorization_code($auth_code_payload, $client, $request);
            $scopes = $this->scope_repository->finalize_scopes($this->validate_scopes($auth_code_payload->scopes), $this->get_identifier(), $client, $auth_code_payload->user_id, $auth_code_payload->auth_code_id);
        } catch (InvalidArgumentException) {
            throw O_Auth_Server_Exception::invalid_grant('Cannot validate the provided authorization code');
        } catch (LogicException $e) {
            throw O_Auth_Server_Exception::invalid_request('code', 'Issue decrypting the authorization code', $e);
        }
        $code_verifier = $this->get_request_parameter('code_verifier', $request);
        // If a code challenge isn't present but a code verifier is, reject the request to block PKCE downgrade attack
        if (!isset($auth_code_payload->code_challenge) && $code_verifier !== null) {
            throw O_Auth_Server_Exception::invalid_request('code_challenge', 'code_verifier received when no code_challenge is present');
        }
        if (isset($auth_code_payload->code_challenge)) {
            $this->validate_code_challenge($auth_code_payload, $code_verifier);
        }
        // Revoke used auth code before issuing new tokens to prevent replay attacks
        $this->auth_code_repository->revoke_auth_code($auth_code_payload->auth_code_id);
        // Issue and persist new access token
        $access_token = $this->issue_access_token($access_token_ttl, $client, $auth_code_payload->user_id, $scopes);
        $this->get_emitter()->emit(new Request_Access_Token_Event(Request_Event::ACCESS_TOKEN_ISSUED, $request, $access_token));
        $response_type->set_access_token($access_token);
        // Issue and persist new refresh token if given
        $refresh_token = $this->issue_refresh_token($access_token);
        if ($refresh_token !== null) {
            $this->get_emitter()->emit(new Request_Refresh_Token_Event(Request_Event::REFRESH_TOKEN_ISSUED, $request, $refresh_token));
            $response_type->set_refresh_token($refresh_token);
        }
        return $response_type;
    }
    private function validate_code_challenge(object $auth_code_payload, ?string $code_verifier): void
    {
        if ($code_verifier === null) {
            throw O_Auth_Server_Exception::invalid_request('code_verifier');
        }
        // Validate code_verifier according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.1
        if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $code_verifier) !== 1) {
            throw O_Auth_Server_Exception::invalid_request('code_verifier', 'Code Verifier must follow the specifications of RFC-7636.');
        }
        if (property_exists($auth_code_payload, 'code_challenge_method')) {
            if (isset($this->code_challenge_verifiers[$auth_code_payload->code_challenge_method])) {
                $code_challenge_verifier = $this->code_challenge_verifiers[$auth_code_payload->code_challenge_method];
                if (!property_exists($auth_code_payload, 'code_challenge') || !isset($auth_code_payload->code_challenge) || $code_challenge_verifier->verify_code_challenge($code_verifier, $auth_code_payload->code_challenge) === false) {
                    throw O_Auth_Server_Exception::invalid_grant('Failed to verify `code_verifier`.');
                }
            } else {
                throw O_Auth_Server_Exception::server_error(sprintf('Unsupported code challenge method `%s`', $auth_code_payload->code_challenge_method));
            }
        }
    }
    /**
     * Validate the authorization code.
     */
    private function validate_authorization_code(stdClass $auth_code_payload, Client_Entity_Interface $client, Server_Request_Interface $request): void
    {
        if (!property_exists($auth_code_payload, 'auth_code_id')) {
            throw O_Auth_Server_Exception::invalid_request('code', 'Authorization code malformed');
        }
        if (time() > $auth_code_payload->expire_time) {
            throw O_Auth_Server_Exception::invalid_grant('Authorization code has expired');
        }
        if ($this->auth_code_repository->is_auth_code_revoked($auth_code_payload->auth_code_id) === true) {
            throw O_Auth_Server_Exception::invalid_grant('Authorization code has been revoked');
        }
        if ($auth_code_payload->client_id !== $client->get_identifier()) {
            throw O_Auth_Server_Exception::invalid_request('code', 'Authorization code was not issued to this client');
        }
        // The redirect URI is required in this request if it was specified
        // in the authorization request
        $redirect_uri = $this->get_request_parameter('redirect_uri', $request);
        if ($auth_code_payload->redirect_uri !== null && $redirect_uri === null) {
            throw O_Auth_Server_Exception::invalid_request('redirect_uri');
        }
        // If a redirect URI has been provided ensure it matches the stored redirect URI
        if ($redirect_uri !== null && $auth_code_payload->redirect_uri !== $redirect_uri) {
            throw O_Auth_Server_Exception::invalid_request('redirect_uri', 'Invalid redirect URI');
        }
    }
    /**
     * Return the grant identifier that can be used in matching up requests.
     */
    public function get_identifier(): string
    {
        return 'authorization_code';
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_authorization_request(Server_Request_Interface $request): bool
    {
        return array_key_exists('response_type', $request->get_query_params()) && $request->get_query_params()['response_type'] === 'code' && isset($request->get_query_params()['client_id']);
    }
    /**
     * {@inheritdoc}
     */
    public function validate_authorization_request(Server_Request_Interface $request): Authorization_Request_Interface
    {
        $client_id = $this->get_query_string_parameter('client_id', $request, $this->get_server_parameter('PHP_AUTH_USER', $request));
        if ($client_id === null) {
            throw O_Auth_Server_Exception::invalid_request('client_id');
        }
        $client = $this->get_client_entity_or_fail($client_id, $request);
        $redirect_uri = $this->get_query_string_parameter('redirect_uri', $request);
        if ($redirect_uri !== null) {
            $this->validate_redirect_uri($redirect_uri, $client, $request);
        } elseif ($client->get_redirect_uri() === '' || is_array($client->get_redirect_uri()) && count($client->get_redirect_uri()) !== 1) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::CLIENT_AUTHENTICATION_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_client($request);
        }
        $state_parameter = $this->get_query_string_parameter('state', $request);
        $scopes = $this->validate_scopes($this->get_query_string_parameter('scope', $request, $this->default_scope), $this->make_redirect_uri($redirect_uri ?? $this->get_client_redirect_uri($client), $state_parameter !== null ? ['state' => $state_parameter] : []));
        $authorization_request = $this->create_authorization_request();
        $authorization_request->set_grant_type_id($this->get_identifier());
        $authorization_request->set_client($client);
        $authorization_request->set_redirect_uri($redirect_uri);
        if ($state_parameter !== null) {
            $authorization_request->set_state($state_parameter);
        }
        $authorization_request->set_scopes($scopes);
        $code_challenge = $this->get_query_string_parameter('code_challenge', $request);
        if ($code_challenge !== null) {
            $code_challenge_method = $this->get_query_string_parameter('code_challenge_method', $request, 'plain');
            if ($code_challenge_method === null) {
                throw O_Auth_Server_Exception::invalid_request('code_challenge_method', 'Code challenge method must be provided when `code_challenge` is set.');
            }
            if (array_key_exists($code_challenge_method, $this->code_challenge_verifiers) === false) {
                throw O_Auth_Server_Exception::invalid_request('code_challenge_method', 'Code challenge method must be one of ' . implode(', ', array_map(fn(int|string $method) => '`' . $method . '`', array_keys($this->code_challenge_verifiers))));
            }
            // Validate code_challenge according to RFC-7636
            // @see: https://tools.ietf.org/html/rfc7636#section-4.2
            if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $code_challenge) !== 1) {
                throw O_Auth_Server_Exception::invalid_request('code_challenge', 'Code challenge must follow the specifications of RFC-7636.');
            }
            $authorization_request->set_code_challenge($code_challenge);
            $authorization_request->set_code_challenge_method($code_challenge_method);
        } elseif ($this->require_code_challenge_for_public_clients && !$client->is_confidential()) {
            throw O_Auth_Server_Exception::invalid_request('code_challenge', 'Code challenge must be provided for public clients');
        }
        return $authorization_request;
    }
    /**
     * {@inheritdoc}
     */
    public function complete_authorization_request(Authorization_Request_Interface $authorization_request): Response_Type_Interface
    {
        if ($authorization_request->get_user() instanceof User_Entity_Interface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }
        $final_redirect_uri = $authorization_request->get_redirect_uri() ?? $this->get_client_redirect_uri($authorization_request->get_client());
        // The user approved the client, redirect them back with an auth code
        if ($authorization_request->is_authorization_approved() === true) {
            $auth_code = $this->issue_auth_code($this->auth_code_ttl, $authorization_request->get_client(), $authorization_request->get_user()->get_identifier(), $authorization_request->get_redirect_uri(), $authorization_request->get_scopes());
            $payload = ['client_id' => $auth_code->get_client()->get_identifier(), 'redirect_uri' => $auth_code->get_redirect_uri(), 'auth_code_id' => $auth_code->get_identifier(), 'scopes' => $auth_code->get_scopes(), 'user_id' => $auth_code->get_user_identifier(), 'expire_time' => (new DateTimeImmutable())->add($this->auth_code_ttl)->get_timestamp(), 'code_challenge' => $authorization_request->get_code_challenge(), 'code_challenge_method' => $authorization_request->get_code_challenge_method()];
            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new LogicException('An error was encountered when JSON encoding the authorization request response');
            }
            $response = new Redirect_Response();
            $response->set_redirect_uri($this->make_redirect_uri($final_redirect_uri, ['code' => $this->encrypt($json_payload), 'state' => $authorization_request->get_state()]));
            return $response;
        }
        // The user denied the client, redirect them back with an error
        throw O_Auth_Server_Exception::access_denied('The user denied the request', $this->make_redirect_uri($final_redirect_uri, ['state' => $authorization_request->get_state()]));
    }
}
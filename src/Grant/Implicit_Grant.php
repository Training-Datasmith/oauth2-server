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

use function count;
use DateInterval;
use function is_array;
use function is_null;
use League\O_Auth2\Server\Entities\User_Entity_Interface;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Repositories\Refresh_Token_Repository_Interface;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Request_Types\Authorization_Request_Interface;
use League\O_Auth2\Server\Response_Types\Redirect_Response;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use LogicException;
use Psr\Http\Message\Server_Request_Interface;
use function time;
class Implicit_Grant extends Abstract_Authorize_Grant
{
    public function __construct(private readonly DateInterval $access_token_ttl, private readonly string $query_delimiter = '#')
    {
    }
    /**
     * @throws LogicException
     */
    public function set_refresh_token_ttl(DateInterval $refresh_token_ttl): void
    {
        throw new LogicException('The Implicit Grant does not return refresh tokens');
    }
    /**
     * @throws LogicException
     */
    public function set_refresh_token_repository(Refresh_Token_Repository_Interface $refresh_token_repository): void
    {
        throw new LogicException('The Implicit Grant does not return refresh tokens');
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_access_token_request(Server_Request_Interface $request): bool
    {
        return false;
    }
    /**
     * Return the grant identifier that can be used in matching up requests.
     */
    public function get_identifier(): string
    {
        return 'implicit';
    }
    /**
     * Respond to an incoming request.
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Type_Interface $response_type, DateInterval $access_token_ttl): Response_Type_Interface
    {
        throw new LogicException('This grant does not used this method');
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_authorization_request(Server_Request_Interface $request): bool
    {
        return isset($request->get_query_params()['response_type']) && $request->get_query_params()['response_type'] === 'token' && isset($request->get_query_params()['client_id']);
    }
    /**
     * {@inheritdoc}
     */
    public function validate_authorization_request(Server_Request_Interface $request): Authorization_Request_Interface
    {
        $client_id = $this->get_query_string_parameter('client_id', $request, $this->get_server_parameter('PHP_AUTH_USER', $request));
        if (is_null($client_id)) {
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
        $scopes = $this->validate_scopes($this->get_query_string_parameter('scope', $request, $this->default_scope), $this->make_redirect_uri($redirect_uri ?? $this->get_client_redirect_uri($client), $state_parameter !== null ? ['state' => $state_parameter] : [], $this->query_delimiter));
        $authorization_request = $this->create_authorization_request();
        $authorization_request->set_grant_type_id($this->get_identifier());
        $authorization_request->set_client($client);
        $authorization_request->set_redirect_uri($redirect_uri);
        if ($state_parameter !== null) {
            $authorization_request->set_state($state_parameter);
        }
        $authorization_request->set_scopes($scopes);
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
        // The user approved the client, redirect them back with an access token
        if ($authorization_request->is_authorization_approved() === true) {
            // Finalize the requested scopes
            $finalized_scopes = $this->scope_repository->finalize_scopes($authorization_request->get_scopes(), $this->get_identifier(), $authorization_request->get_client(), $authorization_request->get_user()->get_identifier());
            $access_token = $this->issue_access_token($this->access_token_ttl, $authorization_request->get_client(), $authorization_request->get_user()->get_identifier(), $finalized_scopes);
            // TODO: next major release: this method needs `ServerRequestInterface` as an argument
            // $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
            $response = new Redirect_Response();
            $response->set_redirect_uri($this->make_redirect_uri($final_redirect_uri, ['access_token' => $access_token->to_string(), 'token_type' => 'Bearer', 'expires_in' => $access_token->get_expiry_date_time()->get_timestamp() - time(), 'state' => $authorization_request->get_state()], $this->query_delimiter));
            return $response;
        }
        // The user denied the client, redirect them back with an error
        throw O_Auth_Server_Exception::access_denied('The user denied the request', $this->make_redirect_uri($final_redirect_uri, ['state' => $authorization_request->get_state()], $this->query_delimiter));
    }
}
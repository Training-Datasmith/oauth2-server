<?php

/**
 * OAuth 2.0 Password grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Grant;

use DateInterval;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\User_Entity_Interface;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Repositories\Refresh_Token_Repository_Interface;
use League\O_Auth2\Server\Repositories\User_Repository_Interface;
use League\O_Auth2\Server\Request_Access_Token_Event;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Request_Refresh_Token_Event;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use Psr\Http\Message\Server_Request_Interface;
/**
 * Password grant class.
 */
class Password_Grant extends Abstract_Grant
{
    public function __construct(User_Repository_Interface $user_repository, Refresh_Token_Repository_Interface $refresh_token_repository)
    {
        $this->set_user_repository($user_repository);
        $this->set_refresh_token_repository($refresh_token_repository);
        $this->refresh_token_ttl = new DateInterval('P1M');
    }
    /**
     * {@inheritdoc}
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Type_Interface $response_type, DateInterval $access_token_ttl): Response_Type_Interface
    {
        // Validate request
        $client = $this->validate_client($request);
        $scopes = $this->validate_scopes($this->get_request_parameter('scope', $request, $this->default_scope));
        $user = $this->validate_user($request, $client);
        $finalized_scopes = $this->scope_repository->finalize_scopes($scopes, $this->get_identifier(), $client, $user->get_identifier());
        // Issue and persist new access token
        $access_token = $this->issue_access_token($access_token_ttl, $client, $user->get_identifier(), $finalized_scopes);
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
    /**
     * @throws OAuthServerException
     */
    protected function validate_user(Server_Request_Interface $request, Client_Entity_Interface $client): User_Entity_Interface
    {
        $username = $this->get_request_parameter('username', $request) ?? throw O_Auth_Server_Exception::invalid_request('username');
        $password = $this->get_request_parameter('password', $request) ?? throw O_Auth_Server_Exception::invalid_request('password');
        $user = $this->user_repository->get_user_entity_by_user_credentials($username, $password, $this->get_identifier(), $client);
        if ($user instanceof User_Entity_Interface === false) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::USER_AUTHENTICATION_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_credentials();
        }
        return $user;
    }
    /**
     * {@inheritdoc}
     */
    public function get_identifier(): string
    {
        return 'password';
    }
}
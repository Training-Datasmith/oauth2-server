<?php

/**
 * OAuth 2.0 Client credentials grant.
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
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Request_Access_Token_Event;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use Psr\Http\Message\Server_Request_Interface;
/**
 * Client credentials grant class.
 */
class Client_Credentials_Grant extends Abstract_Grant
{
    /**
     * {@inheritdoc}
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Type_Interface $response_type, DateInterval $access_token_ttl): Response_Type_Interface
    {
        $client = $this->validate_client($request);
        if (!$client->is_confidential()) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::CLIENT_AUTHENTICATION_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_client($request);
        }
        $scopes = $this->validate_scopes($this->get_request_parameter('scope', $request, $this->default_scope));
        // Finalize the requested scopes
        $finalized_scopes = $this->scope_repository->finalize_scopes($scopes, $this->get_identifier(), $client);
        // Issue and persist access token
        $access_token = $this->issue_access_token($access_token_ttl, $client, null, $finalized_scopes);
        // Send event to emitter
        $this->get_emitter()->emit(new Request_Access_Token_Event(Request_Event::ACCESS_TOKEN_ISSUED, $request, $access_token));
        // Inject access token into response type
        $response_type->set_access_token($access_token);
        return $response_type;
    }
    /**
     * {@inheritdoc}
     */
    public function get_identifier(): string
    {
        return 'client_credentials';
    }
}
<?php

/**
 * OAuth 2.0 Refresh token grant.
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
use Exception;
use function implode;
use function in_array;
use function json_decode;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Repositories\Refresh_Token_Repository_Interface;
use League\O_Auth2\Server\Request_Access_Token_Event;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Request_Refresh_Token_Event;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use Psr\Http\Message\Server_Request_Interface;
use function time;
/**
 * Refresh token grant.
 */
class Refresh_Token_Grant extends Abstract_Grant
{
    public function __construct(Refresh_Token_Repository_Interface $refresh_token_repository)
    {
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
        $old_refresh_token = $this->validate_old_refresh_token($request, $client->get_identifier());
        $scopes = $this->validate_scopes($this->get_request_parameter('scope', $request, implode(self::SCOPE_DELIMITER_STRING, $old_refresh_token['scopes'])));
        // The OAuth spec says that a refreshed access token can have the original scopes or fewer so ensure
        // the request doesn't include any new scopes
        foreach ($scopes as $scope) {
            if (in_array($scope->get_identifier(), $old_refresh_token['scopes'], true) === false) {
                throw O_Auth_Server_Exception::invalid_scope($scope->get_identifier());
            }
        }
        $user_id = $old_refresh_token['user_id'];
        if (is_int($user_id)) {
            $user_id = (string) $user_id;
        }
        $scopes = $this->scope_repository->finalize_scopes($scopes, $this->get_identifier(), $client, $user_id);
        // Expire old tokens
        $this->access_token_repository->revoke_access_token($old_refresh_token['access_token_id']);
        if ($this->revoke_refresh_tokens) {
            $this->refresh_token_repository->revoke_refresh_token($old_refresh_token['refresh_token_id']);
        }
        // Issue and persist new access token
        $access_token = $this->issue_access_token($access_token_ttl, $client, $user_id, $scopes);
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
     *
     * @return array<string, mixed>
     */
    protected function validate_old_refresh_token(Server_Request_Interface $request, string $client_id): array
    {
        $encrypted_refresh_token = $this->get_request_parameter('refresh_token', $request) ?? throw O_Auth_Server_Exception::invalid_request('refresh_token');
        // Validate refresh token
        try {
            $refresh_token = $this->decrypt($encrypted_refresh_token);
        } catch (Exception $e) {
            throw O_Auth_Server_Exception::invalid_refresh_token('Cannot decrypt the refresh token', $e);
        }
        $refresh_token_data = json_decode($refresh_token, true);
        if (!is_array($refresh_token_data)) {
            throw O_Auth_Server_Exception::invalid_refresh_token('Cannot decode the refresh token');
        }
        if ($refresh_token_data['client_id'] !== $client_id) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_refresh_token('Token is not linked to client');
        }
        if ($refresh_token_data['expire_time'] < time()) {
            throw O_Auth_Server_Exception::invalid_refresh_token('Token has expired');
        }
        if ($this->refresh_token_repository->is_refresh_token_revoked($refresh_token_data['refresh_token_id']) === true) {
            throw O_Auth_Server_Exception::invalid_refresh_token('Token has been revoked');
        }
        return $refresh_token_data;
    }
    /**
     * {@inheritdoc}
     */
    public function get_identifier(): string
    {
        return 'refresh_token';
    }
}
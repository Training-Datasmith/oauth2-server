<?php

/**
 * OAuth 2.0 Grant type interface.
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
use Defuse\Crypto\Key;
use League\O_Auth2\Server\Crypt_Key_Interface;
use League\O_Auth2\Server\Event_Emitting\Emitter_Aware_Interface;
use League\O_Auth2\Server\Repositories\Access_Token_Repository_Interface;
use League\O_Auth2\Server\Repositories\Client_Repository_Interface;
use League\O_Auth2\Server\Repositories\Scope_Repository_Interface;
use League\O_Auth2\Server\Request_Types\Authorization_Request_Interface;
use League\O_Auth2\Server\Response_Types\Device_Code_Response;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use Psr\Http\Message\Server_Request_Interface;
/**
 * Grant type interface.
 */
interface Grant_Type_Interface extends Emitter_Aware_Interface
{
    /**
     * Set refresh token TTL.
     */
    public function set_refresh_token_ttl(DateInterval $refresh_token_ttl): void;
    /**
     * Return the grant identifier that can be used in matching up requests.
     */
    public function get_identifier(): string;
    /**
     * Respond to an incoming request.
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Type_Interface $response_type, DateInterval $access_token_ttl): Response_Type_Interface;
    /**
     * The grant type should return true if it is able to respond to an authorization request
     */
    public function can_respond_to_authorization_request(Server_Request_Interface $request): bool;
    /**
     * If the grant can respond to an authorization request this method should be called to validate the parameters of
     * the request.
     *
     * If the validation is successful an AuthorizationRequest object will be returned. This object can be safely
     * serialized in a user's session, and can be used during user authentication and authorization.
     */
    public function validate_authorization_request(Server_Request_Interface $request): Authorization_Request_Interface;
    /**
     * Once a user has authenticated and authorized the client the grant can complete the authorization request.
     * The AuthorizationRequest object's $userId property must be set to the authenticated user and the
     * $authorizationApproved property must reflect their desire to authorize or deny the client.
     */
    public function complete_authorization_request(Authorization_Request_Interface $authorization_request): Response_Type_Interface;
    /**
     * The grant type should return true if it is able to respond to this request.
     *
     * For example most grant types will check that the $_POST['grant_type'] property matches it's identifier property.
     */
    public function can_respond_to_access_token_request(Server_Request_Interface $request): bool;
    /**
     * The grant type should return true if it is able to respond to a device authorization request
     */
    public function can_respond_to_device_authorization_request(Server_Request_Interface $request): bool;
    /**
     * If the grant can respond to a device authorization request this method should be called to validate the parameters of
     * the request.
     *
     * If the validation is successful a DeviceAuthorizationRequest object will be returned. This object can be safely
     * serialized in a user's session, and can be used during user authentication and authorization.
     */
    public function respond_to_device_authorization_request(Server_Request_Interface $request): Device_Code_Response;
    /**
     * If the grant can respond to a device authorization request this method should be called to validate the parameters of
     * the request.
     *
     * If the validation is successful a DeviceCode object is persisted.
     */
    public function complete_device_authorization_request(string $device_code, string $user_id, bool $user_approved): void;
    /**
     * Set the client repository.
     */
    public function set_client_repository(Client_Repository_Interface $client_repository): void;
    /**
     * Set the access token repository.
     */
    public function set_access_token_repository(Access_Token_Repository_Interface $access_token_repository): void;
    /**
     * Set the scope repository.
     */
    public function set_scope_repository(Scope_Repository_Interface $scope_repository): void;
    /**
     * Set the default scope.
     */
    public function set_default_scope(string $scope): void;
    /**
     * Set the path to the private key.
     */
    public function set_private_key(Crypt_Key_Interface $private_key): void;
    public function set_encryption_key(Key|string|null $key = null): void;
    /**
     * Enable or prevent the revocation of refresh tokens upon usage.
     */
    public function revoke_refresh_tokens(bool $will_revoke): void;
    /**
     * If set, the minimum interval between device code polling will be
     * returned by the server.
     */
    public function set_interval_visibility(bool $interval_visibility): void;
    /**
     * Checks if the minimum interval between device code polling should be
     * returned by the server.
     */
    public function get_interval_visibility(): bool;
    /**
     * If set, the server will return a full verification URI to the client.
     * This is useful when your device authorization endpoint might not be able
     * to enter the user code easily.
     */
    public function set_include_verification_uri_complete(bool $include_verification_uri_complete): void;
}
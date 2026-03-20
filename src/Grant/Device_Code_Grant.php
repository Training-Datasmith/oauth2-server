<?php

/**
 * OAuth 2.0 Device Code grant.
 *
 * @author      Andrew Millington <andrew@noexceptions.io>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Grant;

use DateInterval;
use DateTimeImmutable;
use Error;
use Exception;
use function is_null;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Device_Code_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Exception\Unique_Token_Identifier_Constraint_Violation_Exception;
use League\O_Auth2\Server\Repositories\Device_Code_Repository_Interface;
use League\O_Auth2\Server\Repositories\Refresh_Token_Repository_Interface;
use League\O_Auth2\Server\Request_Access_Token_Event;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Request_Refresh_Token_Event;
use League\O_Auth2\Server\Response_Types\Device_Code_Response;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use Psr\Http\Message\Server_Request_Interface;
use function random_int;
use function strlen;
use function time;
use TypeError;
/**
 * Device Code grant class.
 */
class Device_Code_Grant extends Abstract_Grant
{
    protected Device_Code_Repository_Interface $device_code_repository;
    private bool $include_verification_uri_complete = false;
    private bool $interval_visibility = false;
    private string $verification_uri;
    public function __construct(Device_Code_Repository_Interface $device_code_repository, Refresh_Token_Repository_Interface $refresh_token_repository, private readonly DateInterval $device_code_ttl, string $verification_uri, private readonly int $retry_interval = 5)
    {
        $this->set_device_code_repository($device_code_repository);
        $this->set_refresh_token_repository($refresh_token_repository);
        $this->refresh_token_ttl = new DateInterval('P1M');
        $this->set_verification_uri($verification_uri);
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_device_authorization_request(Server_Request_Interface $request): bool
    {
        return true;
    }
    /**
     * {@inheritdoc}
     */
    public function respond_to_device_authorization_request(Server_Request_Interface $request): Device_Code_Response
    {
        $client_id = $this->get_request_parameter('client_id', $request, $this->get_server_parameter('PHP_AUTH_USER', $request));
        if ($client_id === null) {
            throw O_Auth_Server_Exception::invalid_request('client_id');
        }
        $client = $this->get_client_entity_or_fail($client_id, $request);
        $scopes = $this->validate_scopes($this->get_request_parameter('scope', $request, $this->default_scope));
        $device_code_entity = $this->issue_device_code($this->device_code_ttl, $client, $this->verification_uri, $scopes);
        $response = new Device_Code_Response();
        if ($this->include_verification_uri_complete === true) {
            $response->include_verification_uri_complete();
        }
        if ($this->interval_visibility === true) {
            $response->include_interval();
        }
        $response->set_device_code_entity($device_code_entity);
        return $response;
    }
    /**
     * {@inheritdoc}
     */
    public function complete_device_authorization_request(string $device_code, string $user_id, bool $user_approved): void
    {
        $device_code = $this->device_code_repository->get_device_code_entity_by_device_code($device_code);
        if ($device_code instanceof Device_Code_Entity_Interface === false) {
            throw O_Auth_Server_Exception::invalid_request('device_code', 'Device code does not exist');
        }
        if ($user_id === '') {
            throw O_Auth_Server_Exception::invalid_request('user_id', 'User ID is required');
        }
        $device_code->set_user_identifier($user_id);
        $device_code->set_user_approved($user_approved);
        $this->device_code_repository->persist_device_code($device_code);
    }
    /**
     * {@inheritdoc}
     */
    public function respond_to_access_token_request(Server_Request_Interface $request, Response_Type_Interface $response_type, DateInterval $access_token_ttl): Response_Type_Interface
    {
        // Validate request
        $client = $this->validate_client($request);
        $device_code_entity = $this->validate_device_code($request, $client);
        // If device code has no user associated, respond with pending or slow down
        if (is_null($device_code_entity->get_user_identifier())) {
            $should_slow_down = $this->device_code_polled_too_soon($device_code_entity->get_last_polled_at());
            $device_code_entity->set_last_polled_at(new DateTimeImmutable());
            $this->device_code_repository->persist_device_code($device_code_entity);
            if ($should_slow_down) {
                throw O_Auth_Server_Exception::slow_down();
            }
            throw O_Auth_Server_Exception::authorization_pending();
        }
        if ($device_code_entity->get_user_approved() === false) {
            throw O_Auth_Server_Exception::access_denied();
        }
        // Finalize the requested scopes
        $finalized_scopes = $this->scope_repository->finalize_scopes($device_code_entity->get_scopes(), $this->get_identifier(), $client, $device_code_entity->get_user_identifier());
        // Issue and persist new access token
        $access_token = $this->issue_access_token($access_token_ttl, $client, $device_code_entity->get_user_identifier(), $finalized_scopes);
        $this->get_emitter()->emit(new Request_Access_Token_Event(Request_Event::ACCESS_TOKEN_ISSUED, $request, $access_token));
        $response_type->set_access_token($access_token);
        // Issue and persist new refresh token if given
        $refresh_token = $this->issue_refresh_token($access_token);
        if ($refresh_token !== null) {
            $this->get_emitter()->emit(new Request_Refresh_Token_Event(Request_Event::REFRESH_TOKEN_ISSUED, $request, $refresh_token));
            $response_type->set_refresh_token($refresh_token);
        }
        $this->device_code_repository->revoke_device_code($device_code_entity->get_identifier());
        return $response_type;
    }
    /**
     * @throws OAuthServerException
     */
    protected function validate_device_code(Server_Request_Interface $request, Client_Entity_Interface $client): Device_Code_Entity_Interface
    {
        $device_code = $this->get_request_parameter('device_code', $request);
        if (is_null($device_code)) {
            throw O_Auth_Server_Exception::invalid_request('device_code');
        }
        $device_code_entity = $this->device_code_repository->get_device_code_entity_by_device_code($device_code);
        if ($device_code_entity instanceof Device_Code_Entity_Interface === false) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::USER_AUTHENTICATION_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_grant();
        }
        if (time() > $device_code_entity->get_expiry_date_time()->get_timestamp()) {
            throw O_Auth_Server_Exception::expired_token('device_code');
        }
        if ($this->device_code_repository->is_device_code_revoked($device_code) === true) {
            throw O_Auth_Server_Exception::invalid_request('device_code', 'Device code has been revoked');
        }
        if ($device_code_entity->get_client()->get_identifier() !== $client->get_identifier()) {
            throw O_Auth_Server_Exception::invalid_request('device_code', 'Device code was not issued to this client');
        }
        return $device_code_entity;
    }
    private function device_code_polled_too_soon(?DateTimeImmutable $last_poll): bool
    {
        return $last_poll !== null && $last_poll->get_timestamp() + $this->retry_interval > time();
    }
    /**
     * Set the verification uri
     */
    public function set_verification_uri(string $verification_uri): void
    {
        $this->verification_uri = $verification_uri;
    }
    /**
     * {@inheritdoc}
     */
    public function get_identifier(): string
    {
        return 'urn:ietf:params:oauth:grant-type:device_code';
    }
    private function set_device_code_repository(Device_Code_Repository_Interface $device_code_repository): void
    {
        $this->device_code_repository = $device_code_repository;
    }
    /**
     * Issue a device code.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issue_device_code(DateInterval $device_code_ttl, Client_Entity_Interface $client, string $verification_uri, array $scopes = []): Device_Code_Entity_Interface
    {
        $max_generation_attempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        $device_code = $this->device_code_repository->get_new_device_code();
        $device_code->set_expiry_date_time((new DateTimeImmutable())->add($device_code_ttl));
        $device_code->set_client($client);
        $device_code->set_verification_uri($verification_uri);
        $device_code->set_interval($this->retry_interval);
        foreach ($scopes as $scope) {
            $device_code->add_scope($scope);
        }
        while ($max_generation_attempts-- > 0) {
            $device_code->set_identifier($this->generate_unique_identifier());
            $device_code->set_user_code($this->generate_user_code());
            try {
                $this->device_code_repository->persist_device_code($device_code);
                return $device_code;
            } catch (Unique_Token_Identifier_Constraint_Violation_Exception $e) {
                if ($max_generation_attempts === 0) {
                    throw $e;
                }
            }
        }
        // This should never be hit. It is here to work around a PHPStan false error
        return $device_code;
    }
    /**
     * Generate a new user code.
     *
     * @throws OAuthServerException
     */
    protected function generate_user_code(int $length = 8): string
    {
        try {
            $user_code = '';
            $user_code_characters = 'BCDFGHJKLMNPQRSTVWXZ';
            while (strlen($user_code) < $length) {
                $user_code .= $user_code_characters[random_int(0, 19)];
            }
            return $user_code;
            // @codeCoverageIgnoreStart
        } catch (TypeError|Error $e) {
            throw O_Auth_Server_Exception::server_error('An unexpected error has occurred', $e);
        } catch (Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw O_Auth_Server_Exception::server_error('Could not generate a random string', $e);
        }
        // @codeCoverageIgnoreEnd
    }
    public function set_interval_visibility(bool $interval_visibility): void
    {
        $this->interval_visibility = $interval_visibility;
    }
    public function get_interval_visibility(): bool
    {
        return $this->interval_visibility;
    }
    public function set_include_verification_uri_complete(bool $include_verification_uri_complete): void
    {
        $this->include_verification_uri_complete = $include_verification_uri_complete;
    }
}
<?php

/**
 * OAuth 2.0 Abstract grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Grant;

use function array_filter;
use function array_key_exists;
use function base64_decode;
use function bin2hex;
use DateInterval;
use DateTimeImmutable;
use DomainException;
use Error;
use Exception;
use function explode;
use function is_string;
use League\O_Auth2\Server\Crypt_Key_Interface;
use League\O_Auth2\Server\Crypt_Trait;
use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
use League\O_Auth2\Server\Entities\Auth_Code_Entity_Interface;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Refresh_Token_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
use League\O_Auth2\Server\Event_Emitting\Emitter_Aware_Polyfill;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Exception\Unique_Token_Identifier_Constraint_Violation_Exception;
use League\O_Auth2\Server\Redirect_Uri_Validators\Redirect_Uri_Validator;
use League\O_Auth2\Server\Repositories\Access_Token_Repository_Interface;
use League\O_Auth2\Server\Repositories\Auth_Code_Repository_Interface;
use League\O_Auth2\Server\Repositories\Client_Repository_Interface;
use League\O_Auth2\Server\Repositories\Refresh_Token_Repository_Interface;
use League\O_Auth2\Server\Repositories\Scope_Repository_Interface;
use League\O_Auth2\Server\Repositories\User_Repository_Interface;
use League\O_Auth2\Server\Request_Event;
use League\O_Auth2\Server\Request_Types\Authorization_Request_Interface;
use League\O_Auth2\Server\Response_Types\Device_Code_Response;
use League\O_Auth2\Server\Response_Types\Response_Type_Interface;
use LogicException;
use Psr\Http\Message\Server_Request_Interface;
use function random_bytes;
use function substr;
use function trim;
use TypeError;
/**
 * Abstract grant class.
 */
abstract class Abstract_Grant implements Grant_Type_Interface
{
    use Emitter_Aware_Polyfill;
    use Crypt_Trait;
    protected const SCOPE_DELIMITER_STRING = ' ';
    protected const MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS = 10;
    protected Client_Repository_Interface $client_repository;
    protected Access_Token_Repository_Interface $access_token_repository;
    protected Scope_Repository_Interface $scope_repository;
    protected Auth_Code_Repository_Interface $auth_code_repository;
    protected Refresh_Token_Repository_Interface $refresh_token_repository;
    protected User_Repository_Interface $user_repository;
    protected DateInterval $refresh_token_ttl;
    protected Crypt_Key_Interface $private_key;
    protected string $default_scope;
    protected bool $revoke_refresh_tokens = true;
    public function set_client_repository(Client_Repository_Interface $client_repository): void
    {
        $this->client_repository = $client_repository;
    }
    public function set_access_token_repository(Access_Token_Repository_Interface $access_token_repository): void
    {
        $this->access_token_repository = $access_token_repository;
    }
    public function set_scope_repository(Scope_Repository_Interface $scope_repository): void
    {
        $this->scope_repository = $scope_repository;
    }
    public function set_refresh_token_repository(Refresh_Token_Repository_Interface $refresh_token_repository): void
    {
        $this->refresh_token_repository = $refresh_token_repository;
    }
    public function set_auth_code_repository(Auth_Code_Repository_Interface $auth_code_repository): void
    {
        $this->auth_code_repository = $auth_code_repository;
    }
    public function set_user_repository(User_Repository_Interface $user_repository): void
    {
        $this->user_repository = $user_repository;
    }
    /**
     * {@inheritdoc}
     */
    public function set_refresh_token_ttl(DateInterval $refresh_token_ttl): void
    {
        $this->refresh_token_ttl = $refresh_token_ttl;
    }
    /**
     * Set the private key
     */
    public function set_private_key(Crypt_Key_Interface $private_key): void
    {
        $this->private_key = $private_key;
    }
    public function set_default_scope(string $scope): void
    {
        $this->default_scope = $scope;
    }
    public function revoke_refresh_tokens(bool $will_revoke): void
    {
        $this->revoke_refresh_tokens = $will_revoke;
    }
    /**
     * Validates client credentials extracted from the request.
     *
     * Client credentials are read from the HTTP Basic Authorization header
     * first; if absent, from the request body (client_id + client_secret).
     * For confidential clients the secret is verified via the repository's
     * validate_client() method.  An empty client_secret for a confidential
     * client is rejected immediately.
     *
     * @security Both missing and invalid client credentials emit a
     *           CLIENT_AUTHENTICATION_FAILED event before throwing, enabling
     *           rate-limiting and alerting without exposing whether the client_id
     *           itself exists (invalid_client is used for both cases).
     *
     * @security Confidential client secrets are never logged or returned to
     *           callers.  The repository receives the raw secret for comparison;
     *           repositories MUST hash-compare secrets (e.g., password_verify)
     *           rather than storing them in plaintext.
     *
     * @param Server_Request_Interface $request  The PSR-7 token request.
     *
     * @throws O_Auth_Server_Exception with error=invalid_request if client_id is missing.
     * @throws O_Auth_Server_Exception with error=invalid_client if credentials are invalid.
     *
     * @return Client_Entity_Interface The validated client entity.
     */
    protected function validate_client(Server_Request_Interface $request): Client_Entity_Interface
    {
        [$client_id, $client_secret] = $this->get_client_credentials($request);
        $client = $this->get_client_entity_or_fail($client_id, $request);
        if ($client->is_confidential()) {
            if ($client_secret === '') {
                throw O_Auth_Server_Exception::invalid_request('client_secret');
            }
            if ($this->client_repository->validate_client($client_id, $client_secret, $this->get_identifier()) === false) {
                $this->get_emitter()->emit(new Request_Event(Request_Event::CLIENT_AUTHENTICATION_FAILED, $request));
                throw O_Auth_Server_Exception::invalid_client($request);
            }
        }
        return $client;
    }
    /**
     * Wrapper around ClientRepository::getClientEntity() that ensures we emit
     * an event and throw an exception if the repo doesn't return a client
     * entity.
     *
     * This is a bit of defensive coding because the interface contract
     * doesn't actually enforce non-null returns/exception-on-no-client so
     * getClientEntity might return null. By contrast, this method will
     * always either return a ClientEntityInterface or throw.
     *
     * @throws OAuthServerException
     */
    protected function get_client_entity_or_fail(string $client_id, Server_Request_Interface $request): Client_Entity_Interface
    {
        $client = $this->client_repository->get_client_entity($client_id);
        if ($client instanceof Client_Entity_Interface === false) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::CLIENT_AUTHENTICATION_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_client($request);
        }
        if ($this->supports_grant_type($client, $this->get_identifier()) === false) {
            throw O_Auth_Server_Exception::unauthorized_client();
        }
        return $client;
    }
    /**
     * Returns true if the given client is authorized to use the given grant type.
     */
    protected function supports_grant_type(Client_Entity_Interface $client, string $grant_type): bool
    {
        return method_exists($client, 'supportsGrantType') === false || $client->supports_grant_type($grant_type) === true;
    }
    /**
     * Gets the client credentials from the request from the request body or
     * the Http Basic Authorization header
     *
     * @return array{0:non-empty-string,1:string}
     *
     * @throws OAuthServerException
     */
    protected function get_client_credentials(Server_Request_Interface $request): array
    {
        [$basic_auth_user, $basic_auth_password] = $this->get_basic_auth_credentials($request);
        $client_id = $this->get_request_parameter('client_id', $request, $basic_auth_user);
        if ($client_id === null) {
            throw O_Auth_Server_Exception::invalid_request('client_id');
        }
        $client_secret = $this->get_request_parameter('client_secret', $request, $basic_auth_password);
        return [$client_id, $client_secret ?? ''];
    }
    /**
     * Validate redirectUri from the request. If a redirect URI is provided
     * ensure it matches what is pre-registered
     *
     * @throws OAuthServerException
     */
    protected function validate_redirect_uri(string $redirect_uri, Client_Entity_Interface $client, Server_Request_Interface $request): void
    {
        $validator = new Redirect_Uri_Validator($client->get_redirect_uri());
        if (!$validator->validate_redirect_uri($redirect_uri)) {
            $this->get_emitter()->emit(new Request_Event(Request_Event::CLIENT_AUTHENTICATION_FAILED, $request));
            throw O_Auth_Server_Exception::invalid_client($request);
        }
    }
    /**
     * Validate scopes in the request.
     *
     * @param null|string|string[] $scopes
     *
     * @throws OAuthServerException
     *
     * @return ScopeEntityInterface[]
     */
    public function validate_scopes(string|array|null $scopes, ?string $redirect_uri = null): array
    {
        if ($scopes === null) {
            $scopes = [];
        } elseif (is_string($scopes)) {
            $scopes = $this->convert_scopes_query_string_to_array($scopes);
        }
        $valid_scopes = [];
        foreach ($scopes as $scope_item) {
            $scope = $this->scope_repository->get_scope_entity_by_identifier($scope_item);
            if ($scope instanceof Scope_Entity_Interface === false) {
                throw O_Auth_Server_Exception::invalid_scope($scope_item, $redirect_uri);
            }
            $valid_scopes[] = $scope;
        }
        return $valid_scopes;
    }
    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @return string[]
     */
    private function convert_scopes_query_string_to_array(string $scopes): array
    {
        return array_filter(explode(self::SCOPE_DELIMITER_STRING, trim($scopes)), static fn($scope): bool => $scope !== '');
    }
    /**
     * Parse request parameter.
     *
     * @param array<array-key, mixed> $request
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    private static function parse_param(string $parameter, array $request, ?string $default = null): ?string
    {
        $value = $request[$parameter] ?? '';
        if (is_scalar($value)) {
            $value = trim((string) $value);
        } else {
            throw O_Auth_Server_Exception::invalid_request($parameter);
        }
        if ($value === '') {
            $value = $default === null ? null : trim($default);
            if ($value === '') {
                $value = null;
            }
        }
        return $value;
    }
    /**
     * Retrieve request parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function get_request_parameter(string $parameter, Server_Request_Interface $request, ?string $default = null): ?string
    {
        return self::parse_param($parameter, (array) $request->get_parsed_body(), $default);
    }
    /**
     * Retrieve HTTP Basic Auth credentials with the Authorization header
     * of a request. First index of the returned array is the username,
     * second is the password (so list() will work). If the header does
     * not exist, or is otherwise an invalid HTTP Basic header, return
     * [null, null].
     *
     * @return array{0:non-empty-string,1:string}|array{0:null,1:null}
     */
    protected function get_basic_auth_credentials(Server_Request_Interface $request): array
    {
        if (!$request->has_header('Authorization')) {
            return [null, null];
        }
        $header = $request->get_header('Authorization')[0];
        if (stripos((string) $header, 'Basic ') !== 0) {
            return [null, null];
        }
        $decoded = base64_decode(substr((string) $header, 6), true);
        if ($decoded === false) {
            return [null, null];
        }
        if (str_contains($decoded, ':') === false) {
            return [null, null];
            // HTTP Basic header without colon isn't valid
        }
        [$username, $password] = explode(':', $decoded, 2);
        if ($username === '') {
            return [null, null];
        }
        return [$username, $password];
    }
    /**
     * Retrieve query string parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function get_query_string_parameter(string $parameter, Server_Request_Interface $request, ?string $default = null): ?string
    {
        return self::parse_param($parameter, $request->get_query_params(), $default);
    }
    /**
     * Retrieve cookie parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function get_cookie_parameter(string $parameter, Server_Request_Interface $request, ?string $default = null): ?string
    {
        return self::parse_param($parameter, $request->get_cookie_params(), $default);
    }
    /**
     * Retrieve server parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function get_server_parameter(string $parameter, Server_Request_Interface $request, ?string $default = null): ?string
    {
        return self::parse_param($parameter, $request->get_server_params(), $default);
    }
    /**
     * Issue an access token.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issue_access_token(DateInterval $access_token_ttl, Client_Entity_Interface $client, string|null $user_identifier, array $scopes = []): Access_Token_Entity_Interface
    {
        $max_generation_attempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        $access_token = $this->access_token_repository->get_new_token($client, $scopes, $user_identifier);
        $access_token->set_expiry_date_time((new DateTimeImmutable())->add($access_token_ttl));
        $access_token->set_private_key($this->private_key);
        while ($max_generation_attempts-- > 0) {
            $access_token->set_identifier($this->generate_unique_identifier());
            try {
                $this->access_token_repository->persist_new_access_token($access_token);
                return $access_token;
            } catch (Unique_Token_Identifier_Constraint_Violation_Exception $e) {
                if ($max_generation_attempts === 0) {
                    throw $e;
                }
            }
        }
        // This should never be hit. It is here to work around a PHPStan false error
        return $access_token;
    }
    /**
     * Issue an auth code.
     *
     * @param non-empty-string       $userIdentifier
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issue_auth_code(DateInterval $auth_code_ttl, Client_Entity_Interface $client, string $user_identifier, ?string $redirect_uri, array $scopes = []): Auth_Code_Entity_Interface
    {
        $max_generation_attempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        $auth_code = $this->auth_code_repository->get_new_auth_code();
        $auth_code->set_expiry_date_time((new DateTimeImmutable())->add($auth_code_ttl));
        $auth_code->set_client($client);
        $auth_code->set_user_identifier($user_identifier);
        if ($redirect_uri !== null) {
            $auth_code->set_redirect_uri($redirect_uri);
        }
        foreach ($scopes as $scope) {
            $auth_code->add_scope($scope);
        }
        while ($max_generation_attempts-- > 0) {
            $auth_code->set_identifier($this->generate_unique_identifier());
            try {
                $this->auth_code_repository->persist_new_auth_code($auth_code);
                return $auth_code;
            } catch (Unique_Token_Identifier_Constraint_Violation_Exception $e) {
                if ($max_generation_attempts === 0) {
                    throw $e;
                }
            }
        }
        // This should never be hit. It is here to work around a PHPStan false error
        return $auth_code;
    }
    /**
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issue_refresh_token(Access_Token_Entity_Interface $access_token): ?Refresh_Token_Entity_Interface
    {
        if ($this->supports_grant_type($access_token->get_client(), 'refresh_token') === false) {
            return null;
        }
        $refresh_token = $this->refresh_token_repository->get_new_refresh_token();
        if ($refresh_token === null) {
            return null;
        }
        $refresh_token->set_expiry_date_time((new DateTimeImmutable())->add($this->refresh_token_ttl));
        $refresh_token->set_access_token($access_token);
        $max_generation_attempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        while ($max_generation_attempts-- > 0) {
            $refresh_token->set_identifier($this->generate_unique_identifier());
            try {
                $this->refresh_token_repository->persist_new_refresh_token($refresh_token);
                return $refresh_token;
            } catch (Unique_Token_Identifier_Constraint_Violation_Exception $e) {
                if ($max_generation_attempts === 0) {
                    throw $e;
                }
            }
        }
        // This should never be hit. It is here to work around a PHPStan false error
        return $refresh_token;
    }
    /**
     * Generates a cryptographically random token identifier.
     *
     * Uses random_bytes() as the entropy source (CSPRNG), then hex-encodes the
     * result.  The default $length of 40 bytes produces an 80-character hex string,
     * providing 320 bits of entropy — well above the 128-bit minimum recommended
     * for token identifiers.
     *
     * @security Do NOT reduce $length below 16 bytes (128 bits).  Shorter
     *           identifiers are vulnerable to brute-force enumeration of token
     *           databases.
     *
     * @security The identifier is used as the JWT jti claim and as the lookup key
     *           in the token repository.  It must be unpredictable and unique.
     *
     * @param int $length  Number of random bytes before hex encoding (default: 40 → 80 hex chars).
     *                     Must be ≥ 1.
     *
     * @return non-empty-string  The hex-encoded random identifier.
     *
     * @throws O_Auth_Server_Exception with error=server_error if the CSPRNG fails.
     */
    protected function generate_unique_identifier(int $length = 40): string
    {
        try {
            if ($length < 1) {
                throw new DomainException('Length must be a positive integer');
            }
            return bin2hex(random_bytes($length));
            // @codeCoverageIgnoreStart
        } catch (TypeError|Error $e) {
            throw O_Auth_Server_Exception::server_error('An unexpected error has occurred', $e);
        } catch (Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw O_Auth_Server_Exception::server_error('Could not generate a random string', $e);
        }
        // @codeCoverageIgnoreEnd
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_access_token_request(Server_Request_Interface $request): bool
    {
        $request_parameters = (array) $request->get_parsed_body();
        return array_key_exists('grant_type', $request_parameters) && $request_parameters['grant_type'] === $this->get_identifier();
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_authorization_request(Server_Request_Interface $request): bool
    {
        return false;
    }
    /**
     * {@inheritdoc}
     */
    public function validate_authorization_request(Server_Request_Interface $request): Authorization_Request_Interface
    {
        throw new LogicException('This grant cannot validate an authorization request');
    }
    /**
     * {@inheritdoc}
     */
    public function complete_authorization_request(Authorization_Request_Interface $authorization_request): Response_Type_Interface
    {
        throw new LogicException('This grant cannot complete an authorization request');
    }
    /**
     * {@inheritdoc}
     */
    public function can_respond_to_device_authorization_request(Server_Request_Interface $request): bool
    {
        return false;
    }
    /**
     * {@inheritdoc}
     */
    public function respond_to_device_authorization_request(Server_Request_Interface $request): Device_Code_Response
    {
        throw new LogicException('This grant cannot validate a device authorization request');
    }
    /**
     * {@inheritdoc}
     */
    public function complete_device_authorization_request(string $device_code, string $user_id, bool $user_approved): void
    {
        throw new LogicException('This grant cannot complete a device authorization request');
    }
    /**
     * {@inheritdoc}
     */
    public function set_interval_visibility(bool $interval_visibility): void
    {
        throw new LogicException('This grant does not support the interval parameter');
    }
    /**
     * {@inheritdoc}
     */
    public function get_interval_visibility(): bool
    {
        return false;
    }
    /**
     * {@inheritdoc}
     */
    public function set_include_verification_uri_complete(bool $include_verification_uri_complete): void
    {
        throw new LogicException('This grant does not support the verification_uri_complete parameter');
    }
}
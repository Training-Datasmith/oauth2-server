<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Exception;

use Exception;
use function htmlspecialchars;
use function http_build_query;
use Psr\Http\Message\Response_Interface;
use Psr\Http\Message\Server_Request_Interface;
use function sprintf;
use Throwable;
class O_Auth_Server_Exception extends Exception
{
    /**
     * @var array<string, string>
     */
    private array $payload;
    private Server_Request_Interface $server_request;
    /**
     * Throw a new exception.
     */
    final public function __construct(string $message, int $code, private readonly string $error_type, private readonly int $http_status_code = 400, private readonly ?string $hint = null, private ?string $redirect_uri = null, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->payload = ['error' => $error_type, 'error_description' => $message];
        if ($hint !== null) {
            $this->payload['hint'] = $hint;
        }
    }
    /**
     * Returns the current payload.
     *
     * @return array<string, string>
     */
    public function get_payload(): array
    {
        return $this->payload;
    }
    /**
     * Updates the current payload.
     *
     * @param array<string, string> $payload
     */
    public function set_payload(array $payload): void
    {
        $this->payload = $payload;
    }
    /**
     * Set the server request that is responsible for generating the exception
     */
    public function set_server_request(Server_Request_Interface $server_request): void
    {
        $this->server_request = $server_request;
    }
    /**
     * Unsupported grant type error.
     */
    public static function unsupported_grant_type(): static
    {
        $error_message = 'The authorization grant type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';
        return new static($error_message, 2, 'unsupported_grant_type', 400, $hint);
    }
    /**
     * Invalid request error.
     */
    public static function invalid_request(string $parameter, ?string $hint = null, ?Throwable $previous = null): static
    {
        $error_message = 'The request is missing a required parameter, includes an invalid parameter value, ' . 'includes a parameter more than once, or is otherwise malformed.';
        $hint ??= sprintf('Check the `%s` parameter', $parameter);
        return new static($error_message, 3, 'invalid_request', 400, $hint, null, $previous);
    }
    /**
     * Invalid client error.
     */
    public static function invalid_client(Server_Request_Interface $server_request): static
    {
        $exception = new static('Client authentication failed', 4, 'invalid_client', 401);
        $exception->set_server_request($server_request);
        return $exception;
    }
    /**
     * Invalid scope error
     */
    public static function invalid_scope(string $scope, string|null $redirect_uri = null): static
    {
        $error_message = 'The requested scope is invalid, unknown, or malformed';
        if ($scope === '') {
            $hint = 'Specify a scope in the request or set a default scope';
        } else {
            $hint = sprintf('Check the `%s` scope', htmlspecialchars($scope, ENT_QUOTES, 'UTF-8', false));
        }
        return new static($error_message, 5, 'invalid_scope', 400, $hint, $redirect_uri);
    }
    /**
     * Invalid credentials error.
     */
    public static function invalid_credentials(): static
    {
        return new static('The user credentials were incorrect.', 6, 'invalid_grant', 400);
    }
    /**
     * Server error.
     *
     * @codeCoverageIgnore
     */
    public static function server_error(string $hint, ?Throwable $previous = null): static
    {
        return new static('The authorization server encountered an unexpected condition which prevented it from fulfilling' . ' the request: ' . $hint, 7, 'server_error', 500, null, null, $previous);
    }
    /**
     * Invalid refresh token.
     */
    public static function invalid_refresh_token(?string $hint = null, ?Throwable $previous = null): static
    {
        return new static('The refresh token is invalid.', 8, 'invalid_grant', 400, $hint, null, $previous);
    }
    /**
     * Access denied.
     */
    public static function access_denied(?string $hint = null, ?string $redirect_uri = null, ?Throwable $previous = null): static
    {
        return new static('The resource owner or authorization server denied the request.', 9, 'access_denied', 401, $hint, $redirect_uri, $previous);
    }
    /**
     * Invalid grant.
     */
    public static function invalid_grant(string $hint = ''): static
    {
        return new static('The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token ' . 'is invalid, expired, revoked, does not match the redirection URI used in the authorization request, ' . 'or was issued to another client.', 10, 'invalid_grant', 400, $hint);
    }
    public function get_error_type(): string
    {
        return $this->error_type;
    }
    /**
     * Expired token error.
     *
     * @param Throwable $previous Previous exception
     */
    public static function expired_token(?string $hint = null, ?Throwable $previous = null): static
    {
        $error_message = 'The `device_code` has expired and the device ' . 'authorization session has concluded.';
        return new static($error_message, 11, 'expired_token', 400, $hint, null, $previous);
    }
    public static function authorization_pending(string $hint = '', ?Throwable $previous = null): static
    {
        return new static('The authorization request is still pending as the end user ' . 'hasn\'t yet completed the user interaction steps. The client ' . 'SHOULD repeat the Access Token Request to the token endpoint', 12, 'authorization_pending', 400, $hint, null, $previous);
    }
    /**
     * Slow down error used with the Device Authorization Grant.
     *
     */
    public static function slow_down(string $hint = '', ?Throwable $previous = null): static
    {
        return new static('The authorization request is still pending and polling should ' . 'continue, but the interval MUST be increased ' . 'by 5 seconds for this and all subsequent requests.', 13, 'slow_down', 400, $hint, null, $previous);
    }
    /**
     * Unauthorized client error.
     */
    public static function unauthorized_client(?string $hint = null): static
    {
        return new static('The authenticated client is not authorized to use this authorization grant type.', 14, 'unauthorized_client', 400, $hint);
    }
    /**
     * Generate a HTTP response.
     */
    public function generate_http_response(Response_Interface $response, bool $use_fragment = false, int $json_options = 0): Response_Interface
    {
        $headers = $this->get_http_headers();
        $payload = $this->get_payload();
        if ($this->redirect_uri !== null) {
            if ($use_fragment === true) {
                $this->redirect_uri .= str_contains($this->redirect_uri, '#') === false ? '#' : '&';
            } else {
                $this->redirect_uri .= str_contains($this->redirect_uri, '?') === false ? '?' : '&';
            }
            return $response->with_status(302)->with_header('Location', $this->redirect_uri . http_build_query($payload));
        }
        foreach ($headers as $header => $content) {
            $response = $response->with_header($header, $content);
        }
        $json_encoded_payload = json_encode($payload, $json_options);
        $response_body = $json_encoded_payload === false ? 'JSON encoding of payload failed' : $json_encoded_payload;
        $response->get_body()->write($response_body);
        return $response->with_status($this->get_http_status_code());
    }
    /**
     * Get all headers that have to be send with the error response.
     *
     * @return array<string, string> Array with header values
     */
    public function get_http_headers(): array
    {
        $headers = ['Content-type' => 'application/json'];
        // Add "WWW-Authenticate" header
        //
        // RFC 6749, section 5.2.:
        // "If the client attempted to authenticate via the 'Authorization'
        // request header field, the authorization server MUST
        // respond with an HTTP 401 (Unauthorized) status code and
        // include the "WWW-Authenticate" response header field
        // matching the authentication scheme used by the client.
        if ($this->error_type === 'invalid_client' && $this->request_has_authorization_header()) {
            $auth_scheme = str_starts_with((string) $this->server_request->get_header('Authorization')[0], 'Bearer') ? 'Bearer' : 'Basic';
            $headers['WWW-Authenticate'] = $auth_scheme . ' realm="OAuth"';
        }
        return $headers;
    }
    /**
     * Check if the exception has an associated redirect URI.
     *
     * Returns whether the exception includes a redirect, since
     * getHttpStatusCode() doesn't return a 302 when there's a
     * redirect enabled. This helps when you want to override local
     * error pages but want to let redirects through.
     */
    public function has_redirect(): bool
    {
        return $this->redirect_uri !== null;
    }
    /**
     * Returns the Redirect URI used for redirecting.
     */
    public function get_redirect_uri(): ?string
    {
        return $this->redirect_uri;
    }
    /**
     * Returns the HTTP status code to send when the exceptions is output.
     */
    public function get_http_status_code(): int
    {
        return $this->http_status_code;
    }
    public function get_hint(): ?string
    {
        return $this->hint;
    }
    /**
     * Check if the request has a non-empty 'Authorization' header value.
     *
     * Returns true if the header is present and not an empty string, false
     * otherwise.
     */
    private function request_has_authorization_header(): bool
    {
        if (!$this->server_request->has_header('Authorization')) {
            return false;
        }
        $authorization_header = $this->server_request->get_header('Authorization');
        // Common .htaccess configurations yield an empty string for the
        // 'Authorization' header when one is not provided by the client.
        // For practical purposes that case should be treated as though the
        // header isn't present.
        // See https://github.com/thephpleague/oauth2-server/issues/1162
        if ($authorization_header === [] || $authorization_header[0] === '') {
            return false;
        }
        return true;
    }
}
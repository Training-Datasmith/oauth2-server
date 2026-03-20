<?php

/**
 * @author      Sebastiano Degan <sebdeg87@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Redirect_Uri_Validators;

use function in_array;
use function is_string;
use League\Uri\Exceptions\Syntax_Error;
use League\Uri\Uri;
class Redirect_Uri_Validator implements Redirect_Uri_Validator_Interface
{
    /**
     * @var string[]
     */
    private array $allowed_redirect_uris;
    /**
     * New validator instance for the given uri
     *
     * @param string[]|string $allowedRedirectUris
     */
    public function __construct(array|string $allowed_redirect_uris)
    {
        if (is_string($allowed_redirect_uris)) {
            $this->allowed_redirect_uris = [$allowed_redirect_uris];
        } else {
            $this->allowed_redirect_uris = $allowed_redirect_uris;
        }
    }
    /**
     * Validates the redirect uri.
     *
     * @return bool Return true if valid, false otherwise
     */
    public function validate_redirect_uri(string $redirect_uri): bool
    {
        if ($this->is_loopback_uri($redirect_uri)) {
            return $this->match_uri_excluding_port($redirect_uri);
        }
        return $this->match_exact_uri($redirect_uri);
    }
    /**
     * According to section 7.3 of rfc8252, loopback uris are:
     *   - "http://127.0.0.1:{port}/{path}" for IPv4
     *   - "http://[::1]:{port}/{path}" for IPv6
     */
    private function is_loopback_uri(string $redirect_uri): bool
    {
        try {
            $uri = Uri::new($redirect_uri);
        } catch (Syntax_Error) {
            return false;
        }
        return $uri->get_scheme() === 'http' && in_array($uri->get_host(), ['127.0.0.1', '[::1]'], true);
    }
    /**
     * Find an exact match among allowed uris
     */
    private function match_exact_uri(string $redirect_uri): bool
    {
        return in_array($redirect_uri, $this->allowed_redirect_uris, true);
    }
    /**
     * Find a match among allowed uris, allowing for different port numbers
     */
    private function match_uri_excluding_port(string $redirect_uri): bool
    {
        $parsed_url = $this->parse_url_and_remove_port($redirect_uri);
        foreach ($this->allowed_redirect_uris as $allowed_redirect_uri) {
            if ($parsed_url === $this->parse_url_and_remove_port($allowed_redirect_uri)) {
                return true;
            }
        }
        return false;
    }
    /**
     * Parse an url like \parse_url, excluding the port
     */
    private function parse_url_and_remove_port(string $url): string
    {
        $uri = Uri::new($url);
        return (string) $uri->with_port(null);
    }
}
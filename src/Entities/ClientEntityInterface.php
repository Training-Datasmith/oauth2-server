<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities;

interface Client_Entity_Interface
{
    /**
     * Get the client's identifier.
     *
     * @return non-empty-string
     */
    public function get_identifier(): string;
    /**
     * Get the client's name.
     */
    public function get_name(): string;
    /**
     * Returns the registered redirect URI (as a string). Alternatively return
     * an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function get_redirect_uri(): string|array;
    /**
     * Returns true if the client is confidential.
     */
    public function is_confidential(): bool;
    /*
     * Returns true if the client supports the given grant type.
     *
     * TODO: To be added in a future major release.
     */
    // public function supportsGrantType(string $grantType): bool;
}
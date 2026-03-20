<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities\Traits;

trait Client_Trait
{
    protected string $name;
    /**
     * @var string|string[]
     */
    protected string|array $redirect_uri;
    protected bool $is_confidential = false;
    /**
     * Get the client's name.
     *
     *
     * @codeCoverageIgnore
     */
    public function get_name(): string
    {
        return $this->name;
    }
    /**
     * Returns the registered redirect URI (as a string). Alternatively return
     * an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function get_redirect_uri(): string|array
    {
        return $this->redirect_uri;
    }
    /**
     * Returns true if the client is confidential.
     */
    public function is_confidential(): bool
    {
        return $this->is_confidential;
    }
    /**
     * Returns true if the client supports the given grant type.
     */
    public function supports_grant_type(string $grant_type): bool
    {
        return true;
    }
}
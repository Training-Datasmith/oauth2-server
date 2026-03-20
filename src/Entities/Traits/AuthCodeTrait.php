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

trait Auth_Code_Trait
{
    protected ?string $redirect_uri = null;
    public function get_redirect_uri(): string|null
    {
        return $this->redirect_uri;
    }
    public function set_redirect_uri(string $uri): void
    {
        $this->redirect_uri = $uri;
    }
}
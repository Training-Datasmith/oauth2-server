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

interface Auth_Code_Entity_Interface extends Token_Interface
{
    public function get_redirect_uri(): string|null;
    public function set_redirect_uri(string $uri): void;
}
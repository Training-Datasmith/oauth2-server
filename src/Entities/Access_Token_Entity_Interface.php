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

use League\O_Auth2\Server\Crypt_Key_Interface;
interface Access_Token_Entity_Interface extends Token_Interface
{
    /**
     * Set a private key used to encrypt the access token.
     */
    public function set_private_key(Crypt_Key_Interface $private_key): void;
    /**
     * Generate a string representation of the access token.
     */
    public function to_string(): string;
}
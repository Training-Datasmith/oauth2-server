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

interface User_Entity_Interface
{
    /**
     * Return the user's identifier.
     *
     * @return non-empty-string
     */
    public function get_identifier(): string;
}
<?php

/**
 * @author      Ivan Kurnosov <zerkms@zerkms.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Exception;

class Unique_Token_Identifier_Constraint_Violation_Exception extends O_Auth_Server_Exception
{
    public static function create(): Unique_Token_Identifier_Constraint_Violation_Exception
    {
        $error_message = 'Could not create unique access token identifier';
        return new static($error_message, 100, 'access_token_duplicate', 500);
    }
}
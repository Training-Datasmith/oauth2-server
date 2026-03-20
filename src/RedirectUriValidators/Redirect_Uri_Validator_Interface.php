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

interface Redirect_Uri_Validator_Interface
{
    /**
     * Validates the redirect uri.
     */
    public function validate_redirect_uri(string $redirect_uri): bool;
}
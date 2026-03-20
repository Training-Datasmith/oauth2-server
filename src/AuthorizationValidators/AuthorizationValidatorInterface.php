<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Authorization_Validators;

use Psr\Http\Message\Server_Request_Interface;
interface Authorization_Validator_Interface
{
    /**
     * Determine the access token in the authorization header and append OAUth
     * properties to the request as attributes.
     */
    public function validate_authorization(Server_Request_Interface $request): Server_Request_Interface;
}
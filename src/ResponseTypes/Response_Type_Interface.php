<?php

/**
 * OAuth 2.0 Response Type Interface.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Response_Types;

use Defuse\Crypto\Key;
use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
use League\O_Auth2\Server\Entities\Refresh_Token_Entity_Interface;
use Psr\Http\Message\Response_Interface;
interface Response_Type_Interface
{
    public function set_access_token(Access_Token_Entity_Interface $access_token): void;
    public function set_refresh_token(Refresh_Token_Entity_Interface $refresh_token): void;
    public function generate_http_response(Response_Interface $response): Response_Interface;
    public function set_encryption_key(Key|string|null $key = null): void;
}
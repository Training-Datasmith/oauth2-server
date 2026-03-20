<?php

/**
 * OAuth 2.0 Abstract Response Type.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Response_Types;

use League\O_Auth2\Server\Crypt_Key_Interface;
use League\O_Auth2\Server\Crypt_Trait;
use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
use League\O_Auth2\Server\Entities\Refresh_Token_Entity_Interface;
use Sensitive_Parameter;
abstract class Abstract_Response_Type implements Response_Type_Interface
{
    use Crypt_Trait;
    protected Access_Token_Entity_Interface $access_token;
    protected Refresh_Token_Entity_Interface $refresh_token;
    protected Crypt_Key_Interface $private_key;
    public function set_access_token(
        #[Sensitive_Parameter]
        Access_Token_Entity_Interface $access_token
    ): void
    {
        $this->access_token = $access_token;
    }
    public function set_refresh_token(
        #[Sensitive_Parameter]
        Refresh_Token_Entity_Interface $refresh_token
    ): void
    {
        $this->refresh_token = $refresh_token;
    }
    public function set_private_key(
        #[Sensitive_Parameter]
        Crypt_Key_Interface $key
    ): void
    {
        $this->private_key = $key;
    }
}
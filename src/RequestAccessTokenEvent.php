<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server;

use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
use Psr\Http\Message\Server_Request_Interface;
use Sensitive_Parameter;
class Request_Access_Token_Event extends Request_Event
{
    public function __construct(
        string $name,
        Server_Request_Interface $request,
        #[Sensitive_Parameter]
        private readonly Access_Token_Entity_Interface $access_token
    )
    {
        parent::__construct($name, $request);
    }
    /**
     * @codeCoverageIgnore
     */
    public function get_access_token(): Access_Token_Entity_Interface
    {
        return $this->access_token;
    }
}
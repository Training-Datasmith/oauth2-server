<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Middleware;

use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Resource_Server;
use Psr\Http\Message\Response_Interface;
use Psr\Http\Message\Server_Request_Interface;
class Resource_Server_Middleware
{
    public function __construct(private readonly Resource_Server $server)
    {
    }
    public function __invoke(Server_Request_Interface $request, Response_Interface $response, callable $next): Response_Interface
    {
        try {
            $request = $this->server->validate_authenticated_request($request);
        } catch (O_Auth_Server_Exception $exception) {
            return $exception->generate_http_response($response);
        }
        // Pass the request and response on to the next responder in the chain
        return $next($request, $response);
    }
}
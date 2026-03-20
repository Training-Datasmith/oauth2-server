<?php

/**
 * Abstract authorization grant.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Grant;

use function http_build_query;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Request_Types\Authorization_Request;
use League\O_Auth2\Server\Request_Types\Authorization_Request_Interface;
abstract class Abstract_Authorize_Grant extends Abstract_Grant
{
    /**
     * @param array<array-key,mixed> $params
     */
    public function make_redirect_uri(string $uri, array $params = [], string $query_delimiter = '?'): string
    {
        $uri .= str_contains($uri, $query_delimiter) ? '&' : $query_delimiter;
        return $uri . http_build_query($params);
    }
    protected function create_authorization_request(): Authorization_Request_Interface
    {
        return new Authorization_Request();
    }
    /**
     * Get the client redirect URI.
     */
    protected function get_client_redirect_uri(Client_Entity_Interface $client): string
    {
        return is_array($client->get_redirect_uri()) ? $client->get_redirect_uri()[0] : $client->get_redirect_uri();
    }
}
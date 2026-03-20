<?php

/**
 * OAuth 2.0 Redirect Response.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Response_Types;

use Psr\Http\Message\Response_Interface;
class Redirect_Response extends Abstract_Response_Type
{
    private string $redirect_uri;
    public function set_redirect_uri(string $redirect_uri): void
    {
        $this->redirect_uri = $redirect_uri;
    }
    public function generate_http_response(Response_Interface $response): Response_Interface
    {
        return $response->with_status(302)->with_header('Location', $this->redirect_uri);
    }
}
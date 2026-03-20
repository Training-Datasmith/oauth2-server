<?php

/**
 * OAuth 2.0 Bearer Token Response.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Response_Types;

use function array_merge;
use function json_encode;
use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
use LogicException;
use Psr\Http\Message\Response_Interface;
use Sensitive_Parameter;
use function time;
class Bearer_Token_Response extends Abstract_Response_Type
{
    public function generate_http_response(Response_Interface $response): Response_Interface
    {
        $expire_date_time = $this->access_token->get_expiry_date_time()->get_timestamp();
        $response_params = ['token_type' => 'Bearer', 'expires_in' => $expire_date_time - time(), 'access_token' => $this->access_token->to_string()];
        if (isset($this->refresh_token)) {
            $refresh_token_payload = json_encode(['client_id' => $this->access_token->get_client()->get_identifier(), 'refresh_token_id' => $this->refresh_token->get_identifier(), 'access_token_id' => $this->access_token->get_identifier(), 'scopes' => $this->access_token->get_scopes(), 'user_id' => $this->access_token->get_user_identifier(), 'expire_time' => $this->refresh_token->get_expiry_date_time()->get_timestamp()]);
            if ($refresh_token_payload === false) {
                throw new LogicException('Error encountered JSON encoding the refresh token payload');
            }
            $response_params['refresh_token'] = $this->encrypt($refresh_token_payload);
        }
        $response_params = json_encode(array_merge($this->get_extra_params($this->access_token), $response_params));
        if ($response_params === false) {
            throw new LogicException('Error encountered JSON encoding response parameters');
        }
        $response = $response->with_status(200)->with_header('pragma', 'no-cache')->with_header('cache-control', 'no-store')->with_header('content-type', 'application/json; charset=UTF-8');
        $response->get_body()->write($response_params);
        return $response;
    }
    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array<array-key,mixed>
     */
    protected function get_extra_params(
        #[Sensitive_Parameter]
        Access_Token_Entity_Interface $access_token
    ): array
    {
        return [];
    }
}
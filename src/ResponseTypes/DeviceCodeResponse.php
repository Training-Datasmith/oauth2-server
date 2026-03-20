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

use function json_encode;
use League\O_Auth2\Server\Entities\Device_Code_Entity_Interface;
use LogicException;
use Psr\Http\Message\Response_Interface;
use function time;
class Device_Code_Response extends Abstract_Response_Type
{
    protected Device_Code_Entity_Interface $device_code_entity;
    private bool $include_verification_uri_complete = false;
    private bool $include_interval = false;
    /**
     * {@inheritdoc}
     */
    public function generate_http_response(Response_Interface $response): Response_Interface
    {
        $expire_date_time = $this->device_code_entity->get_expiry_date_time()->get_timestamp();
        $response_params = ['device_code' => $this->device_code_entity->get_identifier(), 'user_code' => $this->device_code_entity->get_user_code(), 'verification_uri' => $this->device_code_entity->get_verification_uri(), 'expires_in' => $expire_date_time - time()];
        if ($this->include_verification_uri_complete === true) {
            $response_params['verification_uri_complete'] = $this->device_code_entity->get_verification_uri_complete();
        }
        if ($this->include_interval === true) {
            $response_params['interval'] = $this->device_code_entity->get_interval();
        }
        $response_params = json_encode($response_params);
        if ($response_params === false) {
            throw new LogicException('Error encountered JSON encoding response parameters');
        }
        $response = $response->with_status(200)->with_header('pragma', 'no-cache')->with_header('cache-control', 'no-store')->with_header('content-type', 'application/json; charset=UTF-8');
        $response->get_body()->write($response_params);
        return $response;
    }
    /**
     * {@inheritdoc}
     */
    public function set_device_code_entity(Device_Code_Entity_Interface $device_code_entity): void
    {
        $this->device_code_entity = $device_code_entity;
    }
    public function include_verification_uri_complete(): void
    {
        $this->include_verification_uri_complete = true;
    }
    public function include_interval(): void
    {
        $this->include_interval = true;
    }
    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array<array-key,mixed>
     */
    protected function get_extra_params(Device_Code_Entity_Interface $device_code): array
    {
        return [];
    }
}
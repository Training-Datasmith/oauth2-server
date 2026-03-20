<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities\Traits;

use DateTimeImmutable;
use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
trait Refresh_Token_Trait
{
    protected Access_Token_Entity_Interface $access_token;
    protected DateTimeImmutable $expiry_date_time;
    /**
     * {@inheritdoc}
     */
    public function set_access_token(Access_Token_Entity_Interface $access_token): void
    {
        $this->access_token = $access_token;
    }
    /**
     * {@inheritdoc}
     */
    public function get_access_token(): Access_Token_Entity_Interface
    {
        return $this->access_token;
    }
    /**
     * Get the token's expiry date time.
     */
    public function get_expiry_date_time(): DateTimeImmutable
    {
        return $this->expiry_date_time;
    }
    /**
     * Set the date time when the token expires.
     */
    public function set_expiry_date_time(DateTimeImmutable $date_time): void
    {
        $this->expiry_date_time = $date_time;
    }
}
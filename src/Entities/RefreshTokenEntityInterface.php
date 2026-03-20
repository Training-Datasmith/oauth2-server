<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities;

use DateTimeImmutable;
interface Refresh_Token_Entity_Interface
{
    /**
     * Get the token's identifier.
     *
     * @return non-empty-string
     */
    public function get_identifier(): string;
    /**
     * Set the token's identifier.
     *
     * @param non-empty-string $identifier
     */
    public function set_identifier(string $identifier): void;
    /**
     * Get the token's expiry date time.
     */
    public function get_expiry_date_time(): DateTimeImmutable;
    /**
     * Set the date time when the token expires.
     */
    public function set_expiry_date_time(DateTimeImmutable $date_time): void;
    /**
     * Set the access token that the refresh token was associated with.
     */
    public function set_access_token(Access_Token_Entity_Interface $access_token): void;
    /**
     * Get the access token that the refresh token was originally associated with.
     */
    public function get_access_token(): Access_Token_Entity_Interface;
}
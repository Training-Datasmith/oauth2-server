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
interface Device_Code_Entity_Interface extends Token_Interface
{
    public function get_user_code(): string;
    public function set_user_code(string $user_code): void;
    public function get_verification_uri(): string;
    public function set_verification_uri(string $verification_uri): void;
    public function get_verification_uri_complete(): string;
    public function get_last_polled_at(): ?DateTimeImmutable;
    public function set_last_polled_at(DateTimeImmutable $last_polled_at): void;
    public function get_interval(): int;
    public function set_interval(int $interval): void;
    public function get_user_approved(): bool;
    public function set_user_approved(bool $user_approved): void;
}
<?php

/**
 * @author      Andrew Millington <andrew@noexceptions.io>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities\Traits;

use DateTimeImmutable;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
trait Device_Code_Trait
{
    private bool $user_approved = false;
    private bool $include_verification_uri_complete = false;
    private int $interval = 5;
    private string $user_code;
    private string $verification_uri;
    private ?DateTimeImmutable $last_polled_at = null;
    public function get_user_code(): string
    {
        return $this->user_code;
    }
    public function set_user_code(string $user_code): void
    {
        $this->user_code = $user_code;
    }
    public function get_verification_uri(): string
    {
        return $this->verification_uri;
    }
    public function set_verification_uri(string $verification_uri): void
    {
        $this->verification_uri = $verification_uri;
    }
    public function get_verification_uri_complete(): string
    {
        return $this->verification_uri . '?user_code=' . $this->user_code;
    }
    abstract public function get_client(): Client_Entity_Interface;
    abstract public function get_expiry_date_time(): DateTimeImmutable;
    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function get_scopes(): array;
    /**
     * @return non-empty-string
     */
    abstract public function get_identifier(): string;
    public function get_last_polled_at(): ?DateTimeImmutable
    {
        return $this->last_polled_at;
    }
    public function set_last_polled_at(DateTimeImmutable $last_polled_at): void
    {
        $this->last_polled_at = $last_polled_at;
    }
    public function get_interval(): int
    {
        return $this->interval;
    }
    public function set_interval(int $interval): void
    {
        $this->interval = $interval;
    }
    public function get_user_approved(): bool
    {
        return $this->user_approved;
    }
    public function set_user_approved(bool $user_approved): void
    {
        $this->user_approved = $user_approved;
    }
    public function get_verification_uri_complete_in_auth_response(): bool
    {
        return $this->include_verification_uri_complete;
    }
    public function set_verification_uri_complete_in_auth_response(bool $include_verification_uri_complete): void
    {
        $this->include_verification_uri_complete = $include_verification_uri_complete;
    }
}
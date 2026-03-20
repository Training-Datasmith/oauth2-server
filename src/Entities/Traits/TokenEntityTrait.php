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

use function array_values;
use DateTimeImmutable;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
trait Token_Entity_Trait
{
    /**
     * @var ScopeEntityInterface[]
     */
    protected array $scopes = [];
    protected DateTimeImmutable $expiry_date_time;
    /**
     * @var non-empty-string|null
     */
    protected string|null $user_identifier = null;
    protected Client_Entity_Interface $client;
    /**
     * Associate a scope with the token.
     */
    public function add_scope(Scope_Entity_Interface $scope): void
    {
        $this->scopes[$scope->get_identifier()] = $scope;
    }
    /**
     * Return an array of scopes associated with the token.
     *
     * @return ScopeEntityInterface[]
     */
    public function get_scopes(): array
    {
        return array_values($this->scopes);
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
    /**
     * Set the identifier of the user associated with the token.
     *
     * @param non-empty-string $identifier The identifier of the user
     */
    public function set_user_identifier(string $identifier): void
    {
        $this->user_identifier = $identifier;
    }
    /**
     * Get the token user's identifier.
     *
     * @return non-empty-string|null
     */
    public function get_user_identifier(): string|null
    {
        return $this->user_identifier;
    }
    /**
     * Get the client that the token was issued to.
     */
    public function get_client(): Client_Entity_Interface
    {
        return $this->client;
    }
    /**
     * Set the client that the token was issued to.
     */
    public function set_client(Client_Entity_Interface $client): void
    {
        $this->client = $client;
    }
}
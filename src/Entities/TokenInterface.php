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
interface Token_Interface
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
     * Set the identifier of the user associated with the token.
     *
     * @param non-empty-string $identifier
     */
    public function set_user_identifier(string $identifier): void;
    /**
     * Get the token user's identifier.
     *
     * @return non-empty-string|null
     */
    public function get_user_identifier(): string|null;
    /**
     * Get the client that the token was issued to.
     */
    public function get_client(): Client_Entity_Interface;
    /**
     * Set the client that the token was issued to.
     */
    public function set_client(Client_Entity_Interface $client): void;
    /**
     * Associate a scope with the token.
     */
    public function add_scope(Scope_Entity_Interface $scope): void;
    /**
     * Return an array of scopes associated with the token.
     *
     * @return ScopeEntityInterface[]
     */
    public function get_scopes(): array;
}
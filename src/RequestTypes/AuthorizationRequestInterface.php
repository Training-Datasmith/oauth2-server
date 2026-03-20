<?php

/**
 * @author      Patrick Rodacker <dev@rodacker.de>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Request_Types;

use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
use League\O_Auth2\Server\Entities\User_Entity_Interface;
interface Authorization_Request_Interface
{
    public function get_user(): User_Entity_Interface|null;
    public function set_state(string $state): void;
    public function get_client(): Client_Entity_Interface;
    public function set_authorization_approved(bool $authorization_approved): void;
    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function set_scopes(array $scopes): void;
    public function set_redirect_uri(?string $redirect_uri): void;
    public function get_redirect_uri(): ?string;
    public function get_code_challenge_method(): ?string;
    public function set_grant_type_id(string $grant_type_id): void;
    public function set_user(User_Entity_Interface $user): void;
    public function set_client(Client_Entity_Interface $client): void;
    public function set_code_challenge(string $code_challenge): void;
    public function is_authorization_approved(): bool;
    public function get_state(): ?string;
    public function get_code_challenge(): ?string;
    public function set_code_challenge_method(string $code_challenge_method): void;
    /**
     * @return ScopeEntityInterface[]
     */
    public function get_scopes(): array;
    public function get_grant_type_id(): string;
}
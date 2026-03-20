<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
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
class Authorization_Request implements Authorization_Request_Interface
{
    /**
     * The grant type identifier
     */
    protected string $grant_type_id;
    /**
     * The client identifier
     */
    protected Client_Entity_Interface $client;
    /**
     * The user identifier
     */
    protected User_Entity_Interface $user;
    /**
     * An array of scope identifiers
     *
     * @var ScopeEntityInterface[]
     */
    protected array $scopes = [];
    /**
     * Has the user authorized the authorization request
     */
    protected bool $authorization_approved = false;
    /**
     * The redirect URI used in the request
     */
    protected ?string $redirect_uri = null;
    /**
     * The state parameter on the authorization request
     */
    protected ?string $state = null;
    /**
     * The code challenge (if provided)
     */
    protected string $code_challenge;
    /**
     * The code challenge method (if provided)
     */
    protected string $code_challenge_method;
    public function get_grant_type_id(): string
    {
        return $this->grant_type_id;
    }
    public function set_grant_type_id(string $grant_type_id): void
    {
        $this->grant_type_id = $grant_type_id;
    }
    public function get_client(): Client_Entity_Interface
    {
        return $this->client;
    }
    public function set_client(Client_Entity_Interface $client): void
    {
        $this->client = $client;
    }
    public function get_user(): ?User_Entity_Interface
    {
        return $this->user ?? null;
    }
    public function set_user(User_Entity_Interface $user): void
    {
        $this->user = $user;
    }
    /**
     * @return ScopeEntityInterface[]
     */
    public function get_scopes(): array
    {
        return $this->scopes;
    }
    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function set_scopes(array $scopes): void
    {
        $this->scopes = $scopes;
    }
    public function is_authorization_approved(): bool
    {
        return $this->authorization_approved;
    }
    public function set_authorization_approved(bool $authorization_approved): void
    {
        $this->authorization_approved = $authorization_approved;
    }
    public function get_redirect_uri(): ?string
    {
        return $this->redirect_uri;
    }
    public function set_redirect_uri(?string $redirect_uri): void
    {
        $this->redirect_uri = $redirect_uri;
    }
    public function get_state(): ?string
    {
        return $this->state;
    }
    public function set_state(string $state): void
    {
        $this->state = $state;
    }
    public function get_code_challenge(): ?string
    {
        return $this->code_challenge ?? null;
    }
    public function set_code_challenge(string $code_challenge): void
    {
        $this->code_challenge = $code_challenge;
    }
    public function get_code_challenge_method(): ?string
    {
        return $this->code_challenge_method ?? null;
    }
    public function set_code_challenge_method(string $code_challenge_method): void
    {
        $this->code_challenge_method = $code_challenge_method;
    }
}
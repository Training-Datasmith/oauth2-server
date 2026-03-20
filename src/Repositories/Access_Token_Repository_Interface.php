<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Repositories;

use League\O_Auth2\Server\Entities\Access_Token_Entity_Interface;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
use League\O_Auth2\Server\Exception\Unique_Token_Identifier_Constraint_Violation_Exception;
/**
 * Access token interface.
 */
interface Access_Token_Repository_Interface extends Repository_Interface
{
    /**
     * Create a new access token
     *
     * @param ScopeEntityInterface[] $scopes
     */
    public function get_new_token(Client_Entity_Interface $client_entity, array $scopes, string|null $user_identifier = null): Access_Token_Entity_Interface;
    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persist_new_access_token(Access_Token_Entity_Interface $access_token_entity): void;
    public function revoke_access_token(string $token_id): void;
    public function is_access_token_revoked(string $token_id): bool;
}
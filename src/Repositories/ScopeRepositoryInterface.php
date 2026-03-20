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

use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
/**
 * Scope interface.
 */
interface Scope_Repository_Interface extends Repository_Interface
{
    /**
     * Return information about a scope.
     *
     * @param string $identifier The scope identifier
     */
    public function get_scope_entity_by_identifier(string $identifier): ?Scope_Entity_Interface;
    /**
     * Given a client, grant type and optional user identifier validate the set of scopes requested are valid and optionally
     * append additional scopes or remove requested scopes.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @return ScopeEntityInterface[]
     */
    public function finalize_scopes(array $scopes, string $grant_type, Client_Entity_Interface $client_entity, string|null $user_identifier = null, ?string $auth_code_id = null): array;
}
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

use League\O_Auth2\Server\Entities\Refresh_Token_Entity_Interface;
use League\O_Auth2\Server\Exception\Unique_Token_Identifier_Constraint_Violation_Exception;
/**
 * Refresh token interface.
 */
interface Refresh_Token_Repository_Interface extends Repository_Interface
{
    public function get_new_refresh_token(): ?Refresh_Token_Entity_Interface;
    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persist_new_refresh_token(Refresh_Token_Entity_Interface $refresh_token_entity): void;
    public function revoke_refresh_token(string $token_id): void;
    public function is_refresh_token_revoked(string $token_id): bool;
}
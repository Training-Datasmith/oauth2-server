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

use League\O_Auth2\Server\Entities\Auth_Code_Entity_Interface;
use League\O_Auth2\Server\Exception\Unique_Token_Identifier_Constraint_Violation_Exception;
/**
 * Auth code storage interface.
 */
interface Auth_Code_Repository_Interface extends Repository_Interface
{
    public function get_new_auth_code(): Auth_Code_Entity_Interface;
    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persist_new_auth_code(Auth_Code_Entity_Interface $auth_code_entity): void;
    public function revoke_auth_code(string $code_id): void;
    public function is_auth_code_revoked(string $code_id): bool;
}
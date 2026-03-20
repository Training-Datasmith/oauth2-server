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
use League\O_Auth2\Server\Entities\User_Entity_Interface;
interface User_Repository_Interface extends Repository_Interface
{
    /**
     * Get a user entity.
     */
    public function get_user_entity_by_user_credentials(string $username, string $password, string $grant_type, Client_Entity_Interface $client_entity): ?User_Entity_Interface;
}
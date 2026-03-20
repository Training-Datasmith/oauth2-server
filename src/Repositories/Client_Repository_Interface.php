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
/**
 * Client storage interface.
 */
interface Client_Repository_Interface extends Repository_Interface
{
    /**
     * Get a client.
     */
    public function get_client_entity(string $client_identifier): ?Client_Entity_Interface;
    /**
     * Validate a client's secret.
     */
    public function validate_client(string $client_identifier, ?string $client_secret, ?string $grant_type): bool;
}
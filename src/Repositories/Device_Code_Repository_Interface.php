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

use League\O_Auth2\Server\Entities\Device_Code_Entity_Interface;
use League\O_Auth2\Server\Exception\Unique_Token_Identifier_Constraint_Violation_Exception;
interface Device_Code_Repository_Interface extends Repository_Interface
{
    /**
     * Creates a new DeviceCode
     */
    public function get_new_device_code(): Device_Code_Entity_Interface;
    /**
     * Persists a device code to permanent storage.
     *
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persist_device_code(Device_Code_Entity_Interface $device_code_entity): void;
    /**
     * Get a device code entity.
     */
    public function get_device_code_entity_by_device_code(string $device_code_entity): ?Device_Code_Entity_Interface;
    /**
     * Revoke a device code.
     */
    public function revoke_device_code(string $code_id): void;
    /**
     * Check if the device code has been revoked.
     *
     * @return bool Return true if this code has been revoked
     */
    public function is_device_code_revoked(string $code_id): bool;
}
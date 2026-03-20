<?php

/**
 * @author    Andrew Millington <andrew@noexceptions.io>
 * @copyright Copyright (c) Andrew Millington
 * @license   http://mit-license.org
 *
 * @link      https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities\Traits;

trait Scope_Trait
{
    /**
     * Serialize the object to the scopes string identifier when using json_encode().
     */
    public function jsonSerialize(): string
    {
        return $this->get_identifier();
    }
    abstract public function get_identifier(): string;
}
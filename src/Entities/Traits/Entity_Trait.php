<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Entities\Traits;

trait Entity_Trait
{
    /**
     * @var non-empty-string
     */
    protected string $identifier;
    /**
     * @return non-empty-string
     */
    public function get_identifier(): string
    {
        return $this->identifier;
    }
    /**
     * @param non-empty-string $identifier
     */
    public function set_identifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }
}
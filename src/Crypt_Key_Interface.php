<?php

declare (strict_types=1);
namespace League\O_Auth2\Server;

interface Crypt_Key_Interface
{
    /**
     * Retrieve key path.
     */
    public function get_key_path(): string;
    /**
     * Retrieve key pass phrase.
     */
    public function get_pass_phrase(): ?string;
    /**
     * Get key contents
     *
     * @return string Key contents
     */
    public function get_key_contents(): string;
}
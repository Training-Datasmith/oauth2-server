<?php

/**
 * @author      Lukáš Unger <lookymsc@gmail.com>
 * @copyright   Copyright (c) Lukáš Unger
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Code_Challenge_Verifiers;

use function base64_encode;
use function hash;
use function hash_equals;
use function rtrim;
use function strtr;
class S256Verifier implements Code_Challenge_Verifier_Interface
{
    /**
     * Return code challenge method.
     */
    public function get_method(): string
    {
        return 'S256';
    }
    /**
     * Verify the code challenge.
     */
    public function verify_code_challenge(string $code_verifier, string $code_challenge): bool
    {
        return hash_equals(strtr(rtrim(base64_encode(hash('sha256', $code_verifier, true)), '='), '+/', '-_'), $code_challenge);
    }
}
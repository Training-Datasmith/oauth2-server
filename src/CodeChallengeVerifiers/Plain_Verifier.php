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

use function hash_equals;
class Plain_Verifier implements Code_Challenge_Verifier_Interface
{
    /**
     * Returns the PKCE method identifier string ('plain').
     *
     * @deprecated — Use S256Verifier (Code_Challenge_Method::S256) for all new clients.
     *               The plain method provides no security benefit over no PKCE.
     *
     * @return string Always 'plain'.
     *
     * @see Code_Challenge_Method::Plain
     */
    public function get_method(): string
    {
        return 'plain';
    }

    /**
     * Verifies a PKCE plain code_verifier against its stored code_challenge.
     *
     * In the plain method code_challenge == code_verifier, so this is a
     * constant-time string comparison.  hash_equals() is still used to prevent
     * timing leakage of the code_verifier value.
     *
     * @deprecated — The plain method offers no real security because the
     *               code_challenge is identical to the code_verifier and is
     *               transmitted unprotected in the authorization request URL.
     *               Use S256 instead.
     *
     * @security Although hash_equals() is used, the fundamental weakness of
     *           the plain method is that interception of the authorization
     *           request gives an attacker the code_verifier directly.
     *
     * @param string $code_verifier  The raw code_verifier from the token request.
     * @param string $code_challenge The code_challenge (identical to code_verifier for plain).
     *
     * @return bool True if the strings are identical.
     */
    public function verify_code_challenge(string $code_verifier, string $code_challenge): bool
    {
        return hash_equals($code_verifier, $code_challenge);
    }
}
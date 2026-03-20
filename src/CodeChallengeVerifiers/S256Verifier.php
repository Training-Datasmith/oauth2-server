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
     * Returns the PKCE method identifier string ('S256').
     *
     * @return string Always 'S256'.
     *
     * @see Code_Challenge_Method::S256
     */
    public function get_method(): string
    {
        return 'S256';
    }

    /**
     * Verifies a PKCE S256 code_verifier against its stored code_challenge.
     *
     * Computes BASE64URL(SHA256(ASCII(code_verifier))) and compares the result
     * to the stored $code_challenge using hash_equals() for constant-time
     * comparison.
     *
     * @security hash_equals() is used to prevent timing attacks: an attacker
     *           who can measure the time of this comparison cannot learn partial
     *           information about the correct code_challenge.
     *
     * @security The code_verifier must be the original random value generated
     *           by the client (43–128 characters from the RFC 7636 alphabet).
     *           Any other value will produce a different SHA-256 hash and fail.
     *
     * @param string $code_verifier  The raw code_verifier from the token request.
     * @param string $code_challenge The BASE64URL(SHA256(code_verifier)) stored in the auth code.
     *
     * @return bool True if and only if the verifier matches the challenge.
     */
    public function verify_code_challenge(string $code_verifier, string $code_challenge): bool
    {
        return hash_equals(strtr(rtrim(base64_encode(hash('sha256', $code_verifier, true)), '='), '+/', '-_'), $code_challenge);
    }
}
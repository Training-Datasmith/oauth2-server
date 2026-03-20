<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\O_Auth2\Server\Code_Challenge_Verifiers;

/**
 * Enumeration of supported PKCE code_challenge_method values (RFC 7636).
 *
 * Use this enum when comparing or storing the code_challenge_method to avoid
 * stringly-typed comparisons and to make valid values self-documenting.
 *
 * @security S256 MUST be preferred over Plain.  The Plain method provides no
 *           security benefit over not using PKCE at all, because the
 *           code_challenge is identical to the code_verifier and can be
 *           intercepted from the authorization request URL.
 *
 * @see https://tools.ietf.org/html/rfc7636#section-4.2
 * @since 9.0.0
 */
enum Code_Challenge_Method: string
{
    /**
     * SHA-256-based code challenge method (recommended).
     *
     * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
     *
     * @security This is the only method that provides genuine PKCE security.
     *           The code_verifier cannot be recovered from the code_challenge
     *           without reversing SHA-256.
     */
    case S256 = 'S256';

    /**
     * Plain code challenge method (not recommended).
     *
     * code_challenge = code_verifier
     *
     * @deprecated Use S256 instead.  The plain method offers no additional
     *             security: if an attacker intercepts the authorization request,
     *             they already have the code_verifier.
     *
     * @security Do NOT use this method for public clients.  It is retained
     *           only for interoperability with legacy clients that cannot
     *           perform SHA-256 hashing.
     */
    case Plain = 'plain';
}

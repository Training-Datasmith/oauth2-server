<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server;

use League\O_Auth2\Server\Authorization_Validators\Authorization_Validator_Interface;
use League\O_Auth2\Server\Authorization_Validators\Bearer_Token_Validator;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Repositories\Access_Token_Repository_Interface;
use Psr\Http\Message\Server_Request_Interface;
/**
 * Validates access tokens on resource server endpoints.
 *
 * A Resource_Server requires only the RSA/EC PUBLIC key — the private key never
 * leaves the Authorization_Server.  Token validation includes JWT signature
 * verification (RS256), time-based claim validation, and revocation checks via
 * the Access_Token_Repository.
 *
 * @security Never share the Authorization_Server private key with Resource_Server
 *           instances.  Each resource server needs only the public key.
 */
class Resource_Server
{
    private readonly Crypt_Key_Interface $public_key;

    /**
     * Creates a new Resource_Server.
     *
     * @security The $public_key must correspond to the private key used by the
     *           Authorization_Server.  An incorrect public key will cause every
     *           JWT validation to fail with an access_denied error.
     *
     * @param Access_Token_Repository_Interface   $access_token_repository  Checks whether a token has been revoked.
     * @param Crypt_Key_Interface|string          $public_key               The RSA/EC public key (object or file:// path / PEM string).
     * @param Authorization_Validator_Interface|null $authorization_validator Optional custom token validator; defaults to Bearer_Token_Validator.
     */
    public function __construct(private readonly Access_Token_Repository_Interface $access_token_repository, Crypt_Key_Interface|string $public_key, private ?Authorization_Validator_Interface $authorization_validator = null)
    {
        if ($public_key instanceof Crypt_Key_Interface === false) {
            $public_key = new Crypt_Key($public_key);
        }
        $this->public_key = $public_key;
    }
    protected function get_authorization_validator(): Authorization_Validator_Interface
    {
        if ($this->authorization_validator instanceof Authorization_Validator_Interface === false) {
            $this->authorization_validator = new Bearer_Token_Validator($this->access_token_repository);
        }
        if ($this->authorization_validator instanceof Bearer_Token_Validator === true) {
            $this->authorization_validator->set_public_key($this->public_key);
        }
        return $this->authorization_validator;
    }
    /**
     * Determine the access token validity.
     *
     * @throws OAuthServerException
     */
    public function validate_authenticated_request(Server_Request_Interface $request): Server_Request_Interface
    {
        return $this->get_authorization_validator()->validate_authorization($request);
    }
}
<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server\Authorization_Validators;

use function date_default_timezone_get;
use DateInterval;
use DateTimeZone;
use Lcobucci\Clock\System_Clock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Exception;
use Lcobucci\JWT\Signer\Key\In_Memory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Unencrypted_Token;
use Lcobucci\JWT\Validation\Constraint\Loose_Valid_At;
use Lcobucci\JWT\Validation\Constraint\Signed_With;
use Lcobucci\JWT\Validation\Required_Constraints_Violated;
use League\O_Auth2\Server\Crypt_Key_Interface;
use League\O_Auth2\Server\Crypt_Trait;
use League\O_Auth2\Server\Exception\O_Auth_Server_Exception;
use League\O_Auth2\Server\Repositories\Access_Token_Repository_Interface;
use function preg_replace;
use Psr\Http\Message\Server_Request_Interface;
use RuntimeException;
use function trim;
class Bearer_Token_Validator implements Authorization_Validator_Interface
{
    use Crypt_Trait;
    protected Crypt_Key_Interface $public_key;
    private Configuration $jwt_configuration;
    public function __construct(private Access_Token_Repository_Interface $access_token_repository, private ?DateInterval $jwt_valid_at_date_leeway = null)
    {
    }
    /**
     * Sets the RSA/EC public key used to verify JWT access token signatures.
     *
     * This method must be called before validate_authorization().  It also
     * initialises the lcobucci/jwt configuration with the correct public key
     * material and the signature algorithm (RS256 via SHA-256).
     *
     * @security Only RSA and EC keys are accepted (validated by Crypt_Key).
     *           Symmetric HS256 tokens are not supported — each resource server
     *           would then need the shared secret, widening the attack surface.
     *
     * @param Crypt_Key_Interface $key  The public key corresponding to the private key
     *                                  used by the Authorization_Server to sign JWTs.
     *
     * @return void
     *
     * @throws \RuntimeException if the public key contents are empty
     */
    public function set_public_key(Crypt_Key_Interface $key): void
    {
        $this->public_key = $key;
        $this->init_jwt_configuration();
    }
    /**
     * Initialise the JWT configuration.
     */
    private function init_jwt_configuration(): void
    {
        $this->jwt_configuration = Configuration::for_symmetric_signer(new Sha256(), In_Memory::plain_text('empty', 'empty'));
        $clock = new System_Clock(new DateTimeZone(date_default_timezone_get()));
        $public_key_contents = $this->public_key->get_key_contents();
        if ($public_key_contents === '') {
            throw new RuntimeException('Public key is empty');
        }
        // TODO: next major release: replace deprecated method and remove phpstan ignored error
        $this->jwt_configuration->set_validation_constraints(new Loose_Valid_At($clock, $this->jwt_valid_at_date_leeway), new Signed_With(new Sha256(), In_Memory::plain_text($public_key_contents, $this->public_key->get_pass_phrase() ?? '')));
    }
    /**
     * Validates the Bearer token in the incoming request and injects OAuth claims as request attributes.
     *
     * Performs, in order:
     * 1. Checks for the presence of an Authorization header.
     * 2. Strips the "Bearer " prefix and ensures the token string is non-empty.
     * 3. Parses the JWT (lcobucci/jwt parser).
     * 4. Validates the JWT signature (RS256 with the configured public key) and
     *    time-based claims (exp, nbf, iat) via LooseValidAt.
     * 5. Checks that the access token has not been explicitly revoked via the
     *    Access_Token_Repository.
     *
     * On success, the following attributes are added to the request:
     * - oauth_access_token_id (string) — the JWT jti claim
     * - oauth_client_id (string)       — the JWT aud[0] claim
     * - oauth_user_id (string|null)    — the JWT sub claim
     * - oauth_scopes (array)           — the JWT scopes claim
     *
     * @security JWT signature verification uses RS256; any token signed with a
     *           different algorithm will fail the Signed_With constraint.
     *           lcobucci/jwt v5 rejects the "alg: none" attack by design.
     *
     * @security Clock-skew tolerance ($jwt_valid_at_date_leeway) should be kept
     *           small (seconds) to limit the window in which expired tokens are
     *           accepted.
     *
     * @param Server_Request_Interface $request  The incoming PSR-7 request carrying the Bearer token.
     *
     * @throws O_Auth_Server_Exception with error=access_denied on any validation failure.
     *
     * @return Server_Request_Interface The original request enriched with oauth_* attributes.
     *
     * @see set_public_key()
     */
    public function validate_authorization(Server_Request_Interface $request): Server_Request_Interface
    {
        if ($request->has_header('authorization') === false) {
            throw O_Auth_Server_Exception::access_denied('Missing "Authorization" header');
        }
        $header = $request->get_header('authorization');
        $jwt = trim((string) preg_replace('/^\s*Bearer\s/i', '', (string) $header[0]));
        if ($jwt === '') {
            throw O_Auth_Server_Exception::access_denied('Missing "Bearer" token');
        }
        try {
            // Attempt to parse the JWT
            $token = $this->jwt_configuration->parser()->parse($jwt);
        } catch (Exception $exception) {
            throw O_Auth_Server_Exception::access_denied($exception->get_message(), null, $exception);
        }
        try {
            // Attempt to validate the JWT
            $constraints = $this->jwt_configuration->validation_constraints();
            $this->jwt_configuration->validator()->assert($token, ...$constraints);
        } catch (Required_Constraints_Violated $exception) {
            throw O_Auth_Server_Exception::access_denied('Access token could not be verified', null, $exception);
        }
        if (!$token instanceof Unencrypted_Token) {
            throw O_Auth_Server_Exception::access_denied('Access token is not an instance of UnencryptedToken');
        }
        $claims = $token->claims();
        // Check if token has been revoked
        if ($this->access_token_repository->is_access_token_revoked($claims->get('jti'))) {
            throw O_Auth_Server_Exception::access_denied('Access token has been revoked');
        }
        // Return the request with additional attributes
        return $request->with_attribute('oauth_access_token_id', $claims->get('jti'))->with_attribute('oauth_client_id', $claims->get('aud')[0])->with_attribute('oauth_user_id', $claims->get('sub'))->with_attribute('oauth_scopes', $claims->get('scopes'));
    }
}
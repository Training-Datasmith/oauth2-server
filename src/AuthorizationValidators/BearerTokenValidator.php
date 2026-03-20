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
     * Set the public key
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
     * {@inheritdoc}
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
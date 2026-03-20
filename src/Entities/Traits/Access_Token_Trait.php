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

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\In_Memory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\O_Auth2\Server\Crypt_Key_Interface;
use League\O_Auth2\Server\Entities\Client_Entity_Interface;
use League\O_Auth2\Server\Entities\Scope_Entity_Interface;
use RuntimeException;
use Sensitive_Parameter;
trait Access_Token_Trait
{
    private Crypt_Key_Interface $private_key;
    private Configuration $jwt_configuration;
    /**
     * Set the private key used to encrypt this access token.
     */
    public function set_private_key(
        #[Sensitive_Parameter]
        Crypt_Key_Interface $private_key
    ): void
    {
        $this->private_key = $private_key;
    }
    /**
     * Initialise the JWT Configuration.
     */
    public function init_jwt_configuration(): void
    {
        $private_key_contents = $this->private_key->get_key_contents();
        if ($private_key_contents === '') {
            throw new RuntimeException('Private key is empty');
        }
        $this->jwt_configuration = Configuration::for_asymmetric_signer(new Sha256(), In_Memory::plain_text($private_key_contents, $this->private_key->get_pass_phrase() ?? ''), In_Memory::plain_text('empty', 'empty'));
    }
    /**
     * Generate a JWT from the access token
     */
    private function convert_to_jwt(): Token
    {
        $this->init_jwt_configuration();
        return $this->jwt_configuration->builder()->permitted_for($this->get_client()->get_identifier())->identified_by($this->get_identifier())->issued_at(new DateTimeImmutable())->can_only_be_used_after(new DateTimeImmutable())->expires_at($this->get_expiry_date_time())->related_to($this->get_subject_identifier())->with_claim('scopes', $this->get_scopes())->get_token($this->jwt_configuration->signer(), $this->jwt_configuration->signing_key());
    }
    /**
     * Generate a string representation from the access token
     */
    public function to_string(): string
    {
        return $this->convert_to_jwt()->to_string();
    }
    abstract public function get_client(): Client_Entity_Interface;
    abstract public function get_expiry_date_time(): DateTimeImmutable;
    /**
     * @return non-empty-string|null
     */
    abstract public function get_user_identifier(): string|null;
    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function get_scopes(): array;
    /**
     * @return non-empty-string
     */
    abstract public function get_identifier(): string;
    /**
     * @return non-empty-string
     */
    private function get_subject_identifier(): string
    {
        return $this->get_user_identifier() ?? $this->get_client()->get_identifier();
    }
}
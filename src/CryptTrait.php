<?php

/**
 * Encrypt/decrypt with encryptionKey.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\Environment_Is_Broken_Exception;
use Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception;
use Defuse\Crypto\Key;
use Exception;
use InvalidArgumentException;
use function is_string;
use LogicException;
use Sensitive_Parameter;
trait Crypt_Trait
{
    protected string|Key|null $encryption_key = null;
    /**
     * Encrypt data with encryptionKey.
     *
     * @throws LogicException
     */
    protected function encrypt(string $unencrypted_data): string
    {
        try {
            if ($this->encryption_key instanceof Key) {
                return Crypto::encrypt($unencrypted_data, $this->encryption_key);
            }
            if (is_string($this->encryption_key)) {
                return Crypto::encrypt_with_password($unencrypted_data, $this->encryption_key);
            }
            throw new LogicException('Encryption key not set when attempting to encrypt');
        } catch (Exception $e) {
            throw new LogicException($e->get_message(), 0, $e);
        }
    }
    /**
     * Decrypt data with encryptionKey.
     *
     * @throws LogicException
     */
    protected function decrypt(string $encrypted_data): string
    {
        try {
            if ($this->encryption_key instanceof Key) {
                return Crypto::decrypt($encrypted_data, $this->encryption_key);
            }
            if (is_string($this->encryption_key)) {
                return Crypto::decrypt_with_password($encrypted_data, $this->encryption_key);
            }
            throw new LogicException('Encryption key not set when attempting to decrypt');
        } catch (Wrong_Key_Or_Modified_Ciphertext_Exception $e) {
            $exception_message = 'The authcode or decryption key/password used ' . 'is not correct';
            throw new InvalidArgumentException($exception_message, 0, $e);
        } catch (Environment_Is_Broken_Exception $e) {
            $exception_message = 'Auth code decryption failed. This is likely ' . 'due to an environment issue or runtime bug in the ' . 'decryption library';
            throw new LogicException($exception_message, 0, $e);
        } catch (Exception $e) {
            throw new LogicException($e->get_message(), 0, $e);
        }
    }
    public function set_encryption_key(
        #[Sensitive_Parameter]
        Key|string|null $key = null
    ): void
    {
        $this->encryption_key = $key;
    }
}
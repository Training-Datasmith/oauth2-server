<?php

/**
 * Cryptography key holder.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
declare (strict_types=1);
namespace League\O_Auth2\Server;

use function decoct;
use function file_get_contents;
use function fileperms;
use function in_array;
use function is_file;
use function is_readable;
use LogicException;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use Open_Ssl_Asymmetric_Key;
use Sensitive_Parameter;
use function sprintf;
use function trigger_error;
class Crypt_Key implements Crypt_Key_Interface
{
    private const FILE_PREFIX = 'file://';
    /**
     * @var string Key contents
     */
    protected string $key_contents;
    protected string $key_path;
    /**
     * Loads a cryptographic key from a file path, a PEM string, or a file:// URI.
     *
     * The constructor validates the key material against OpenSSL and optionally
     * checks that the key file has appropriately restrictive permissions (Unix only).
     *
     * @security Private key files must be readable only by the process owner.
     *           The recommended file mode is 600 (owner read/write only).  A
     *           broader mode (e.g., 644, 664) will trigger an E_USER_NOTICE
     *           warning.  $pass_phrase is annotated #[SensitiveParameter] so it
     *           is redacted from stack traces.
     *
     * @security Only RSA and EC keys are accepted.  DH and DSA keys are rejected
     *           because they are not appropriate for JWT signing (RS256/ES256).
     *
     * @param string      $key_path              File path (with or without file:// prefix),
     *                                           or a raw PEM string containing the key.
     * @param string|null $pass_phrase           Passphrase for encrypted private key files; null if unencrypted.
     * @param bool        $key_permissions_check Whether to warn about insecure file permissions (Unix only).
     *
     * @throws \LogicException if the key path is not readable, the file cannot be read,
     *                         or the key material is invalid.
     */
    public function __construct(
        string $key_path,
        #[Sensitive_Parameter]
        protected ?string $pass_phrase = null,
        bool $key_permissions_check = true
    )
    {
        if (str_starts_with($key_path, self::FILE_PREFIX) === false && $this->is_valid_key($key_path, $this->pass_phrase ?? '')) {
            $this->key_contents = $key_path;
            $this->key_path = '';
            // There's no file, so no need for permission check.
            $key_permissions_check = false;
        } elseif (is_file($key_path)) {
            if (str_starts_with($key_path, self::FILE_PREFIX) === false) {
                $key_path = self::FILE_PREFIX . $key_path;
            }
            if (!is_readable($key_path)) {
                throw new LogicException(sprintf('Key path "%s" does not exist or is not readable', $key_path));
            }
            $key_contents = file_get_contents($key_path);
            if ($key_contents === false) {
                throw new LogicException('Unable to read key from file ' . $key_path);
            }
            $this->key_contents = $key_contents;
            $this->key_path = $key_path;
            if (!$this->is_valid_key($this->key_contents, $this->pass_phrase ?? '')) {
                throw new LogicException('Unable to read key from file ' . $key_path);
            }
        } else {
            throw new LogicException('Invalid key supplied');
        }
        if ($key_permissions_check === true && PHP_OS_FAMILY !== 'Windows') {
            // Verify the permissions of the key
            $key_path_perms = decoct(fileperms($this->key_path) & 0777);
            if (in_array($key_path_perms, ['400', '440', '600', '640', '660'], true) === false) {
                trigger_error(sprintf('Key file "%s" permissions are not correct, recommend changing to 600 or 660 instead of %s', $this->key_path, $key_path_perms), E_USER_NOTICE);
            }
        }
    }
    /**
     * {@inheritdoc}
     */
    public function get_key_contents(): string
    {
        return $this->key_contents;
    }
    /**
     * Validate key contents.
     */
    private function is_valid_key(
        #[Sensitive_Parameter]
        string $contents,
        #[Sensitive_Parameter]
        string $pass_phrase
    ): bool
    {
        $private_key = openssl_pkey_get_private($contents, $pass_phrase);
        $key = $private_key instanceof Open_Ssl_Asymmetric_Key ? $private_key : openssl_pkey_get_public($contents);
        if ($key === false) {
            return false;
        }
        $details = openssl_pkey_get_details($key);
        return $details !== false && in_array($details['type'] ?? -1, [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC], true);
    }
    /**
     * {@inheritdoc}
     */
    public function get_key_path(): string
    {
        return $this->key_path;
    }
    /**
     * {@inheritdoc}
     */
    public function get_pass_phrase(): ?string
    {
        return $this->pass_phrase;
    }
}
<?php

declare(strict_types=1);

namespace Zaphyr\Encrypt;

use Exception;
use Zaphyr\Encrypt\Contracts\EncryptInterface;
use Zaphyr\Encrypt\Exceptions\DecryptException;
use Zaphyr\Encrypt\Exceptions\EncryptException;

/**
 * @author merloxx <merloxx@zaphyr.org>
 */
class Encrypt implements EncryptInterface
{
    /**
     * @var string
     */
    protected $key;

    /**
     * @var string
     */
    protected $cipher;

    /**
     * @param string $key
     * @param string $cipher
     *
     * @throws EncryptException
     */
    public function __construct(string $key, string $cipher = 'AES-128-CBC')
    {
        if (!$this->validKeyAndCipher($key, $cipher)) {
            throw new EncryptException(
                'The only supported ciphers are "AES-128-CBC" and "AES-256-CBC" with the correct key lengths'
            );
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

    /**
     * @param string $key
     * @param string $cipher
     *
     * @return bool
     */
    protected function validKeyAndCipher(string $key, string $cipher): bool
    {
        $length = mb_strlen($key, '8bit');

        return ($cipher === 'AES-128-CBC' && $length === 16) || ($cipher === 'AES-256-CBC' && $length === 32);
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception
     */
    public function encrypt($value, bool $serialize = true)
    {
        $length = openssl_cipher_iv_length($this->cipher);

        if (!is_int($length)) {
            throw new EncryptException('Could not encrypt the data');
        }

        $iv = random_bytes($length);

        $value = openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher,
            $this->key,
            0,
            $iv
        );

        if (!$value) {
            throw new EncryptException('Could not encrypt the data');
        }

        $mac = $this->hash($iv = base64_encode($iv), $value);
        $json = json_encode(compact('iv', 'value', 'mac'));

        if (!is_string($json) || json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data');
        }

        return base64_encode($json);
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception
     */
    public function encryptString(string $value): string
    {
        return $this->encrypt($value, false);
    }

    /**
     * @param string $iv
     * @param mixed  $value
     *
     * @return string
     */
    protected function hash(string $iv, $value): string
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception
     */
    public function decrypt($payload, bool $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);
        $iv = base64_decode($payload['iv']);

        $decrypted = openssl_decrypt(
            $payload['value'],
            $this->cipher,
            $this->key,
            0,
            $iv
        );

        if (!$decrypted) {
            throw new DecryptException('Could not decrypt data');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception
     */
    public function decryptString(string $payload): string
    {
        return $this->decrypt($payload, false);
    }

    /**
     * @param mixed $payload
     *
     * @return array<string, mixed>
     *
     * @throws Exception
     * @throws DecryptException
     */
    protected function getJsonPayload($payload): array
    {
        $payload = json_decode(base64_decode($payload), true);

        if (!$this->validPayload($payload)) {
            throw new DecryptException('Invalid payload');
        }

        if (!$this->validMac($payload)) {
            throw new DecryptException('Invalid MAC');
        }

        return $payload;
    }

    /**
     * @param mixed $payload
     *
     * @return bool
     */
    protected function validPayload($payload): bool
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) &&
            strlen((string)base64_decode($payload['iv'], true)) === openssl_cipher_iv_length($this->cipher);
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return bool
     *
     * @throws Exception
     */
    protected function validMac(array $payload): bool
    {
        $calculated = $this->calculateMac($payload, $bytes = random_bytes(16));

        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true),
            $calculated
        );
    }

    /**
     * @param array<string, mixed> $payload
     * @param string               $bytes
     *
     * @return string
     */
    protected function calculateMac(array $payload, string $bytes): string
    {
        return hash_hmac('sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true);
    }
}

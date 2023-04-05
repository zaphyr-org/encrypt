<?php

declare(strict_types=1);

namespace Zaphyr\Encrypt\Contracts;

use Zaphyr\Encrypt\Exceptions\DecryptException;
use Zaphyr\Encrypt\Exceptions\EncryptException;

/**
 * @author merloxx <merloxx@zaphyr.org>
 */
interface EncryptInterface
{
    /**
     * @param mixed $value
     * @param bool  $serialize
     *
     * @throws EncryptException If the data could not be encrypted.
     * @return string
     */
    public function encrypt(mixed $value, bool $serialize = true): string;

    /**
     * @param string $value
     *
     * @throws EncryptException If the data could not be encrypted.
     * @return string
     */
    public function encryptString(string $value): string;

    /**
     * @param mixed $payload
     * @param bool  $unserialize
     *
     * @throws DecryptException If the data could not be decrypted.
     * @return mixed
     */
    public function decrypt(mixed $payload, bool $unserialize = true): mixed;

    /**
     * @param string $payload
     *
     * @throws DecryptException If the data could not be decrypted.
     * @return string
     */
    public function decryptString(string $payload): string;
}

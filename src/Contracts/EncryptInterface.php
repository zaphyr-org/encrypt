<?php

declare(strict_types=1);

namespace Zaphyr\Encrypt\Contracts;

use Zaphyr\Encrypt\Exceptions\DecryptException;
use Zaphyr\Encrypt\Exceptions\EncryptException;

/**
 * Interface EncryptInterface
 *
 * @package Zaphyr\Encrypt\Contracts
 * @author  merloxx <merloxx@zaphyr.org>
 */
interface EncryptInterface
{
    /**
     * @param mixed $value
     * @param bool  $serialize
     *
     * @return mixed
     *
     * @throws EncryptException
     */
    public function encrypt($value, bool $serialize = true);

    /**
     * @param string $value
     *
     * @return string
     *
     * @throws EncryptException
     */
    public function encryptString(string $value): string;

    /**
     * @param mixed $payload
     * @param bool  $unserialize
     *
     * @return mixed
     *
     * @throws DecryptException
     */
    public function decrypt($payload, bool $unserialize = true);

    /**
     * @param string $payload
     *
     * @return string
     *
     * @throws DecryptException
     */
    public function decryptString(string $payload): string;
}

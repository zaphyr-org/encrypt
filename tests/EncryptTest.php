<?php

declare(strict_types=1);

namespace Zaphyr\EncryptTests;

use PHPUnit\Framework\TestCase;
use Zaphyr\Encrypt\Encrypt;
use Zaphyr\Encrypt\Exceptions\DecryptException;
use Zaphyr\Encrypt\Exceptions\EncryptException;

class EncryptTest extends TestCase
{
    /**
     * ------------------------------------------
     * CONSTRUCTOR
     * ------------------------------------------
     */

    public function testConstructorThrowsExceptionOnLongerKey(): void
    {
        $this->expectException(EncryptException::class);

        new Encrypt(str_repeat('a', 32));
    }

    public function testConstructorThrowsExceptionWithShorterKeyLength(): void
    {
        $this->expectException(EncryptException::class);

        new Encrypt(str_repeat('a', 8));
    }

    public function testConstructorThrowsExceptionOnBadKeyLengthAndCustomCipher(): void
    {
        $this->expectException(EncryptException::class);

        new Encrypt(str_repeat('a', 16), 'AES-256-CBC');
    }

    public function testConstructorThrowsExceptionOnUnsupportedCipher(): void
    {
        $this->expectException(EncryptException::class);

        new Encrypt(str_repeat('a', 16), 'AES-256-CFB8');
    }

    /**
     * ------------------------------------------
     * ENCRYPT
     * ------------------------------------------
     */

    public function testEncrypt(): void
    {
        $encrypt = new Encrypt(str_repeat('a', 16));
        $encrypted = $encrypt->encrypt($expected = 'foo');

        self::assertNotEquals($expected, $encrypted);
        self::assertEquals($expected, $encrypt->decrypt($encrypted));
    }

    public function testEncryptString(): void
    {
        $encrypt = new Encrypt(str_repeat('a', 16));
        $encrypted = $encrypt->encryptString($expected = 'foo');

        self::assertNotEquals($expected, $encrypted);
        self::assertEquals($expected, $encrypt->decryptString($encrypted));
    }

    public function testEncryptUsingBase64EncodedKey(): void
    {
        $encrypt = new Encrypt(random_bytes(16));
        $encrypted = $encrypt->encrypt($expected = 'foo');

        self::assertNotEquals($expected, $encrypted);
        self::assertEquals($expected, $encrypt->decrypt($encrypted));
    }

    public function testEncryptWithCustomCipher(): void
    {
        $encrypt = new Encrypt(str_repeat('b', 32), 'AES-256-CBC');
        $encrypted = $encrypt->encrypt($expected = 'foo');

        self::assertNotEquals($expected, $encrypted);
        self::assertEquals($expected, $encrypt->decrypt($encrypted));
    }

    public function testEncryptWithCustomCipherAndBase64EncodedKey(): void
    {
        $encrypt = new Encrypt(random_bytes(32), 'AES-256-CBC');
        $encrypted = $encrypt->encrypt($expected = 'foo');

        self::assertNotEquals($expected, $encrypted);
        self::assertEquals($expected, $encrypt->decrypt($encrypted));
    }

    /**
     * ------------------------------------------
     * DECRYPT
     * ------------------------------------------
     */

    public function testDecryptThrowsExceptionOnInvalidPayload(): void
    {
        $this->expectException(DecryptException::class);

        $encrypt = new Encrypt(str_repeat('a', 16));
        $payload = $encrypt->encrypt('foo');
        $payload = str_shuffle($payload);

        $encrypt->decrypt($payload);
    }

    public function testDecryptThrowsExceptionOnDifferentKey(): void
    {
        $this->expectException(DecryptException::class);

        $encrypt1 = new Encrypt(str_repeat('a', 16));
        $encrypt2 = new Encrypt(str_repeat('b', 16));

        $encrypt2->decrypt($encrypt1->encrypt('foo'));
    }

    public function testDecryptThrowsExceptionWhenIvIsTooLong(): void
    {
        $this->expectException(DecryptException::class);

        $encrypt = new Encrypt(str_repeat('a', 16));
        $payload = $encrypt->encrypt('foo');
        $data = json_decode(base64_decode($payload), true);
        $data['iv'] .= $data['value'][0];
        $data['value'] = substr($data['value'], 1);
        $modifiedPayload = base64_encode(json_encode($data) ?: '');

        $encrypt->decrypt($modifiedPayload);
    }
}

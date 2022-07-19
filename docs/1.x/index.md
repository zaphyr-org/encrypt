# Table of contents

- [Configuration](#configuration)
- [Encrypting](#encrypting)
- [Decrypting](#decrypting)

## Configuration

Before we can start encrypting, we need to make a few configurations. For encryption and decryption we can use a
16 character private key with `AES-128-CBC` cipher or a 32 character private key with the `AES-256-CBC` cipher.

### With AES-128-CBC cipher

```php
$key = 'diw84lfnd74jdms6';
$encryptor = new Zaphyr\Encrypt\Encrypt($key);
```

### With AES-256-CBC cipher

```php
$key = 'OOQPAgC4tA7NanCiVCa1QN5BiRDpdQZR';
$cipher = 'AES-256-CBC';
$encryptor = new Zaphyr\Encrypt\Encrypt($key, $cipher);
```

## Encrypting

To encrypt values we use the `encrypt` method. This method uses [OpenSSL](https://www.openssl.org/) and the
`AES-128-CBC` or `AES-256-CBC` cipher. If the value can not be properly encrypted, an
`Zaphyr\Encrypt\Exception\EncryptException` will be thrown.

```php
try {
    $encrypted = $encryptor->encrypt($value);
} catch(Zaphyr\Encrypt\Exception\EncryptException $exception) {
    //
}
```

### Encrypting without serialization

Encrypted values are passed via serialize during encryption, which enables the encryption of objects and arrays.
If you want to encrypt values without serialisation, you can use the `encryptString` method.

```php
$encryptor->encryptString($string);
```

## Decrypting

We also want to decrypt values using the `decrypt` method. If the variable cannot be decrypted or the `MAC` is invalid,
a `Zaphyr\Encrypt\Exception\DecryptException` is thrown.

```php
try {
    $decrypted = $encryptor->decrypt($encrypted);
} catch(Zaphyr\Encrypt\Exception\DecryptException $exception) {
    //
}
```

### Decrypting without serialization

If you want to decrypt values without serialisation, you can use the `decryptString` method.

```php
$encryptor->decryptString($encrypted);
```

# ralph
A semi-secure symmetric encryption library that sometimes eats crayons.

Ralph provides acceptable security in situations where size is critical.
All major security parameters are 64 bit (block, iv and checksum).
As a result, input strings under 8 bytes long result in a 24 byte cypher text.

```php
$encrypted = ralph()::encrypt('secret', 'password');

var_dump(base64_encode($encrypted));
#string(32) "sBVr2kZo3ckGl+IK25C5lmlYDPBjuact"

$decrypted = ralph()::decrypt($encrypted, 'password');

var_dump($decrypted);
#string(6) "secret"
```

Ralph isn't very smart, so he registers himself the in global namespace `\Ralph`.
He also registers the global helper function `ralph()`, for your convenience and amusement.

## install

**EXPERIMENTAL**

Ralph is compatible with PHP versions 7.1 to 8.1.
```bash
composer require mmeyerk/ralph main-dev
```

## how it works
Ralph uses `hash_pbkdf2()` to generate a key stream which is then XORed with the message.
Both `encrypt` and `decrypt` functions accept an optional third parameter to specify iterations for key hardening.
```php
$iterations = 10000;
$encrypted = ralph()::encrypt('secret', 'password', $iterations);
$decrypted = ralph()::decrypt($encrypted, 'password', $iterations);
```

## specs
 - initialization vector (`random_bytes`)
 - time-safe checksum verification (`hash_equals`, `hash_hmac`, `sha3-256`)
 - block padding (`PKCS#7`)
 - key stream generation (`hash_pbkdf2`, `sha3-512`)

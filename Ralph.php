<?php declare(strict_types=1);

class Ralph
{
    /**
     * @throws Exception|ValueError
     */
    public static function encrypt(string $msg, string $key): string
    {
        $ivr = random_bytes(8);

        $len = strlen($msg);

        $pad = 8 - ($len % 8);

        $msg = $msg . str_repeat(chr($pad), $pad);

        $msg = $msg ^ self::hkdf($key, $len + $pad, $ivr);

        $chk = self::hmac($msg, $key);

        return $ivr . $chk . $msg;
    }

    /**
     * @throws ValueError|Exception|InvalidArgumentException
     */
    public static function decrypt(string $msg, string $key): string
    {
        $ivr = substr($msg, 0, 8);

        $chk = substr($msg, 8, 8);

        $msg = substr($msg, 16);

        $cal = self::hmac($msg, $key);

        if (hash_equals($cal, $chk) === false) {
            throw new InvalidArgumentException('Ciphertext checksum verification failed');
        }

        $len = strlen($msg);

        $msg = $msg ^ self::hkdf($key, $len, $ivr);

        $pad = ord(substr($msg, -1));

        return substr($msg, 0, -$pad);
    }

    /**
     * @throws Exception
     */
    private static function hkdf(string $key, int $len, string $ivr): string
    {
        $data = hash_hkdf('sha3-512', $key, $len, (string) $len, $ivr);

        if ($data === false) {
            throw new Exception('An exception occurred in hash_hkdf');
        }

        return $data;
    }

    /**
     * @throws Exception
     */
    private static function hmac(string $msg, string $key): string
    {
        $hash = hash_hmac('sha3-256', $msg, $key, true);

        if ($hash === false) {
            throw new Exception('An exception occurred in hash_hmac');
        }

        return substr($hash, 0, 8);
    }
}

function ralph(): Ralph
{
    return new Ralph;
}

<?php declare(strict_types=1);

class Ralph
{
    protected const ivrsize = 8;
    protected const chksize = 8;
    protected const padsize = 8;

    /**
     * @throws Exception|ValueError
     */
    public static function encrypt(string $msg, string $key, int $itr = 1): string
    {
        $ivr = random_bytes(self::ivrsize);

        $len = strlen($msg);

        $pad = self::padsize - ($len % self::padsize);

        $msg = $msg . str_repeat(chr($pad), $pad);

        $msg = $msg ^ self::pbkdf($key, $len + $pad, $ivr, $itr);

        $chk = self::hmac($msg, $key);

        return $ivr . $chk . $msg;
    }

    /**
     * @throws ValueError|Exception|InvalidArgumentException
     */
    public static function decrypt(string $msg, string $key, int $itr = 1): string
    {
        $ivr = substr($msg, 0, self::ivrsize);

        $chk = substr($msg, self::ivrsize, self::chksize);

        $msg = substr($msg, self::ivrsize + self::chksize);

        $cal = self::hmac($msg, $key);

        if (hash_equals($cal, $chk) === false) {
            throw new InvalidArgumentException('Ciphertext checksum verification failed');
        }

        $len = strlen($msg);

        $msg = $msg ^ self::pbkdf($key, $len, $ivr, $itr);

        $pad = ord(substr($msg, -1));

        return substr($msg, 0, -$pad);
    }

    /**
     * @throws Exception
     */
    private static function pbkdf(string $key, int $len, string $ivr, int $itr): string
    {
        return hash_pbkdf2('sha3-512', $key, $ivr, $itr, $len, true);
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

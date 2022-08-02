<?php declare(strict_types=1);

class Ralph
{
    protected const bitsize = 8;

    /**
     * @throws Exception|ValueError
     */
    public static function encrypt(string $msg, string $key, int $itr = 1): string
    {
        $ivr = random_bytes(static::bitsize);

        $len = strlen($msg);

        $pad = static::bitsize - ($len % static::bitsize);

        $msg = $msg . str_repeat(chr($pad), $pad);

        $msg = $msg ^ self::pbkdf($key, $len + $pad, $ivr, $itr);

        $chk = self::hmac($msg, $key);

        return $ivr . $chk . $msg;
    }

    /**
     * @throws Exception|InvalidArgumentException
     */
    public static function decrypt(string $msg, string $key, int $itr = 1): string
    {
        $ivr = substr($msg, 0, static::bitsize);

        $chk = substr($msg, static::bitsize, static::bitsize);

        $msg = substr($msg, static::bitsize * 2);

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
        $hmac = hash_hmac('sha3-256', $msg, $key, true);

        return substr($hmac, 0, static::bitsize);
    }
}

class Ralph16 extends Ralph
{
    protected const bitsize = 2;
}

class Ralph32 extends Ralph
{
    protected const bitsize = 4;
}

class Ralph48 extends Ralph
{
    protected const bitsize = 6;
}

class Ralph64 extends Ralph
{
    protected const bitsize = 8;
}

class Ralph80 extends Ralph
{
    protected const bitsize = 10;
}

class Ralph96 extends Ralph
{
    protected const bitsize = 12;
}

function ralph(): Ralph
{
    return new Ralph;
}

function ralph16(): Ralph
{
    return new Ralph16;
}

function ralph32(): Ralph
{
    return new Ralph32;
}

function ralph48(): Ralph
{
    return new Ralph48;
}

function ralph64(): Ralph
{
    return new Ralph64;
}

function ralph80(): Ralph
{
    return new Ralph80;
}

function ralph96(): Ralph
{
    return new Ralph96;
}

<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/Ralph.php';

final class RalphTest extends TestCase
{
    const key = 'AAAAAAAA';
    const msg = '... a secret message ...';

    public function testEncryptionCycle(): void
    {
        $enc = ralph()::encrypt(self::msg, self::key);
        $dec = ralph()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testBadChecksum(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $msg = str_repeat('A', 100);
        ralph()::decrypt($msg, 'password');
    }

    public function testReadmeSnippet(): void
    {
        $enc = base64_decode('M783Db84XVPukJZkRh05R5ZBZxcD4CvM');
        $dec = ralph()::decrypt($enc, 'password');

        $this->assertEquals('secret', $dec);
    }

    public function testStressTestWithRandomBytes(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $msg = random_bytes(mt_rand(1, 100));
            $key = random_bytes(mt_rand(1, 100));

            $enc = Ralph::encrypt($msg, $key);
            $dec = Ralph::decrypt($enc, $key);

            $this->assertEquals($msg, $dec);
            $this->assertEquals(0, strlen($enc) % 8);
        }
    }

    public function testRalph16(): void
    {
        $enc = ralph16()::encrypt(self::msg, self::key);
        $dec = ralph16()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph32(): void
    {
        $enc = ralph32()::encrypt(self::msg, self::key);
        $dec = ralph32()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph48(): void
    {
        $enc = ralph48()::encrypt(self::msg, self::key);
        $dec = ralph48()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph64(): void
    {
        $enc = ralph64()::encrypt(self::msg, self::key);
        $dec = ralph64()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph80(): void
    {
        $enc = ralph80()::encrypt(self::msg, self::key);
        $dec = ralph80()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph96(): void
    {
        $enc = ralph96()::encrypt(self::msg, self::key);
        $dec = ralph96()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph112(): void
    {
        $enc = ralph112()::encrypt(self::msg, self::key);
        $dec = ralph112()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }

    public function testRalph128(): void
    {
        $enc = ralph128()::encrypt(self::msg, self::key);
        $dec = ralph128()::decrypt($enc, self::key);
        $this->assertEquals(self::msg, $dec);
    }
}
<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/Ralph.php';

final class RalphTest extends TestCase
{
    public function testEncryptionCycle(): void
    {
        $msg = 'AAAA';
        $pwd = 'BBBB';
        $enc = ralph()::encrypt($msg, $pwd);
        $dec = ralph()::decrypt($enc, $pwd);
        $this->assertEquals($msg, $dec);
    }

    public function testBadChecksum(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $msg = str_repeat('A', 100);
        ralph()::decrypt($msg, 'password');
    }

    public function testReadmeSnippet(): void
    {
        $enc = base64_decode('sBVr2kZo3ckGl+IK25C5lmlYDPBjuact');
        $dec = ralph()::decrypt($enc, 'password');

        $this->assertEquals('secret', $dec);
    }

    public function testStressTestWithRandomBytes(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $msg = random_bytes(mt_rand(1, 16000));
            $key = random_bytes(mt_rand(1, 100));

            $enc = Ralph::encrypt($msg, $key);
            $dec = Ralph::decrypt($enc, $key);

            $this->assertEquals($msg, $dec);
            $this->assertEquals(0, strlen($enc) % 8);
        }
    }
}

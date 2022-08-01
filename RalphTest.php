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
}

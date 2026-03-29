<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SecurityTest extends TestCase {
    protected function setUp(): void {
        $_SESSION = [];
    }

    public function testCSRFTokenGeneration(): void {
        $token = Security::generateCSRFToken();
        $this->assertNotEmpty($token);
        $this->assertSame(64, strlen($token));
        $this->assertSame($token, $_SESSION['csrf_token']);
    }

    public function testCSRFTokenValidation(): void {
        $token = Security::generateCSRFToken();
        $this->assertTrue(Security::validateCSRFToken($token));
        $this->assertFalse(Security::validateCSRFToken('invalid_token'));
    }

    public function testCSRFTokenExpiry(): void {
        $token = Security::generateCSRFToken();
        $_SESSION['csrf_time'] = time() - 7200; // 2 hours ago
        $this->assertFalse(Security::validateCSRFToken($token));
    }

    public function testRateLimitAllows(): void {
        $key = 'test_allow_' . bin2hex(random_bytes(4));
        $this->assertTrue(Security::checkRateLimit($key, 5, 60));
        $this->assertTrue(Security::checkRateLimit($key, 5, 60));
        $this->assertTrue(Security::checkRateLimit($key, 5, 60));
    }

    public function testRateLimitBlocks(): void {
        $key = 'test_block_' . bin2hex(random_bytes(4));
        for ($i = 0; $i < 5; $i++) {
            Security::checkRateLimit($key, 5, 60);
        }
        $this->assertFalse(Security::checkRateLimit($key, 5, 60));
    }

    public function testSanitizeIdentifierValid(): void {
        $this->assertSame('users', Security::sanitizeIdentifier('users'));
        $this->assertSame('my_table', Security::sanitizeIdentifier('my_table'));
        $this->assertSame('db-name', Security::sanitizeIdentifier('db-name'));
        $this->assertSame('Table123', Security::sanitizeIdentifier('Table123'));
    }

    public function testSanitizeIdentifierInvalid(): void {
        $this->expectException(InvalidArgumentException::class);
        Security::sanitizeIdentifier('table; DROP TABLE users');
    }

    public function testSanitizeIdentifierSQLInjection(): void {
        $this->expectException(InvalidArgumentException::class);
        Security::sanitizeIdentifier("users' OR '1'='1");
    }

    public function testIPWhitelistEmpty(): void {
        $this->assertTrue(Security::checkIPWhitelist([]));
    }
}

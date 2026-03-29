<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SecurityIPv6Test extends TestCase {
    protected function setUp(): void {
        $_SESSION = [];
        $_SERVER = [];
    }

    public function testIPv4CIDRMatch(): void {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $this->assertTrue(Security::checkIPWhitelist(['192.168.1.0/24']));
    }

    public function testIPv4CIDRNoMatch(): void {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        $this->assertFalse(Security::checkIPWhitelist(['192.168.1.0/24']));
    }

    public function testIPv6ExactMatch(): void {
        $_SERVER['REMOTE_ADDR'] = '::1';
        $this->assertTrue(Security::checkIPWhitelist(['::1']));
    }

    public function testIPv6CIDRMatch(): void {
        $_SERVER['REMOTE_ADDR'] = '2001:db8::1';
        $this->assertTrue(Security::checkIPWhitelist(['2001:db8::/32']));
    }

    public function testIPv6CIDRNoMatch(): void {
        $_SERVER['REMOTE_ADDR'] = '2001:db9::1';
        $this->assertFalse(Security::checkIPWhitelist(['2001:db8::/32']));
    }

    public function testIPv6FullAddressCIDR(): void {
        $_SERVER['REMOTE_ADDR'] = 'fe80::1';
        $this->assertTrue(Security::checkIPWhitelist(['fe80::/10']));
    }

    public function testIPv6CIDRSlash128(): void {
        $_SERVER['REMOTE_ADDR'] = '2001:db8::1';
        $this->assertTrue(Security::checkIPWhitelist(['2001:db8::1/128']));
    }

    public function testIPv6CIDRSlash128NoMatch(): void {
        $_SERVER['REMOTE_ADDR'] = '2001:db8::2';
        $this->assertFalse(Security::checkIPWhitelist(['2001:db8::1/128']));
    }

    public function testMixedWhitelistIPv4AndIPv6(): void {
        $_SERVER['REMOTE_ADDR'] = '2001:db8::5';
        $this->assertTrue(Security::checkIPWhitelist(['192.168.0.0/16', '2001:db8::/32']));
    }

    public function testIPv6DoesNotMatchIPv4CIDR(): void {
        $_SERVER['REMOTE_ADDR'] = '::ffff:192.168.1.1';
        // IPv6-mapped IPv4 should not match plain IPv4 CIDR
        $this->assertFalse(Security::checkIPWhitelist(['192.168.1.0/24']));
    }
}

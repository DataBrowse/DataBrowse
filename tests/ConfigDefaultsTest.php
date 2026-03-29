<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ConfigDefaultsTest extends TestCase {
    public function testAllowRootLoginDefaultFalse(): void {
        $config = getDefaultConfig();
        $this->assertFalse($config['security']['allow_root_login']);
    }

    public function testValidateConfigClampsAllowRootLogin(): void {
        $config = getDefaultConfig();
        $config['security']['allow_root_login'] = true;
        $validated = validateConfig($config);
        $this->assertTrue($validated['security']['allow_root_login']);
    }

    public function testDefaultSessionSecretEmpty(): void {
        $config = getDefaultConfig();
        $this->assertSame('', $config['security']['session_secret']);
    }

    public function testDefaultBlockedSqlPatterns(): void {
        $config = getDefaultConfig();
        $this->assertContains('INTO OUTFILE', $config['security']['blocked_sql_patterns']);
        $this->assertContains('LOAD DATA', $config['security']['blocked_sql_patterns']);
    }

    public function testValidateConfigClampsQueryLimit(): void {
        $config = getDefaultConfig();
        $config['security']['max_query_limit'] = 999999;
        $validated = validateConfig($config);
        $this->assertSame(100000, $validated['security']['max_query_limit']);
    }

    public function testValidateConfigClampsQueryLimitMin(): void {
        $config = getDefaultConfig();
        $config['security']['max_query_limit'] = 0;
        $validated = validateConfig($config);
        $this->assertSame(1, $validated['security']['max_query_limit']);
    }

    public function testDefaultForceHttpsFalse(): void {
        $config = getDefaultConfig();
        $this->assertFalse($config['security']['force_https']);
    }

    public function testDefaultAllowedDbHosts(): void {
        $config = getDefaultConfig();
        $this->assertSame(['127.0.0.1', 'localhost'], $config['security']['allowed_db_hosts']);
    }

    public function testValidateConfigNormalizesStringListForIpWhitelist(): void {
        $config = getDefaultConfig();
        $config['security']['ip_whitelist'] = ['  10.0.0.0/8  ', '', '192.168.0.0/16'];
        $validated = validateConfig($config);
        $this->assertSame(['10.0.0.0/8', '192.168.0.0/16'], $validated['security']['ip_whitelist']);
    }

    public function testValidateConfigAllowedExtensionsFiltered(): void {
        $config = getDefaultConfig();
        $config['import']['allowed_extensions'] = ['sql', 'exe', 'csv', 'php'];
        $validated = validateConfig($config);
        $this->assertSame(['sql', 'csv'], $validated['import']['allowed_extensions']);
    }
}

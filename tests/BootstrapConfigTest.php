<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class BootstrapConfigTest extends TestCase {
    public function testValidateConfigClampsNumericValues(): void {
        $config = getDefaultConfig();
        $config['security']['max_login_attempts'] = 0;
        $config['security']['lockout_duration'] = 9999999;
        $config['security']['session_timeout'] = '10';
        $config['security']['max_query_limit'] = 999999999;
        $config['security']['max_sql_length'] = 1;
        $config['security']['max_statements_per_query'] = 1000;
        $config['security']['max_request_body_bytes'] = 10;
        $config['security']['api_rate_limit_max'] = 1;
        $config['security']['api_rate_limit_window'] = 0;
        $config['security']['idempotency_ttl'] = 9999999;
        $config['ui']['rows_per_page'] = -5;
        $config['import']['max_file_size'] = 9999999999;

        $validated = validateConfig($config);

        $this->assertSame(1, $validated['security']['max_login_attempts']);
        $this->assertSame(86400, $validated['security']['lockout_duration']);
        $this->assertSame(60, $validated['security']['session_timeout']);
        $this->assertSame(100000, $validated['security']['max_query_limit']);
        $this->assertSame(1000, $validated['security']['max_sql_length']);
        $this->assertSame(200, $validated['security']['max_statements_per_query']);
        $this->assertSame(1024, $validated['security']['max_request_body_bytes']);
        $this->assertSame(10, $validated['security']['api_rate_limit_max']);
        $this->assertSame(1, $validated['security']['api_rate_limit_window']);
        $this->assertSame(86400, $validated['security']['idempotency_ttl']);
        $this->assertSame(1, $validated['ui']['rows_per_page']);
        $this->assertSame(536870912, $validated['import']['max_file_size']);
    }

    public function testValidateConfigNormalizesListsAndBooleans(): void {
        $config = getDefaultConfig();
        $config['security']['allowed_db_hosts'] = [' 127.0.0.1 ', '', 'localhost', 'localhost'];
        $config['security']['ip_whitelist'] = ['10.0.0.1', '10.0.0.1', ''];
        $config['import']['allowed_extensions'] = ['SQL', 'csv', 'exe', ''];
        $config['security']['blocked_sql_patterns'] = ['  load data ', '', 'into outfile'];
        $config['security']['force_https'] = 1;
        $config['security']['read_only_mode'] = 0;
        $config['security']['allow_dangerous_sql'] = '1';
        $config['security']['audit_log_enabled'] = 0;
        $config['security']['audit_log_path'] = '  /tmp/audit.log  ';

        $validated = validateConfig($config);

        $this->assertSame(['127.0.0.1', 'localhost'], $validated['security']['allowed_db_hosts']);
        $this->assertSame(['10.0.0.1'], $validated['security']['ip_whitelist']);
        $this->assertSame(['sql', 'csv'], $validated['import']['allowed_extensions']);
        $this->assertSame(['LOAD DATA', 'INTO OUTFILE'], $validated['security']['blocked_sql_patterns']);
        $this->assertTrue($validated['security']['force_https']);
        $this->assertFalse($validated['security']['read_only_mode']);
        $this->assertTrue($validated['security']['allow_dangerous_sql']);
        $this->assertFalse($validated['security']['audit_log_enabled']);
        $this->assertSame('/tmp/audit.log', $validated['security']['audit_log_path']);
    }
}

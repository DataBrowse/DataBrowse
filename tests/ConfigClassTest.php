<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ConfigClassTest extends TestCase {
    public function testGetReturnsFullConfig(): void {
        Config::init(['security' => ['force_https' => true]]);
        $all = Config::get();
        $this->assertIsArray($all);
        $this->assertTrue($all['security']['force_https']);
    }

    public function testGetDotNotation(): void {
        Config::init(['security' => ['max_query_limit' => 5000]]);
        $this->assertSame(5000, Config::get('security.max_query_limit'));
    }

    public function testGetReturnsDefault(): void {
        Config::init(['security' => []]);
        $this->assertSame('fallback', Config::get('security.nonexistent', 'fallback'));
    }

    public function testGetTopLevelKey(): void {
        Config::init(['ui' => ['theme' => 'dark']]);
        $this->assertSame(['theme' => 'dark'], Config::get('ui'));
    }

    public function testGetNullKeyReturnsAll(): void {
        $cfg = ['a' => 1, 'b' => 2];
        Config::init($cfg);
        $this->assertSame($cfg, Config::get(null));
    }

    public function testGetDeepNesting(): void {
        Config::init(['a' => ['b' => ['c' => 42]]]);
        $this->assertSame(42, Config::get('a.b.c'));
    }

    public function testGetMissingNestedReturnsDefault(): void {
        Config::init(['a' => ['b' => 1]]);
        $this->assertNull(Config::get('a.b.c.d'));
    }

    protected function tearDown(): void {
        // Restore default config for other tests
        Config::init(getDefaultConfig());
    }
}

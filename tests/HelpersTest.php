<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class HelpersTest extends TestCase {
    public function testFormatSizeBytes(): void {
        $this->assertSame('0 B', Helpers::formatSize(0));
        $this->assertSame('500 B', Helpers::formatSize(500));
    }

    public function testFormatSizeKB(): void {
        $this->assertSame('1 KB', Helpers::formatSize(1024));
        $this->assertSame('1.5 KB', Helpers::formatSize(1536));
    }

    public function testFormatSizeMB(): void {
        $this->assertSame('1 MB', Helpers::formatSize(1048576));
        $this->assertSame('10 MB', Helpers::formatSize(10485760));
    }

    public function testFormatSizeGB(): void {
        $this->assertSame('1 GB', Helpers::formatSize(1073741824));
    }

}

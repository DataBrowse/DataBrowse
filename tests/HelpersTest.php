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

    public function testFormatDurationSeconds(): void {
        $this->assertSame('30s', Helpers::formatDuration(30));
    }

    public function testFormatDurationMinutes(): void {
        $this->assertSame('5m 30s', Helpers::formatDuration(330));
    }

    public function testFormatDurationHours(): void {
        $this->assertSame('2h 15m', Helpers::formatDuration(8100));
    }

    public function testFormatDurationDays(): void {
        $this->assertSame('3d 5h', Helpers::formatDuration(277200));
    }
}

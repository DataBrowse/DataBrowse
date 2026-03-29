<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ImportProgressTest extends TestCase {
    private string $testId;

    protected function setUp(): void {
        $this->testId = 'test_' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void {
        SQLImporter::cleanupProgress($this->testId);
    }

    public function testReadProgressReturnsNullWhenNotFound(): void {
        $result = SQLImporter::readProgress('nonexistent_id_abc');
        $this->assertNull($result);
    }

    public function testWriteAndReadProgress(): void {
        // Simulate what updateProgress does via reflection
        $conn = $this->createMock(mysqli::class);
        $importer = new SQLImporter($conn);

        // Write progress directly using the file mechanism
        $dir = sys_get_temp_dir() . '/databrowse_import_progress';
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $file = $dir . '/' . $this->testId . '.json';
        $data = [
            'bytes_read' => 500,
            'total_bytes' => 1000,
            'percentage' => 50.0,
            'statements' => 10,
            'executed' => 8,
            'failed' => 2,
            'updated_at' => time(),
        ];
        file_put_contents($file, json_encode($data), LOCK_EX);

        $result = SQLImporter::readProgress($this->testId);
        $this->assertIsArray($result);
        $this->assertSame(500, $result['bytes_read']);
        $this->assertSame(1000, $result['total_bytes']);
        $this->assertEquals(50.0, $result['percentage']);
        $this->assertSame(10, $result['statements']);
    }

    public function testCleanupRemovesFile(): void {
        $dir = sys_get_temp_dir() . '/databrowse_import_progress';
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $file = $dir . '/' . $this->testId . '.json';
        file_put_contents($file, '{}');

        $this->assertFileExists($file);
        SQLImporter::cleanupProgress($this->testId);
        $this->assertFileDoesNotExist($file);
    }

    public function testProgressIdSanitization(): void {
        // IDs with special chars should be sanitized
        $result = SQLImporter::readProgress('../../../etc/passwd');
        $this->assertNull($result);
    }
}

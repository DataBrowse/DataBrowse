<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SQLTokenizerTest extends TestCase {
    public function testSplitSingleStatement(): void {
        $queries = SQLTokenizer::splitStatements('SELECT 1');
        $this->assertSame(['SELECT 1'], $queries);
    }

    public function testSplitMultipleStatements(): void {
        $queries = SQLTokenizer::splitStatements('SELECT 1; SELECT 2; SELECT 3');
        $this->assertCount(3, $queries);
    }

    public function testSplitKeepsStringsAndComments(): void {
        $sql = "SELECT 'a;b'; -- keep\nSELECT `x;y` FROM t;";
        $queries = SQLTokenizer::splitStatements($sql);
        $this->assertCount(2, $queries);
        $this->assertStringContainsString("'a;b'", $queries[0]);
        $this->assertStringContainsString('`x;y`', $queries[1]);
    }
}

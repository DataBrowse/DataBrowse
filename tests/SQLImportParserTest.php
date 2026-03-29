<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SQLImportParserTest extends TestCase {
    /**
     * @return list<string>
     */
    private function parseSql(string $sql): array {
        $parser = new SQLImportParser();
        $statements = [];
        $lines = preg_split("/(\r\n|\n|\r)/", $sql);
        if (!is_array($lines)) {
            return [];
        }

        foreach ($lines as $line) {
            $feed = $parser->feedLine($line . "\n");
            foreach ($feed as $stmt) {
                $statements[] = $stmt;
            }
        }

        $tail = $parser->flushRemainder();
        if ($tail !== null) {
            $statements[] = $tail;
        }

        return $statements;
    }

    public function testParsesBasicStatementsAndSkipsComments(): void {
        $sql = "-- heading\nCREATE TABLE t (id INT);\n# another comment\nINSERT INTO t VALUES (1);\n";
        $statements = $this->parseSql($sql);
        $this->assertCount(2, $statements);
        $this->assertSame('CREATE TABLE t (id INT)', $statements[0]);
        $this->assertSame('INSERT INTO t VALUES (1)', $statements[1]);
    }

    public function testSupportsDelimiterForProcedures(): void {
        $sql = "DELIMITER $$\n"
            . "CREATE PROCEDURE p()\n"
            . "BEGIN\n"
            . "  SELECT 1;\n"
            . "  SELECT 'a; b';\n"
            . "END$$\n"
            . "DELIMITER ;\n"
            . "SELECT 2;\n";
        $statements = $this->parseSql($sql);
        $this->assertCount(2, $statements);
        $this->assertStringStartsWith('CREATE PROCEDURE p()', $statements[0]);
        $this->assertStringContainsString("SELECT 'a; b';", $statements[0]);
        $this->assertSame('SELECT 2', $statements[1]);
    }

    public function testKeepsSemicolonsInsideStrings(): void {
        $sql = "INSERT INTO logs(message) VALUES('it\\'s; fine');\n";
        $statements = $this->parseSql($sql);
        $this->assertCount(1, $statements);
        $this->assertSame("INSERT INTO logs(message) VALUES('it\\'s; fine')", $statements[0]);
    }

    public function testReturnsTrailingStatementWithoutDelimiter(): void {
        $sql = "SELECT 1";
        $statements = $this->parseSql($sql);
        $this->assertCount(1, $statements);
        $this->assertSame('SELECT 1', $statements[0]);
    }
}


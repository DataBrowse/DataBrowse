<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class QueryExecutorTest extends TestCase {
    private function createExecutorForSplitTest(): QueryExecutor {
        // Use Reflection to instantiate without a real mysqli connection
        // splitQueries() doesn't use $this->conn so this is safe
        $ref = new ReflectionClass(QueryExecutor::class);
        $instance = $ref->newInstanceWithoutConstructor();
        return $instance;
    }

    public function testSplitSingleQuery(): void {
        $executor = $this->createExecutorForSplitTest();
        $queries = $executor->splitQueries('SELECT * FROM users');
        $this->assertCount(1, $queries);
        $this->assertSame('SELECT * FROM users', $queries[0]);
    }

    public function testSplitMultipleQueries(): void {
        $executor = $this->createExecutorForSplitTest();
        $queries = $executor->splitQueries('SELECT 1; SELECT 2; SELECT 3');
        $this->assertCount(3, $queries);
        $this->assertSame('SELECT 1', $queries[0]);
        $this->assertSame('SELECT 2', $queries[1]);
        $this->assertSame('SELECT 3', $queries[2]);
    }

    public function testSplitPreservesStringLiterals(): void {
        $executor = $this->createExecutorForSplitTest();
        $queries = $executor->splitQueries("SELECT 'hello; world' FROM test; SELECT 2");
        $this->assertCount(2, $queries);
        $this->assertSame("SELECT 'hello; world' FROM test", $queries[0]);
        $this->assertSame('SELECT 2', $queries[1]);
    }

    public function testSplitHandlesEscapedQuotes(): void {
        $executor = $this->createExecutorForSplitTest();
        $queries = $executor->splitQueries("SELECT 'it\\'s a test'; SELECT 2");
        $this->assertCount(2, $queries);
    }

    public function testSplitEmptyInput(): void {
        $executor = $this->createExecutorForSplitTest();
        $queries = $executor->splitQueries('');
        $this->assertCount(0, $queries);
    }

    public function testQueryResultToArray(): void {
        $result = new QueryResult(
            success: true,
            type: QueryType::SELECT,
            rows: [['id' => 1]],
            fields: [['name' => 'id']],
            rowCount: 1,
            affectedRows: 0,
            elapsed: 1.5,
            sql: 'SELECT 1',
        );
        $arr = $result->toArray();
        $this->assertTrue($arr['success']);
        $this->assertSame('SELECT', $arr['type']);
        $this->assertSame(1, $arr['row_count']);
        $this->assertSame(1.5, $arr['elapsed_ms']);
    }

    public function testQueryTypeEnum(): void {
        $this->assertSame(QueryType::SELECT, QueryType::tryFrom('SELECT'));
        $this->assertSame(QueryType::INSERT, QueryType::tryFrom('INSERT'));
        $this->assertSame(QueryType::UPDATE, QueryType::tryFrom('UPDATE'));
        $this->assertSame(QueryType::DELETE, QueryType::tryFrom('DELETE'));
        $this->assertNull(QueryType::tryFrom('INVALID'));
    }
}

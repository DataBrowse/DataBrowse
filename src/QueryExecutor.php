<?php
declare(strict_types=1);

enum QueryType: string {
    case SELECT = 'SELECT';
    case INSERT = 'INSERT';
    case UPDATE = 'UPDATE';
    case DELETE = 'DELETE';
    case CREATE = 'CREATE';
    case ALTER = 'ALTER';
    case DROP = 'DROP';
    case TRUNCATE = 'TRUNCATE';
    case SHOW = 'SHOW';
    case DESCRIBE = 'DESCRIBE';
    case EXPLAIN = 'EXPLAIN';
    case USE_DB = 'USE';
    case SET = 'SET';
    case GRANT = 'GRANT';
    case REVOKE = 'REVOKE';
    case OTHER = 'OTHER';
}

final readonly class QueryResult {
    public function __construct(
        public bool $success,
        public QueryType $type,
        public array $rows,
        public array $fields,
        public int $rowCount,
        public int $affectedRows,
        public float $elapsed,
        public string $sql,
        public string $message = '',
        public string $error = '',
        public int $errorCode = 0,
    ) {}

    public function toArray(): array {
        return [
            'success'       => $this->success,
            'type'          => $this->type->value,
            'rows'          => $this->rows,
            'fields'        => $this->fields,
            'row_count'     => $this->rowCount,
            'affected_rows' => $this->affectedRows,
            'elapsed_ms'    => $this->elapsed,
            'sql'           => $this->sql,
            'message'       => $this->message,
            'error'         => $this->error,
            'error_code'    => $this->errorCode,
        ];
    }
}

final class QueryExecutor {
    private array $history = [];

    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function execute(string $sql, int $limit = 1000): QueryResult {
        $startTime = hrtime(true);

        // Multi-query detection
        $queries = $this->splitQueries($sql);

        if (count($queries) > 1) {
            return $this->executeMulti($queries, $limit);
        }

        $query = trim($queries[0]);
        $type = $this->detectQueryType($query);

        // Auto-inject LIMIT for SELECT queries without one (safety measure)
        if ($type === QueryType::SELECT) {
            if (!preg_match('/\bLIMIT\b/i', $query)) {
                $query .= " LIMIT {$limit}";
            }
        }

        try {
            $result = $this->conn->query($query);
            $elapsed = (hrtime(true) - $startTime) / 1e6; // ms

            $queryResult = match(true) {
                $result instanceof mysqli_result => new QueryResult(
                    success: true,
                    type: $type,
                    rows: $result->fetch_all(MYSQLI_ASSOC),
                    fields: $this->extractFields($result),
                    rowCount: $result->num_rows,
                    affectedRows: 0,
                    elapsed: round($elapsed, 3),
                    sql: $query,
                ),
                $result === true => new QueryResult(
                    success: true,
                    type: $type,
                    rows: [],
                    fields: [],
                    rowCount: 0,
                    affectedRows: $this->conn->affected_rows,
                    elapsed: round($elapsed, 3),
                    sql: $query,
                    message: $this->conn->info ?: "Query OK, {$this->conn->affected_rows} rows affected",
                ),
                default => throw new \RuntimeException('Unexpected query result'),
            };

            $this->history[] = $queryResult;
            return $queryResult;

        } catch (\mysqli_sql_exception $e) {
            $elapsed = (hrtime(true) - $startTime) / 1e6;
            return new QueryResult(
                success: false,
                type: $type,
                rows: [],
                fields: [],
                rowCount: 0,
                affectedRows: 0,
                elapsed: round($elapsed, 3),
                sql: $query,
                error: $e->getMessage(),
                errorCode: $e->getCode(),
            );
        }
    }

    public function explain(string $sql): QueryResult {
        return $this->execute("EXPLAIN " . $sql);
    }

    public function getHistory(): array {
        return array_map(fn(QueryResult $r) => [
            'sql'      => $r->sql,
            'elapsed'  => $r->elapsed,
            'success'  => $r->success,
            'rowCount' => $r->rowCount,
            'type'     => $r->type->value,
        ], $this->history);
    }

    private function executeMulti(array $queries, int $limit): QueryResult {
        $results = [];
        $totalElapsed = 0;
        $totalRows = 0;
        $totalAffected = 0;
        $lastResult = null;

        foreach ($queries as $query) {
            $lastResult = $this->execute($query, $limit);
            $totalElapsed += $lastResult->elapsed;
            $totalRows += $lastResult->rowCount;
            $totalAffected += $lastResult->affectedRows;
            $results[] = $lastResult->toArray();

            if (!$lastResult->success) {
                return new QueryResult(
                    success: false,
                    type: $lastResult->type,
                    rows: $results,
                    fields: [],
                    rowCount: $totalRows,
                    affectedRows: $totalAffected,
                    elapsed: round($totalElapsed, 3),
                    sql: implode(";\n", $queries),
                    error: $lastResult->error,
                    errorCode: $lastResult->errorCode,
                );
            }
        }

        return new QueryResult(
            success: true,
            type: $lastResult?->type ?? QueryType::OTHER,
            rows: $lastResult?->rows ?? [],
            fields: $lastResult?->fields ?? [],
            rowCount: $totalRows,
            affectedRows: $totalAffected,
            elapsed: round($totalElapsed, 3),
            sql: implode(";\n", $queries),
            message: count($queries) . " statements executed successfully",
        );
    }

    private function detectQueryType(string $sql): QueryType {
        $trimmed = trim($sql);
        if ($trimmed === '') return QueryType::OTHER;
        $token = strtok($trimmed, " \t\n\r");
        if ($token === false) return QueryType::OTHER;
        return QueryType::tryFrom(strtoupper($token)) ?? QueryType::OTHER;
    }

    private function extractFields(mysqli_result $result): array {
        $fields = [];
        foreach ($result->fetch_fields() as $field) {
            $fields[] = [
                'name'      => $field->name,
                'table'     => $field->table,
                'type'      => $this->mapFieldType($field->type),
                'length'    => $field->length,
                'flags'     => $field->flags,
                'decimals'  => $field->decimals,
                'isPrimary' => (bool)($field->flags & MYSQLI_PRI_KEY_FLAG),
                'isUnique'  => (bool)($field->flags & MYSQLI_UNIQUE_KEY_FLAG),
                'isNotNull' => (bool)($field->flags & MYSQLI_NOT_NULL_FLAG),
                'isAutoInc' => (bool)($field->flags & MYSQLI_AUTO_INCREMENT_FLAG),
            ];
        }
        return $fields;
    }

    public function splitQueries(string $sql): array {
        $queries = [];
        $current = '';
        $inString = false;
        $stringChar = '';
        $escaped = false;

        for ($i = 0, $len = strlen($sql); $i < $len; $i++) {
            $char = $sql[$i];

            if ($escaped) {
                $current .= $char;
                $escaped = false;
                continue;
            }

            if ($char === '\\') {
                $current .= $char;
                $escaped = true;
                continue;
            }

            if (!$inString && ($char === '\'' || $char === '"')) {
                $inString = true;
                $stringChar = $char;
                $current .= $char;
                continue;
            }

            if ($inString && $char === $stringChar) {
                $inString = false;
                $current .= $char;
                continue;
            }

            if (!$inString && $char === ';') {
                $trimmed = trim($current);
                if ($trimmed !== '') $queries[] = $trimmed;
                $current = '';
                continue;
            }

            $current .= $char;
        }

        $trimmed = trim($current);
        if ($trimmed !== '') $queries[] = $trimmed;

        return $queries;
    }

    private function mapFieldType(int $type): string {
        return match($type) {
            MYSQLI_TYPE_TINY => 'tinyint',
            MYSQLI_TYPE_SHORT => 'smallint',
            MYSQLI_TYPE_LONG => 'int',
            MYSQLI_TYPE_FLOAT => 'float',
            MYSQLI_TYPE_DOUBLE => 'double',
            MYSQLI_TYPE_DECIMAL, MYSQLI_TYPE_NEWDECIMAL => 'decimal',
            MYSQLI_TYPE_TIMESTAMP => 'timestamp',
            MYSQLI_TYPE_LONGLONG => 'bigint',
            MYSQLI_TYPE_INT24 => 'mediumint',
            MYSQLI_TYPE_DATE, MYSQLI_TYPE_NEWDATE => 'date',
            MYSQLI_TYPE_TIME => 'time',
            MYSQLI_TYPE_DATETIME => 'datetime',
            MYSQLI_TYPE_YEAR => 'year',
            MYSQLI_TYPE_VAR_STRING, MYSQLI_TYPE_STRING => 'varchar',
            MYSQLI_TYPE_BLOB, MYSQLI_TYPE_TINY_BLOB,
            MYSQLI_TYPE_MEDIUM_BLOB, MYSQLI_TYPE_LONG_BLOB => 'blob',
            MYSQLI_TYPE_ENUM => 'enum',
            MYSQLI_TYPE_SET => 'set',
            MYSQLI_TYPE_JSON => 'json',
            default => 'unknown',
        };
    }
}

<?php
declare(strict_types=1);

final class SchemaInspector {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function getDatabases(): array {
        $result = $this->conn->query("
            SELECT
                s.SCHEMA_NAME as name,
                s.DEFAULT_CHARACTER_SET_NAME as charset,
                s.DEFAULT_COLLATION_NAME as collation,
                COUNT(t.TABLE_NAME) as table_count,
                COALESCE(SUM(t.DATA_LENGTH + t.INDEX_LENGTH), 0) as total_size
            FROM INFORMATION_SCHEMA.SCHEMATA s
            LEFT JOIN INFORMATION_SCHEMA.TABLES t
                ON s.SCHEMA_NAME = t.TABLE_SCHEMA
            GROUP BY s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME,
                     s.DEFAULT_COLLATION_NAME
            ORDER BY s.SCHEMA_NAME
        ");

        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function getTables(string $database): array {
        $stmt = $this->conn->prepare("
            SELECT
                TABLE_NAME as name,
                TABLE_TYPE as type,
                ENGINE as engine,
                TABLE_ROWS as row_count,
                DATA_LENGTH as data_size,
                INDEX_LENGTH as index_size,
                AUTO_INCREMENT as auto_increment,
                TABLE_COLLATION as collation,
                CREATE_TIME as created,
                UPDATE_TIME as updated,
                TABLE_COMMENT as comment
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = ?
            ORDER BY TABLE_NAME
        ");
        $stmt->bind_param('s', $database);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    public function getColumns(string $database, string $table): array {
        $stmt = $this->conn->prepare("
            SELECT
                COLUMN_NAME as name,
                ORDINAL_POSITION as position,
                COLUMN_DEFAULT as default_value,
                IS_NULLABLE as nullable,
                DATA_TYPE as data_type,
                COLUMN_TYPE as column_type,
                CHARACTER_MAXIMUM_LENGTH as max_length,
                NUMERIC_PRECISION as num_precision,
                NUMERIC_SCALE as num_scale,
                COLUMN_KEY as key_type,
                EXTRA as extra,
                COLUMN_COMMENT as comment,
                CHARACTER_SET_NAME as charset,
                COLLATION_NAME as collation
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION
        ");
        $stmt->bind_param('ss', $database, $table);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    public function getIndexes(string $database, string $table): array {
        $stmt = $this->conn->prepare("
            SELECT
                INDEX_NAME as name,
                NON_UNIQUE as non_unique,
                COLUMN_NAME as column_name,
                SEQ_IN_INDEX as seq,
                COLLATION as collation,
                CARDINALITY as cardinality,
                SUB_PART as sub_part,
                INDEX_TYPE as type,
                INDEX_COMMENT as comment
            FROM INFORMATION_SCHEMA.STATISTICS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
            ORDER BY INDEX_NAME, SEQ_IN_INDEX
        ");
        $stmt->bind_param('ss', $database, $table);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    public function getForeignKeys(string $database, string $table): array {
        $stmt = $this->conn->prepare("
            SELECT
                kcu.CONSTRAINT_NAME as name,
                kcu.COLUMN_NAME as column_name,
                kcu.REFERENCED_TABLE_SCHEMA as ref_schema,
                kcu.REFERENCED_TABLE_NAME as ref_table,
                kcu.REFERENCED_COLUMN_NAME as ref_column,
                rc.UPDATE_RULE as on_update,
                rc.DELETE_RULE as on_delete
            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
            JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc
                ON kcu.CONSTRAINT_NAME = rc.CONSTRAINT_NAME
                AND kcu.CONSTRAINT_SCHEMA = rc.CONSTRAINT_SCHEMA
            WHERE kcu.TABLE_SCHEMA = ?
                AND kcu.TABLE_NAME = ?
                AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
            ORDER BY kcu.CONSTRAINT_NAME, kcu.ORDINAL_POSITION
        ");
        $stmt->bind_param('ss', $database, $table);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    public function getCreateStatement(string $database, string $table): string {
        $this->conn->select_db($database);
        $escapedTable = str_replace('`', '``', $table);
        $result = $this->conn->query("SHOW CREATE TABLE `{$escapedTable}`");
        $row = $result->fetch_assoc();
        return $row['Create Table'] ?? $row['Create View'] ?? '';
    }

    public function getTableStatus(string $database, string $table): array {
        $this->conn->select_db($database);
        $stmt = $this->conn->prepare("SHOW TABLE STATUS LIKE ?");
        $stmt->bind_param('s', $table);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc() ?: [];
    }
}

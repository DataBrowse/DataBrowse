<?php
declare(strict_types=1);

final class SQLExporter {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    /**
     * Streaming SQL export — memory efficient using Generator pattern.
     * Even tables with millions of rows use minimal memory.
     */
    public function export(
        string $database,
        array $tables = [],
        bool $includeStructure = true,
        bool $includeData = true,
        bool $addDropTable = true,
        bool $addCreateDatabase = false,
        int $chunkSize = 1000,
    ): \Generator {
        $this->conn->select_db($database);

        // Header
        yield "-- DataBrowse SQL Export\n";
        yield "-- Server: {$this->conn->host_info}\n";
        yield "-- Database: {$database}\n";
        yield "-- Date: " . date('Y-m-d H:i:s') . "\n";
        yield "-- ------------------------------------------------\n\n";
        yield "SET NAMES utf8mb4;\n";
        yield "SET FOREIGN_KEY_CHECKS = 0;\n";
        yield "SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n\n";

        if ($addCreateDatabase) {
            $escapedDb = str_replace('`', '``', $database);
            yield "CREATE DATABASE IF NOT EXISTS `{$escapedDb}` "
                . "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n";
            yield "USE `{$escapedDb}`;\n\n";
        }

        if (empty($tables)) {
            $result = $this->conn->query("SHOW TABLES");
            $tables = array_column($result->fetch_all(), 0);
        }

        foreach ($tables as $table) {
            $escaped = str_replace('`', '``', $table);
            yield "-- ------------------------------------------------\n";
            yield "-- Table: `{$escaped}`\n";
            yield "-- ------------------------------------------------\n\n";

            if ($addDropTable) {
                yield "DROP TABLE IF EXISTS `{$escaped}`;\n\n";
            }

            if ($includeStructure) {
                $create = $this->conn->query("SHOW CREATE TABLE `{$escaped}`");
                $row = $create ? $create->fetch_assoc() : null;
                if ($row) {
                    yield ($row['Create Table'] ?? $row['Create View'] ?? "-- unknown object") . ";\n\n";
                } else {
                    yield "-- Could not retrieve CREATE statement for `{$escaped}`\n\n";
                }
            }

            if ($includeData) {
                yield from $this->exportTableData($table, $chunkSize);
            }
        }

        yield "SET FOREIGN_KEY_CHECKS = 1;\n";
    }

    private function exportTableData(string $table, int $chunkSize): \Generator {
        $escaped = str_replace('`', '``', $table);
        $result = $this->conn->query("SELECT * FROM `{$escaped}`", MYSQLI_USE_RESULT);
        $fields = $result->fetch_fields();
        $fieldNames = array_map(fn($f) => "`" . str_replace('`', '``', $f->name) . "`", $fields);
        $header = implode(', ', $fieldNames);

        $batch = [];
        $batchCount = 0;

        while ($row = $result->fetch_row()) {
            $values = [];
            foreach ($row as $i => $value) {
                if ($value === null) {
                    $values[] = 'NULL';
                } elseif ($this->isNumericType($fields[$i]->type)) {
                    $values[] = $value;
                } else {
                    $values[] = "'" . $this->conn->real_escape_string($value) . "'";
                }
            }
            $batch[] = '(' . implode(', ', $values) . ')';
            $batchCount++;

            if ($batchCount >= $chunkSize) {
                yield "INSERT INTO `{$escaped}` ({$header}) VALUES\n"
                    . implode(",\n", $batch) . ";\n\n";
                $batch = [];
                $batchCount = 0;
            }
        }

        if (!empty($batch)) {
            yield "INSERT INTO `{$escaped}` ({$header}) VALUES\n"
                . implode(",\n", $batch) . ";\n\n";
        }

        $result->free();
    }

    private function isNumericType(int $type): bool {
        return in_array($type, [
            MYSQLI_TYPE_TINY, MYSQLI_TYPE_SHORT, MYSQLI_TYPE_LONG,
            MYSQLI_TYPE_FLOAT, MYSQLI_TYPE_DOUBLE, MYSQLI_TYPE_LONGLONG,
            MYSQLI_TYPE_INT24, MYSQLI_TYPE_DECIMAL, MYSQLI_TYPE_NEWDECIMAL,
        ], true);
    }
}

final class CSVExporter {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function export(string $database, string $table): \Generator {
        $this->conn->select_db($database);
        $escaped = str_replace('`', '``', $table);
        $result = $this->conn->query("SELECT * FROM `{$escaped}`", MYSQLI_USE_RESULT);

        // Header row
        $fields = $result->fetch_fields();
        yield implode(',', array_map(fn($f) => '"' . str_replace('"', '""', $f->name) . '"', $fields)) . "\n";

        // Data rows (RFC 4180 compliant)
        while ($row = $result->fetch_row()) {
            $csvValues = array_map(
                fn($v) => $v === null ? '' : '"' . str_replace('"', '""', (string)$v) . '"',
                $row
            );
            yield implode(',', $csvValues) . "\n";
        }
        $result->free();
    }
}

final class JSONExporter {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function export(string $database, string $table): \Generator {
        $this->conn->select_db($database);
        $escaped = str_replace('`', '``', $table);
        $result = $this->conn->query("SELECT * FROM `{$escaped}`", MYSQLI_USE_RESULT);

        yield "[\n";
        $first = true;
        while ($row = $result->fetch_assoc()) {
            yield ($first ? '' : ",\n") . json_encode($row, JSON_UNESCAPED_UNICODE);
            $first = false;
        }
        yield "\n]";
        $result->free();
    }
}

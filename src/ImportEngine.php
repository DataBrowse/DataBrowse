<?php
declare(strict_types=1);

final readonly class ImportResult {
    public function __construct(
        public int $totalStatements,
        public int $executedStatements,
        public int $failedStatements,
        public array $errors,
    ) {}
}

final class SQLImporter {
    private int $totalStatements = 0;
    private int $executedStatements = 0;
    private int $failedStatements = 0;
    private array $errors = [];

    public function __construct(
        private readonly mysqli $conn,
    ) {}

    /**
     * Import SQL file in chunks with progress tracking.
     * Uses session-based progress updates.
     */
    public function import(
        string $filePath,
        string $database,
        string $progressId,
    ): ImportResult {
        $this->conn->select_db($database);
        $this->conn->begin_transaction();

        $handle = fopen($filePath, 'r');
        if (!$handle) {
            throw new \RuntimeException("Cannot open file: {$filePath}");
        }

        $fileSize = filesize($filePath);
        $bytesRead = 0;
        $currentStatement = '';

        try {
            while (($line = fgets($handle)) !== false) {
                $bytesRead += strlen($line);
                $trimmed = trim($line);

                // Skip comments and blank lines
                if ($trimmed === '' || str_starts_with($trimmed, '--') || str_starts_with($trimmed, '#')) {
                    continue;
                }

                $currentStatement .= $line;

                // Statement complete?
                if (str_ends_with($trimmed, ';')) {
                    $this->totalStatements++;
                    $stmt = trim($currentStatement);
                    $currentStatement = '';

                    try {
                        $this->conn->query($stmt);
                        $this->executedStatements++;
                    } catch (\mysqli_sql_exception $e) {
                        $this->failedStatements++;
                        $this->errors[] = [
                            'statement' => mb_substr($stmt, 0, 200),
                            'error'     => $e->getMessage(),
                            'code'      => $e->getCode(),
                        ];
                    }

                    // Update progress every 100 statements
                    if ($this->totalStatements % 100 === 0) {
                        $this->updateProgress($progressId, $bytesRead, $fileSize);
                    }
                }
            }

            $this->conn->commit();
        } catch (\Throwable $e) {
            $this->conn->rollback();
            throw $e;
        } finally {
            fclose($handle);
        }

        $this->updateProgress($progressId, $fileSize, $fileSize);

        return new ImportResult(
            totalStatements: $this->totalStatements,
            executedStatements: $this->executedStatements,
            failedStatements: $this->failedStatements,
            errors: $this->errors,
        );
    }

    private function updateProgress(string $id, int $bytesRead, int $totalBytes): void {
        $_SESSION['import_progress'][$id] = [
            'bytes_read'    => $bytesRead,
            'total_bytes'   => $totalBytes,
            'percentage'    => $totalBytes > 0 ? round(($bytesRead / $totalBytes) * 100, 1) : 0,
            'statements'    => $this->totalStatements,
            'executed'      => $this->executedStatements,
            'failed'        => $this->failedStatements,
            'updated_at'    => time(),
        ];
    }
}

final class CSVImporter {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function import(
        string $filePath,
        string $database,
        string $table,
        string $delimiter = ',',
        string $enclosure = '"',
        bool $hasHeader = true,
    ): ImportResult {
        $this->conn->select_db($database);
        $escapedTable = str_replace('`', '``', $table);

        $handle = fopen($filePath, 'r');
        if (!$handle) {
            throw new \RuntimeException("Cannot open file: {$filePath}");
        }

        $headers = null;
        $executed = 0;
        $failed = 0;
        $total = 0;
        $errors = [];

        if ($hasHeader) {
            $headers = fgetcsv($handle, 0, $delimiter, $enclosure);
        }

        $this->conn->begin_transaction();

        try {
            while (($row = fgetcsv($handle, 0, $delimiter, $enclosure)) !== false) {
                $total++;
                if (!$headers) {
                    $headers = range(0, count($row) - 1);
                }

                $columns = array_map(
                    fn($h) => '`' . str_replace('`', '``', $h) . '`',
                    $headers
                );
                $placeholders = array_fill(0, count($row), '?');
                $types = str_repeat('s', count($row));

                $sql = "INSERT INTO `{$escapedTable}` (" . implode(',', $columns) . ") VALUES (" . implode(',', $placeholders) . ")";

                try {
                    $stmt = $this->conn->prepare($sql);
                    $stmt->bind_param($types, ...$row);
                    $stmt->execute();
                    $executed++;
                } catch (\mysqli_sql_exception $e) {
                    $failed++;
                    if (count($errors) < 20) {
                        $errors[] = [
                            'row' => $total,
                            'error' => $e->getMessage(),
                            'code' => $e->getCode(),
                        ];
                    }
                }
            }

            $this->conn->commit();
        } catch (\Throwable $e) {
            $this->conn->rollback();
            throw $e;
        } finally {
            fclose($handle);
        }

        return new ImportResult(
            totalStatements: $total,
            executedStatements: $executed,
            failedStatements: $failed,
            errors: $errors,
        );
    }
}

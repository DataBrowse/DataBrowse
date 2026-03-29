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

final class SQLImportParser {
    private string $delimiter = ';';
    private string $buffer = '';
    private bool $firstLine = true;
    private bool $inSingleQuote = false;
    private bool $inDoubleQuote = false;
    private bool $inBacktick = false;
    private bool $inBlockComment = false;

    /**
     * @return list<string>
     */
    public function feedLine(string $line): array {
        if ($this->firstLine && str_starts_with($line, "\xEF\xBB\xBF")) {
            $line = substr($line, 3);
        }
        $this->firstLine = false;

        if (
            !$this->inSingleQuote
            && !$this->inDoubleQuote
            && !$this->inBacktick
            && !$this->inBlockComment
            && trim($this->buffer) === ''
            && preg_match('/^\s*DELIMITER\s+(\S+)\s*$/i', $line, $m) === 1
        ) {
            $candidate = (string)($m[1] ?? '');
            if ($candidate !== '') {
                $this->delimiter = $candidate;
            }
            return [];
        }

        $statements = [];
        $lineComment = false;
        $lineLen = strlen($line);
        $delimiterLen = strlen($this->delimiter);
        $escapeSingle = false;
        $escapeDouble = false;

        for ($i = 0; $i < $lineLen; $i++) {
            $ch = $line[$i];
            $next = $i + 1 < $lineLen ? $line[$i + 1] : '';

            if ($lineComment) {
                continue;
            }

            if ($this->inBlockComment) {
                if ($ch === '*' && $next === '/') {
                    $this->inBlockComment = false;
                    $i++;
                }
                continue;
            }

            if ($this->inSingleQuote) {
                $this->buffer .= $ch;
                if ($escapeSingle) {
                    $escapeSingle = false;
                } elseif ($ch === '\\') {
                    $escapeSingle = true;
                } elseif ($ch === "'") {
                    $this->inSingleQuote = false;
                }
                continue;
            }

            if ($this->inDoubleQuote) {
                $this->buffer .= $ch;
                if ($escapeDouble) {
                    $escapeDouble = false;
                } elseif ($ch === '\\') {
                    $escapeDouble = true;
                } elseif ($ch === '"') {
                    $this->inDoubleQuote = false;
                }
                continue;
            }

            if ($this->inBacktick) {
                $this->buffer .= $ch;
                if ($ch === '`') {
                    $this->inBacktick = false;
                }
                continue;
            }

            // Neutral state
            if ($ch === '#' || ($ch === '-' && $next === '-' && ($i + 2 >= $lineLen || ctype_space($line[$i + 2])))) {
                $lineComment = true;
                continue;
            }
            if ($ch === '/' && $next === '*') {
                $this->inBlockComment = true;
                $i++;
                continue;
            }
            if ($ch === "'") {
                $this->inSingleQuote = true;
                $escapeSingle = false;
                $this->buffer .= $ch;
                continue;
            }
            if ($ch === '"') {
                $this->inDoubleQuote = true;
                $escapeDouble = false;
                $this->buffer .= $ch;
                continue;
            }
            if ($ch === '`') {
                $this->inBacktick = true;
                $this->buffer .= $ch;
                continue;
            }

            $this->buffer .= $ch;
            if (
                $delimiterLen > 0
                && strlen($this->buffer) >= $delimiterLen
                && substr($this->buffer, -$delimiterLen) === $this->delimiter
            ) {
                $stmt = trim(substr($this->buffer, 0, -$delimiterLen));
                $this->buffer = '';
                if ($stmt !== '') {
                    $statements[] = $stmt;
                }
            }
        }

        return $statements;
    }

    public function flushRemainder(): ?string {
        $stmt = trim($this->buffer);
        $this->buffer = '';
        return $stmt !== '' ? $stmt : null;
    }
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
        bool $stopOnError = false,
    ): ImportResult {
        $this->conn->select_db($database);
        $this->conn->begin_transaction();

        $handle = fopen($filePath, 'r');
        if (!$handle) {
            throw new \RuntimeException("Cannot open file: {$filePath}");
        }

        $fileSize = filesize($filePath) ?: 0;
        $bytesRead = 0;
        $parser = new SQLImportParser();

        try {
            while (($line = fgets($handle)) !== false) {
                $bytesRead += strlen($line);
                $statements = $parser->feedLine($line);
                foreach ($statements as $stmt) {
                    if (!$this->executeStatement($stmt, $stopOnError)) {
                        $this->conn->rollback();
                        fclose($handle);
                        return new ImportResult(
                            totalStatements: $this->totalStatements,
                            executedStatements: $this->executedStatements,
                            failedStatements: $this->failedStatements,
                            errors: $this->errors,
                        );
                    }

                    if ($this->totalStatements % 100 === 0) {
                        $this->updateProgress($progressId, $bytesRead, $fileSize);
                    }
                }
            }

            $tail = $parser->flushRemainder();
            if ($tail !== null) {
                if (!$this->executeStatement($tail, $stopOnError)) {
                    $this->conn->rollback();
                    fclose($handle);
                    return new ImportResult(
                        totalStatements: $this->totalStatements,
                        executedStatements: $this->executedStatements,
                        failedStatements: $this->failedStatements,
                        errors: $this->errors,
                    );
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

    private function executeStatement(string $stmt, bool $stopOnError): bool {
        $this->totalStatements++;
        try {
            $this->conn->query($stmt);
            $this->executedStatements++;
            return true;
        } catch (\mysqli_sql_exception $e) {
            $this->failedStatements++;
            if (count($this->errors) < 20) {
                $this->errors[] = [
                    'statement' => mb_substr($stmt, 0, 200),
                    'error'     => $e->getMessage(),
                    'code'      => $e->getCode(),
                ];
            }
            return !$stopOnError;
        }
    }

    private function updateProgress(string $id, int $bytesRead, int $totalBytes): void {
        $dir = sys_get_temp_dir() . '/databrowse_import_progress';
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            return;
        }
        $file = $dir . '/' . preg_replace('/[^a-zA-Z0-9_\-]/', '', $id) . '.json';
        $data = json_encode([
            'bytes_read'    => $bytesRead,
            'total_bytes'   => $totalBytes,
            'percentage'    => $totalBytes > 0 ? round(($bytesRead / $totalBytes) * 100, 1) : 0,
            'statements'    => $this->totalStatements,
            'executed'      => $this->executedStatements,
            'failed'        => $this->failedStatements,
            'updated_at'    => time(),
        ], JSON_THROW_ON_ERROR);
        file_put_contents($file, $data, LOCK_EX);
    }

    public static function readProgress(string $id): ?array {
        $dir = sys_get_temp_dir() . '/databrowse_import_progress';
        $file = $dir . '/' . preg_replace('/[^a-zA-Z0-9_\-]/', '', $id) . '.json';
        if (!file_exists($file)) {
            return null;
        }
        $raw = file_get_contents($file);
        if (!is_string($raw) || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);

        // Probabilistic cleanup of stale progress files (2% chance)
        if (random_int(1, 50) === 1 && is_dir($dir)) {
            $now = time();
            $files = glob($dir . '/*.json');
            if (is_array($files)) {
                foreach ($files as $f) {
                    $mtime = @filemtime($f);
                    if ($mtime !== false && ($now - $mtime) > 3600) {
                        @unlink($f);
                    }
                }
            }
        }

        return is_array($data) ? $data : null;
    }

    public static function cleanupProgress(string $id): void {
        $dir = sys_get_temp_dir() . '/databrowse_import_progress';
        $file = $dir . '/' . preg_replace('/[^a-zA-Z0-9_\-]/', '', $id) . '.json';
        if (file_exists($file)) {
            @unlink($file);
        }
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
            $preparedStmt = null;
            $colCount = null;
            $types = null;

            while (($row = fgetcsv($handle, 0, $delimiter, $enclosure)) !== false) {
                $total++;
                if (!$headers) {
                    $headers = range(0, count($row) - 1);
                }

                $headerCount = count($headers);
                $rowCount = count($row);

                // Normalize row to match header count
                if ($rowCount < $headerCount) {
                    $row = array_pad($row, $headerCount, null);
                } elseif ($rowCount > $headerCount) {
                    $row = array_slice($row, 0, $headerCount);
                }

                // Prepare statement once, reuse for all rows
                if ($preparedStmt === null) {
                    $colCount = $headerCount;
                    $columns = array_map(
                        fn($h) => '`' . str_replace('`', '``', (string)$h) . '`',
                        $headers
                    );
                    $placeholders = array_fill(0, $colCount, '?');
                    $types = str_repeat('s', $colCount);
                    $sql = "INSERT INTO `{$escapedTable}` (" . implode(',', $columns) . ") VALUES (" . implode(',', $placeholders) . ")";
                    $preparedStmt = $this->conn->prepare($sql);
                }

                try {
                    $preparedStmt->bind_param($types, ...$row);
                    $preparedStmt->execute();
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

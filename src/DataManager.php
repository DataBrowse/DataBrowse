<?php
declare(strict_types=1);

final class DataManager {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function getData(
        string $database,
        string $table,
        int $page = 1,
        int $limit = 25,
        ?string $sort = null,
        string $order = 'ASC',
        ?string $search = null,
        array $filters = [],
    ): array {
        $this->conn->select_db($database);
        $page = max(1, $page);
        $limit = max(1, min(5000, $limit));
        $offset = ($page - 1) * $limit;
        $order = strtoupper($order) === 'DESC' ? 'DESC' : 'ASC';

        $whereClauses = [];
        $whereValues = [];
        $whereTypes = '';

        // Column filters
        foreach ($filters as $col => $val) {
            $escapedCol = str_replace('`', '``', (string)$col);
            $whereClauses[] = "`{$escapedCol}` LIKE ?";
            $whereValues[] = '%' . (string)$val . '%';
            $whereTypes .= 's';
        }

        // Global search — only search text-compatible columns to avoid
        // full table scans on BLOB/binary columns and improve performance
        if ($search !== null && $search !== '') {
            $inspector = new SchemaInspector($this->conn);
            $columns = $inspector->getColumns($database, $table);
            $searchableTypes = [
                'char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext',
                'enum', 'set', 'json',
                'int', 'tinyint', 'smallint', 'mediumint', 'bigint',
                'decimal', 'numeric', 'float', 'double',
                'date', 'datetime', 'timestamp', 'time', 'year',
            ];
            $searchClauses = [];
            foreach ($columns as $col) {
                $dataType = strtolower($col['data_type'] ?? '');
                if (!in_array($dataType, $searchableTypes, true)) {
                    continue;
                }
                $escapedCol = str_replace('`', '``', $col['name']);
                $searchClauses[] = "CAST(`{$escapedCol}` AS CHAR) LIKE ?";
                $whereValues[] = '%' . $search . '%';
                $whereTypes .= 's';
            }
            if (!empty($searchClauses)) {
                $whereClauses[] = '(' . implode(' OR ', $searchClauses) . ')';
            }
        }

        $whereSQL = !empty($whereClauses) ? ' WHERE ' . implode(' AND ', $whereClauses) : '';
        $escapedTable = str_replace('`', '``', $table);

        // Total count
        $countSql = "SELECT COUNT(*) as total FROM `{$escapedTable}`{$whereSQL}";
        if (!empty($whereValues)) {
            $countStmt = $this->conn->prepare($countSql);
            $countStmt->bind_param($whereTypes, ...$whereValues);
            $countStmt->execute();
            $total = (int)$countStmt->get_result()->fetch_assoc()['total'];
        } else {
            $total = (int)$this->conn->query($countSql)->fetch_assoc()['total'];
        }

        // Data query
        $dataSql = "SELECT * FROM `{$escapedTable}`{$whereSQL}";
        if ($sort) {
            $escapedSort = str_replace('`', '``', Security::sanitizeIdentifier($sort));
            $dataSql .= " ORDER BY `{$escapedSort}` {$order}";
        }
        $dataSql .= " LIMIT {$limit} OFFSET {$offset}";

        if (!empty($whereValues)) {
            $dataStmt = $this->conn->prepare($dataSql);
            $dataStmt->bind_param($whereTypes, ...$whereValues);
            $dataStmt->execute();
            $result = $dataStmt->get_result();
        } else {
            $result = $this->conn->query($dataSql);
        }

        $fields = [];
        foreach ($result->fetch_fields() as $f) {
            $fields[] = [
                'name' => $f->name,
                'type' => $f->type,
                'isPrimary' => (bool)($f->flags & MYSQLI_PRI_KEY_FLAG),
                'isAutoInc' => (bool)($f->flags & MYSQLI_AUTO_INCREMENT_FLAG),
                'isNotNull' => (bool)($f->flags & MYSQLI_NOT_NULL_FLAG),
            ];
        }

        return [
            'rows' => $result->fetch_all(MYSQLI_ASSOC),
            'fields' => $fields,
            'pagination' => [
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'pages' => $limit > 0 ? (int)ceil($total / $limit) : 0,
            ],
        ];
    }

    public function insertRow(string $database, string $table, array $row): int {
        if (empty($row)) throw new \InvalidArgumentException('Row data cannot be empty');
        $this->conn->select_db($database);
        $escapedTable = str_replace('`', '``', $table);

        $columns = [];
        $values = [];
        foreach ($row as $key => $val) {
            $columns[] = '`' . str_replace('`', '``', $key) . '`';
            $values[] = $val;
        }

        $placeholders = array_fill(0, count($values), '?');
        $types = str_repeat('s', count($values));

        $sql = "INSERT INTO `{$escapedTable}` (" . implode(',', $columns) . ") VALUES (" . implode(',', $placeholders) . ")";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param($types, ...$values);
        $stmt->execute();

        return $this->conn->insert_id;
    }

    public function updateRow(string $database, string $table, array $row, array $where): int {
        if (empty($row)) throw new \InvalidArgumentException('Row data cannot be empty');
        if (empty($where)) throw new \InvalidArgumentException('WHERE clause cannot be empty');
        $this->conn->select_db($database);
        $escapedTable = str_replace('`', '``', $table);

        $setClauses = [];
        $values = [];
        foreach ($row as $col => $val) {
            $setClauses[] = '`' . str_replace('`', '``', $col) . '` = ?';
            $values[] = $val;
        }

        $whereClauses = [];
        foreach ($where as $col => $val) {
            $whereClauses[] = '`' . str_replace('`', '``', $col) . '` = ?';
            $values[] = $val;
        }

        $sql = "UPDATE `{$escapedTable}` SET " . implode(', ', $setClauses) . " WHERE " . implode(' AND ', $whereClauses) . " LIMIT 1";
        $stmt = $this->conn->prepare($sql);
        $types = str_repeat('s', count($values));
        $stmt->bind_param($types, ...$values);
        $stmt->execute();

        return $stmt->affected_rows;
    }

    public function deleteRow(string $database, string $table, array $where): int {
        if (empty($where)) throw new \InvalidArgumentException('WHERE clause cannot be empty');
        $this->conn->select_db($database);
        $escapedTable = str_replace('`', '``', $table);

        $whereClauses = [];
        $values = [];
        foreach ($where as $col => $val) {
            $whereClauses[] = '`' . str_replace('`', '``', $col) . '` = ?';
            $values[] = $val;
        }

        $sql = "DELETE FROM `{$escapedTable}` WHERE " . implode(' AND ', $whereClauses) . " LIMIT 1";
        $stmt = $this->conn->prepare($sql);
        $types = str_repeat('s', count($values));
        $stmt->bind_param($types, ...$values);
        $stmt->execute();

        return $stmt->affected_rows;
    }

    public function batchDelete(string $database, string $table, array $rows): int {
        $this->conn->select_db($database);
        $escapedTable = str_replace('`', '``', $table);
        $this->conn->begin_transaction();
        try {
            $total = 0;
            foreach ($rows as $where) {
                if (empty($where)) continue;
                $whereClauses = [];
                $values = [];
                foreach ($where as $col => $val) {
                    $whereClauses[] = '`' . str_replace('`', '``', $col) . '` = ?';
                    $values[] = $val;
                }
                $sql = "DELETE FROM `{$escapedTable}` WHERE " . implode(' AND ', $whereClauses) . " LIMIT 1";
                $stmt = $this->conn->prepare($sql);
                $types = str_repeat('s', count($values));
                $stmt->bind_param($types, ...$values);
                $stmt->execute();
                $total += $stmt->affected_rows;
            }
            $this->conn->commit();
            return $total;
        } catch (\Throwable $e) {
            $this->conn->rollback();
            throw $e;
        }
    }
}

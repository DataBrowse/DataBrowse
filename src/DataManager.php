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
        $offset = ($page - 1) * $limit;
        $order = strtoupper($order) === 'DESC' ? 'DESC' : 'ASC';

        $whereClauses = [];
        $whereValues = [];
        $whereTypes = '';

        // Column filters
        foreach ($filters as $col => $val) {
            $escapedCol = str_replace('`', '``', $col);
            $whereClauses[] = "`{$escapedCol}` LIKE ?";
            $whereValues[] = "%{$val}%";
            $whereTypes .= 's';
        }

        // Global search
        if ($search) {
            $inspector = new SchemaInspector($this->conn);
            $columns = $inspector->getColumns($database, $table);
            $searchClauses = [];
            foreach ($columns as $col) {
                $escapedCol = str_replace('`', '``', $col['name']);
                $searchClauses[] = "`{$escapedCol}` LIKE ?";
                $whereValues[] = "%{$search}%";
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
            $escapedSort = str_replace('`', '``', $sort);
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
                'pages' => (int)ceil($total / $limit),
            ],
        ];
    }

    public function insertRow(string $database, string $table, array $row): int {
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
        $this->conn->begin_transaction();
        try {
            $total = 0;
            foreach ($rows as $where) {
                $total += $this->deleteRow($database, $table, $where);
            }
            $this->conn->commit();
            return $total;
        } catch (\Throwable $e) {
            $this->conn->rollback();
            throw $e;
        }
    }
}

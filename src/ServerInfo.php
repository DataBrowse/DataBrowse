<?php
declare(strict_types=1);

final class ServerInfo {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function getStatus(): array {
        $info = ConnectionManager::getServerInfo($this->conn);
        $uptime = $this->conn->query("SHOW STATUS LIKE 'Uptime'")->fetch_assoc()['Value'] ?? 0;
        $queries = $this->conn->query("SHOW STATUS LIKE 'Questions'")->fetch_assoc()['Value'] ?? 0;
        $threads = $this->conn->query("SHOW STATUS LIKE 'Threads_connected'")->fetch_assoc()['Value'] ?? 0;
        $slowQueries = $this->conn->query("SHOW STATUS LIKE 'Slow_queries'")->fetch_assoc()['Value'] ?? 0;

        $bufferPool = [];
        $bpResult = $this->conn->query("SHOW STATUS LIKE 'Innodb_buffer_pool%'");
        while ($row = $bpResult->fetch_assoc()) {
            $bufferPool[$row['Variable_name']] = $row['Value'];
        }

        return [
            'server' => $info,
            'uptime_seconds' => (int)$uptime,
            'total_queries' => (int)$queries,
            'threads_connected' => (int)$threads,
            'slow_queries' => (int)$slowQueries,
            'queries_per_second' => $uptime > 0 ? round((int)$queries / (int)$uptime, 2) : 0,
            'buffer_pool' => $bufferPool,
        ];
    }

    public function getVariables(?string $search = null): array {
        $result = $this->conn->query("SHOW VARIABLES");
        $vars = $result->fetch_all(MYSQLI_ASSOC);

        if ($search) {
            $search = strtolower($search);
            $vars = array_filter($vars, fn($v) =>
                str_contains(strtolower($v['Variable_name']), $search) ||
                str_contains(strtolower($v['Value']), $search)
            );
            $vars = array_values($vars);
        }

        return $vars;
    }

    public function getProcessList(): array {
        return $this->conn->query("SHOW FULL PROCESSLIST")->fetch_all(MYSQLI_ASSOC);
    }
}

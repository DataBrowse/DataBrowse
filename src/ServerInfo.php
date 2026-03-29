<?php
declare(strict_types=1);

final class ServerInfo {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function getStatus(): array {
        $info = ConnectionManager::getServerInfo($this->conn);

        // Single query to fetch all status variables
        $result = $this->conn->query("SHOW STATUS");
        $allStatus = [];
        while ($row = $result->fetch_assoc()) {
            $allStatus[$row['Variable_name']] = $row['Value'];
        }

        $uptime = (int)($allStatus['Uptime'] ?? 0);
        $queries = (int)($allStatus['Questions'] ?? 0);
        $threads = (int)($allStatus['Threads_connected'] ?? 0);
        $slowQueries = (int)($allStatus['Slow_queries'] ?? 0);

        $bufferPool = [];
        foreach ($allStatus as $name => $value) {
            if (str_starts_with($name, 'Innodb_buffer_pool')) {
                $bufferPool[$name] = $value;
            }
        }

        return [
            'server' => $info,
            'uptime_seconds' => $uptime,
            'total_queries' => $queries,
            'threads_connected' => $threads,
            'slow_queries' => $slowQueries,
            'queries_per_second' => $uptime > 0 ? round($queries / $uptime, 2) : 0,
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

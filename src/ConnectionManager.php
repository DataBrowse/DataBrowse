<?php
declare(strict_types=1);

final class ConnectionManager {
    private static array $connections = [];

    public static function connect(
        string $host,
        string $username,
        string $password,
        int $port = 3306,
        ?string $database = null,
        ?string $socket = null,
    ): mysqli {
        $key = "{$username}@{$host}:{$port}" . ($socket ? ":sock:{$socket}" : '');

        if (isset(self::$connections[$key])) {
            try {
                self::$connections[$key]->query('SELECT 1');
                if ($database) self::$connections[$key]->select_db($database);
                return self::$connections[$key];
            } catch (\mysqli_sql_exception) {
                unset(self::$connections[$key]);
            }
        }

        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

        $conn = new mysqli();
        $conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
        $conn->options(MYSQLI_OPT_READ_TIMEOUT, 30);

        $conn->real_connect(
            hostname: $socket ? null : $host,
            username: $username,
            password: $password,
            database: $database,
            port: $port,
            socket: $socket,
        );

        $conn->set_charset('utf8mb4');

        // Set session modes for consistent behavior
        $sqlMode = Config::get('security.sql_mode', 'TRADITIONAL');
        if (is_string($sqlMode) && $sqlMode !== '') {
            $conn->query("SET SESSION sql_mode = '" . $conn->real_escape_string($sqlMode) . "'");
        }
        $conn->query("SET SESSION group_concat_max_len = 1048576");

        self::$connections[$key] = $conn;
        return $conn;
    }

    public static function getServerInfo(mysqli $conn): array {
        $version = $conn->server_info;
        $isMariaDB = str_contains(strtolower($version), 'mariadb');

        return [
            'version'    => $version,
            'is_mariadb' => $isMariaDB,
            'charset'    => $conn->character_set_name(),
            'protocol'   => $conn->protocol_version,
            'host_info'  => $conn->host_info,
            'server_id'  => $conn->thread_id,
        ];
    }

}

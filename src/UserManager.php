<?php
declare(strict_types=1);

final class UserManager {
    private const ALLOWED_PRIVILEGES = [
        'ALL PRIVILEGES',
        'ALTER', 'ALTER ROUTINE', 'CREATE', 'CREATE ROUTINE', 'CREATE TABLESPACE', 'CREATE TEMPORARY TABLES',
        'CREATE USER', 'CREATE VIEW', 'DELETE', 'DROP', 'EVENT', 'EXECUTE', 'FILE', 'GRANT OPTION',
        'INDEX', 'INSERT', 'LOCK TABLES', 'PROCESS', 'REFERENCES', 'RELOAD', 'REPLICATION CLIENT',
        'REPLICATION SLAVE', 'SELECT', 'SHOW DATABASES', 'SHOW VIEW', 'SHUTDOWN', 'SUPER', 'TRIGGER',
        'UPDATE', 'USAGE',
    ];

    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function getUsers(): array {
        $result = $this->conn->query(
            "SELECT User, Host, account_locked, password_expired FROM mysql.user ORDER BY User, Host"
        );
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function getPrivileges(string $user, string $host): array {
        $stmt = $this->conn->prepare("SHOW GRANTS FOR ?@?");
        $stmt->bind_param('ss', $user, $host);
        $stmt->execute();
        $grants = [];
        $result = $stmt->get_result();
        while ($row = $result->fetch_row()) {
            $grants[] = $row[0];
        }
        return ['grants' => $grants];
    }

    public function createUser(string $user, string $host, string $password): void {
        $stmt = $this->conn->prepare("CREATE USER ?@? IDENTIFIED BY ?");
        $stmt->bind_param('sss', $user, $host, $password);
        $stmt->execute();
    }

    public function dropUser(string $user, string $host): void {
        $stmt = $this->conn->prepare("DROP USER ?@?");
        $stmt->bind_param('ss', $user, $host);
        $stmt->execute();
    }

    public function grantPrivilege(string $user, string $host, string $privilege, string $database, string $table = '*'): void {
        $priv = $this->sanitizePrivilege($privilege);
        $db = $database === '*' ? '*' : '`' . str_replace('`', '``', Security::sanitizeIdentifier($database)) . '`';
        $tbl = $table === '*' ? '*' : '`' . str_replace('`', '``', Security::sanitizeIdentifier($table)) . '`';
        $escapedUser = $this->conn->real_escape_string($user);
        $escapedHost = $this->conn->real_escape_string($host);
        $this->conn->query("GRANT {$priv} ON {$db}.{$tbl} TO '{$escapedUser}'@'{$escapedHost}'");
        $this->conn->query("FLUSH PRIVILEGES");
    }

    public function revokePrivilege(string $user, string $host, string $privilege, string $database, string $table = '*'): void {
        $priv = $this->sanitizePrivilege($privilege);
        $db = $database === '*' ? '*' : '`' . str_replace('`', '``', Security::sanitizeIdentifier($database)) . '`';
        $tbl = $table === '*' ? '*' : '`' . str_replace('`', '``', Security::sanitizeIdentifier($table)) . '`';
        $escapedUser = $this->conn->real_escape_string($user);
        $escapedHost = $this->conn->real_escape_string($host);
        $this->conn->query("REVOKE {$priv} ON {$db}.{$tbl} FROM '{$escapedUser}'@'{$escapedHost}'");
        $this->conn->query("FLUSH PRIVILEGES");
    }

    private function sanitizePrivilege(string $privilege): string {
        $candidate = strtoupper(trim($privilege));
        if (!in_array($candidate, self::ALLOWED_PRIVILEGES, true)) {
            throw new \InvalidArgumentException('Invalid privilege: ' . $privilege);
        }
        return $candidate;
    }

}

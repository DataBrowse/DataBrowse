<?php
declare(strict_types=1);

final class UserManager {
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
        $priv = Security::sanitizeIdentifier($privilege);
        $db = $database === '*' ? '*' : '`' . Security::sanitizeIdentifier($database) . '`';
        $tbl = $table === '*' ? '*' : '`' . Security::sanitizeIdentifier($table) . '`';
        $this->conn->query(
            "GRANT {$priv} ON {$db}.{$tbl} TO '"
            . $this->conn->real_escape_string($user) . "'@'"
            . $this->conn->real_escape_string($host) . "'"
        );
        $this->conn->query("FLUSH PRIVILEGES");
    }

    public function revokePrivilege(string $user, string $host, string $privilege, string $database, string $table = '*'): void {
        $priv = Security::sanitizeIdentifier($privilege);
        $db = $database === '*' ? '*' : '`' . Security::sanitizeIdentifier($database) . '`';
        $tbl = $table === '*' ? '*' : '`' . Security::sanitizeIdentifier($table) . '`';
        $this->conn->query(
            "REVOKE {$priv} ON {$db}.{$tbl} FROM '"
            . $this->conn->real_escape_string($user) . "'@'"
            . $this->conn->real_escape_string($host) . "'"
        );
        $this->conn->query("FLUSH PRIVILEGES");
    }
}

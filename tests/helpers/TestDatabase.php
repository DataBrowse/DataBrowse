<?php
declare(strict_types=1);

// Tell bootstrap.php we're in test mode — skip runtime initialization
define('DATABROWSE_TESTING', true);

// Initialize session superglobal for tests
if (!isset($_SESSION)) $_SESSION = [];
if (!isset($_SERVER['REQUEST_URI'])) $_SERVER['REQUEST_URI'] = '/';
if (!isset($_SERVER['REMOTE_ADDR'])) $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

// Load source files
require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/Helpers.php';
require_once __DIR__ . '/../../src/Security.php';
require_once __DIR__ . '/../../src/Router.php';
require_once __DIR__ . '/../../src/ConnectionManager.php';
require_once __DIR__ . '/../../src/SchemaInspector.php';
require_once __DIR__ . '/../../src/QueryExecutor.php';
require_once __DIR__ . '/../../src/DataManager.php';
require_once __DIR__ . '/../../src/ExportEngine.php';
require_once __DIR__ . '/../../src/ImportEngine.php';
require_once __DIR__ . '/../../src/UserManager.php';
require_once __DIR__ . '/../../src/ServerInfo.php';
require_once __DIR__ . '/../../src/SchemaCompare.php';

// Restore PHPUnit's error handling (bootstrap.php overrides it)
restore_error_handler();
restore_exception_handler();

final class TestDatabase {
    private static ?string $dbName = null;

    public static function getConnection(): mysqli {
        return ConnectionManager::connect(
            host: getenv('DATABROWSE_TEST_HOST') ?: '127.0.0.1',
            username: getenv('DATABROWSE_TEST_USER') ?: 'root',
            password: getenv('DATABROWSE_TEST_PASS') ?: '',
            port: (int)(getenv('DATABROWSE_TEST_PORT') ?: 3306),
        );
    }

    public static function createTestDb(): string {
        if (self::$dbName) return self::$dbName;
        self::$dbName = 'databrowse_test_' . bin2hex(random_bytes(4));
        $conn = self::getConnection();
        $conn->query("CREATE DATABASE `" . self::$dbName . "` CHARACTER SET utf8mb4");
        $conn->select_db(self::$dbName);

        $conn->query("CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            email VARCHAR(100),
            age INT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username)
        ) ENGINE=InnoDB");

        $conn->query("CREATE TABLE posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            title VARCHAR(200) NOT NULL,
            body TEXT,
            published BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB");

        $conn->query("INSERT INTO users (username, email, age) VALUES
            ('admin', 'admin@example.com', 30),
            ('john', 'john@example.com', 25),
            ('jane', 'jane@example.com', NULL)");

        $conn->query("INSERT INTO posts (user_id, title, body, published) VALUES
            (1, 'First Post', 'Hello world', TRUE),
            (1, 'Second Post', 'Another post', FALSE),
            (2, 'Johns Post', 'Content here', TRUE)");

        return self::$dbName;
    }

    public static function dropTestDb(): void {
        if (!self::$dbName) return;
        $conn = self::getConnection();
        $conn->query("DROP DATABASE IF EXISTS `" . self::$dbName . "`");
        self::$dbName = null;
    }
}

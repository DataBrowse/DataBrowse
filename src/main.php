<?php
declare(strict_types=1);
// === Main Dispatch Point ===

$router = new Router();
if (!isset($config)) $config = loadConfig();
$nonce = $cspNonce ?? '';

// Security headers
if ($config['security']['csp_enabled']) {
    Security::setSecurityHeaders($nonce);
}

// IP whitelist check
if (!Security::checkIPWhitelist($config['security']['ip_whitelist'])) {
    http_response_code(403);
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (str_contains($uri, '/api/')) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Access denied']);
    } else {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>403 Forbidden</h1><p>Your IP address is not allowed.</p></body></html>';
    }
    exit;
}

// === Auth Routes (CSRF exempt) ===
$router->post('/api/auth/login', function (array $params) use ($config): array {
    $input = getJsonInput();

    // Rate limit check
    $ip = Security::getClientIP();
    if (!Security::checkRateLimit(
        "login:{$ip}",
        $config['security']['max_login_attempts'],
        $config['security']['lockout_duration']
    )) {
        http_response_code(429);
        return ['error' => 'Too many login attempts. Try again later.'];
    }

    // Root login check
    if (!$config['security']['allow_root_login'] && ($input['username'] ?? '') === 'root') {
        http_response_code(403);
        return ['error' => 'Root login is disabled.'];
    }

    try {
        $conn = ConnectionManager::connect(
            host: $input['host'] ?? '127.0.0.1',
            username: $input['username'] ?? '',
            password: $input['password'] ?? '',
            port: (int)($input['port'] ?? 3306),
            socket: $input['socket'] ?? null,
        );

        // Save session
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        $_SESSION['host'] = $input['host'] ?? '127.0.0.1';
        $_SESSION['username'] = $input['username'] ?? '';
        $_SESSION['password'] = $input['password'] ?? '';
        $_SESSION['port'] = (int)($input['port'] ?? 3306);
        $_SESSION['socket'] = $input['socket'] ?? null;
        $_SESSION['login_time'] = time();
        $_SESSION['csrf_token'] = Security::generateCSRFToken();

        $serverInfo = ConnectionManager::getServerInfo($conn);

        return [
            'success' => true,
            'server' => $serverInfo,
            'csrf_token' => $_SESSION['csrf_token'],
        ];
    } catch (\mysqli_sql_exception $e) {
        http_response_code(401);
        return ['error' => 'Authentication failed: ' . $e->getMessage()];
    }
});

$router->post('/api/auth/logout', function (): array {
    session_destroy();
    return ['success' => true];
});

$router->get('/api/auth/status', function (): array {
    $authenticated = !empty($_SESSION['authenticated']);
    return [
        'authenticated' => $authenticated,
        'username' => $_SESSION['username'] ?? null,
        'host' => $_SESSION['host'] ?? null,
        'csrf_token' => $authenticated ? ($_SESSION['csrf_token'] ?? null) : null,
    ];
});

// === Middleware: Auth + CSRF check ===
$authMiddleware = function () use ($config): ?array {
    // Session timeout (based on last activity, not login time)
    $lastActivity = $_SESSION['last_activity'] ?? $_SESSION['login_time'] ?? 0;
    if ($lastActivity > 0 && (time() - $lastActivity > $config['security']['session_timeout'])) {
        session_destroy();
        http_response_code(401);
        return ['error' => 'Session expired'];
    }
    $_SESSION['last_activity'] = time();

    if (empty($_SESSION['authenticated'])) {
        http_response_code(401);
        return ['error' => 'Not authenticated'];
    }

    // CSRF check (POST/PUT/DELETE/PATCH only)
    $method = $_SERVER['REQUEST_METHOD'];
    if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH']) && $config['security']['csrf_enabled']) {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!Security::validateCSRFToken($token)) {
            http_response_code(403);
            return ['error' => 'Invalid CSRF token'];
        }
    }

    // Read-only mode: block write operations
    if ($config['security']['read_only_mode'] && in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'])) {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        // Allow login/logout/export/query(read)/explain even in read-only mode
        $writeExempt = ['/api/auth/', '/api/export/', '/api/query/'];
        $isExempt = false;
        foreach ($writeExempt as $prefix) {
            if (str_contains($uri, $prefix)) { $isExempt = true; break; }
        }
        if (!$isExempt) {
            http_response_code(403);
            return ['error' => 'Server is in read-only mode. Write operations are disabled.'];
        }
    }

    return null; // Auth passed
};

// Helper: parse JSON request body with validation
function getJsonInput(): array {
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) {
        http_response_code(400);
        return [];
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        http_response_code(400);
        return [];
    }
    return $data;
}

// Helper: get authenticated connection
function getConnection(): mysqli {
    return ConnectionManager::connect(
        host: $_SESSION['host'],
        username: $_SESSION['username'],
        password: $_SESSION['password'],
        port: $_SESSION['port'],
        socket: $_SESSION['socket'] ?? null,
    );
}

// === Database Routes ===
$router->get('/api/databases', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $inspector = new SchemaInspector(getConnection());
    return ['databases' => $inspector->getDatabases()];
});

$router->post('/api/databases', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    $name = Security::sanitizeIdentifier($input['name'] ?? '');
    $charset = Security::sanitizeIdentifier($input['charset'] ?? 'utf8mb4');
    $collation = Security::sanitizeIdentifier($input['collation'] ?? 'utf8mb4_unicode_ci');

    $conn = getConnection();
    $conn->query("CREATE DATABASE `{$name}` CHARACTER SET {$charset} COLLATE {$collation}");
    return ['success' => true, 'database' => $name];
});

$router->delete('/api/databases/{name}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $name = Security::sanitizeIdentifier($params['name']);
    $conn = getConnection();
    $conn->query("DROP DATABASE `{$name}`");
    return ['success' => true];
});

// === Table Routes ===
$router->get('/api/tables/{db}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $inspector = new SchemaInspector(getConnection());
    return ['tables' => $inspector->getTables($db)];
});

$router->get('/api/tables/{db}/{table}/structure', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $inspector = new SchemaInspector(getConnection());
    return [
        'columns' => $inspector->getColumns($db, $table),
        'indexes' => $inspector->getIndexes($db, $table),
        'foreign_keys' => $inspector->getForeignKeys($db, $table),
        'create_statement' => $inspector->getCreateStatement($db, $table),
        'status' => $inspector->getTableStatus($db, $table),
    ];
});

$router->post('/api/tables/{db}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $input = getJsonInput();
    $tableName = Security::sanitizeIdentifier($input['name']);
    $engine = Security::sanitizeIdentifier($input['engine'] ?? 'InnoDB');
    $charset = Security::sanitizeIdentifier($input['charset'] ?? 'utf8mb4');

    // Allowed MySQL column types (whitelist)
    $allowedTypes = ['INT','TINYINT','SMALLINT','MEDIUMINT','BIGINT','FLOAT','DOUBLE','DECIMAL',
        'VARCHAR','CHAR','TEXT','TINYTEXT','MEDIUMTEXT','LONGTEXT','BLOB','TINYBLOB','MEDIUMBLOB','LONGBLOB',
        'DATE','DATETIME','TIMESTAMP','TIME','YEAR','BOOLEAN','BOOL','JSON','ENUM','SET','BINARY','VARBINARY'];

    $conn = getConnection();
    $conn->select_db($db);

    $columns = [];
    foreach ($input['columns'] as $col) {
        $colType = strtoupper(trim($col['type']));
        if (!in_array($colType, $allowedTypes)) {
            http_response_code(400);
            return ['error' => 'Invalid column type: ' . htmlspecialchars($col['type'])];
        }
        $def = '`' . Security::sanitizeIdentifier($col['name']) . '` ' . $colType;
        if (!empty($col['length'])) $def .= '(' . (int)$col['length'] . ')';
        if (!($col['nullable'] ?? true)) $def .= ' NOT NULL';
        if (isset($col['default'])) {
            $def .= " DEFAULT " . (is_numeric($col['default'])
                ? (float)$col['default']
                : "'" . $conn->real_escape_string((string)$col['default']) . "'");
        }
        if (!empty($col['auto_increment'])) $def .= ' AUTO_INCREMENT';
        if (!empty($col['primary'])) $def .= ' PRIMARY KEY';
        if (!empty($col['comment'])) $def .= " COMMENT '" . $conn->real_escape_string($col['comment']) . "'";
        $columns[] = $def;
    }
    $sql = "CREATE TABLE `{$tableName}` (\n  " . implode(",\n  ", $columns) . "\n) ENGINE={$engine} DEFAULT CHARSET={$charset}";
    $conn->query($sql);
    return ['success' => true, 'table' => $tableName, 'sql' => $sql];
});

$router->delete('/api/tables/{db}/{table}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $conn = getConnection();
    $conn->select_db($db);
    $conn->query("DROP TABLE `{$table}`");
    return ['success' => true];
});

$router->post('/api/tables/{db}/{table}/truncate', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $conn = getConnection();
    $conn->select_db($db);
    $conn->query("TRUNCATE TABLE `{$table}`");
    return ['success' => true];
});

// === Data Routes ===
$router->get('/api/data/{db}/{table}', function (array $params) use ($authMiddleware, $config): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);

    $page = max(1, (int)($_GET['page'] ?? 1));
    $limit = min(500, max(1, (int)($_GET['limit'] ?? $config['ui']['rows_per_page'])));
    $sort = isset($_GET['sort']) && $_GET['sort'] !== '' ? $_GET['sort'] : null;
    if ($sort) { Security::sanitizeIdentifier($sort); } // Validate column name
    $order = $_GET['order'] ?? 'ASC';
    $search = $_GET['search'] ?? null;

    $conn = getConnection();
    $dm = new DataManager($conn);
    return $dm->getData($db, $table, $page, $limit, $sort, $order, $search);
});

$router->post('/api/data/{db}/{table}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $input = getJsonInput();

    $conn = getConnection();
    $dm = new DataManager($conn);
    $insertId = $dm->insertRow($db, $table, $input['row']);
    return ['success' => true, 'insert_id' => $insertId];
});

$router->put('/api/data/{db}/{table}/{pk}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $input = getJsonInput();

    $conn = getConnection();
    $dm = new DataManager($conn);
    $affected = $dm->updateRow($db, $table, $input['row'], $input['where']);
    return ['success' => true, 'affected_rows' => $affected];
});

$router->delete('/api/data/{db}/{table}/{pk}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $input = getJsonInput();

    $conn = getConnection();
    $dm = new DataManager($conn);
    $affected = $dm->deleteRow($db, $table, $input['where']);
    return ['success' => true, 'affected_rows' => $affected];
});

$router->post('/api/data/{db}/{table}/batch-delete', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $input = getJsonInput();

    $conn = getConnection();
    $dm = new DataManager($conn);
    $affected = $dm->batchDelete($db, $table, $input['rows']);
    return ['success' => true, 'affected_rows' => $affected];
});

// === Query Routes ===
$router->post('/api/query/execute', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    $sql = $input['sql'] ?? '';
    $database = $input['database'] ?? null;

    $conn = getConnection();
    if ($database) {
        $conn->select_db(Security::sanitizeIdentifier($database));
    }

    $executor = new QueryExecutor($conn);
    $result = $executor->execute($sql, (int)($input['limit'] ?? 1000));

    // Save to session history
    if (!isset($_SESSION['query_history'])) {
        $_SESSION['query_history'] = [];
    }
    array_unshift($_SESSION['query_history'], [
        'sql' => $sql,
        'database' => $database,
        'success' => $result->success,
        'elapsed' => $result->elapsed,
        'rowCount' => $result->rowCount,
        'timestamp' => time(),
    ]);
    $_SESSION['query_history'] = array_slice($_SESSION['query_history'], 0, 50);

    return $result->toArray();
});

$router->post('/api/query/explain', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    $database = $input['database'] ?? null;

    $conn = getConnection();
    if ($database) {
        $conn->select_db(Security::sanitizeIdentifier($database));
    }

    $executor = new QueryExecutor($conn);
    return $executor->explain($input['sql'] ?? '')->toArray();
});

$router->get('/api/query/history', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    return ['history' => $_SESSION['query_history'] ?? []];
});

// === Export Routes ===
$router->post('/api/export/sql', function () use ($authMiddleware): void {
    if ($err = ($authMiddleware)()) { echo json_encode($err); return; }
    $input = getJsonInput();
    $db = Security::sanitizeIdentifier($input['database']);

    $conn = getConnection();
    $exporter = new SQLExporter($conn);

    header('Content-Type: application/sql');
    header("Content-Disposition: attachment; filename=\"{$db}_" . date('Y-m-d_His') . ".sql\"");

    foreach ($exporter->export(
        database: $db,
        tables: $input['tables'] ?? [],
        includeStructure: $input['structure'] ?? true,
        includeData: $input['data'] ?? true,
        addDropTable: $input['drop_table'] ?? true,
    ) as $chunk) {
        echo $chunk;
        flush();
    }
});

$router->post('/api/export/csv', function () use ($authMiddleware): void {
    if ($err = ($authMiddleware)()) { echo json_encode($err); return; }
    $input = getJsonInput();
    $db = Security::sanitizeIdentifier($input['database']);
    $table = Security::sanitizeIdentifier($input['table']);

    $conn = getConnection();
    $exporter = new CSVExporter($conn);

    header('Content-Type: text/csv; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"{$table}_" . date('Y-m-d_His') . ".csv\"");

    foreach ($exporter->export($db, $table) as $chunk) {
        echo $chunk;
        flush();
    }
});

$router->post('/api/export/json', function () use ($authMiddleware): void {
    if ($err = ($authMiddleware)()) { echo json_encode($err); return; }
    $input = getJsonInput();
    $db = Security::sanitizeIdentifier($input['database']);
    $table = Security::sanitizeIdentifier($input['table']);

    $conn = getConnection();
    $exporter = new JSONExporter($conn);

    header('Content-Type: application/json');
    header("Content-Disposition: attachment; filename=\"{$table}_" . date('Y-m-d_His') . ".json\"");

    foreach ($exporter->export($db, $table) as $chunk) {
        echo $chunk;
        flush();
    }
});

// === Import Routes ===
$router->post('/api/import/sql', function () use ($authMiddleware, $config): array {
    if ($err = ($authMiddleware)()) return $err;

    if (!isset($_FILES['file'])) {
        http_response_code(400);
        return ['error' => 'No file uploaded'];
    }

    $file = $_FILES['file'];
    $maxSize = $config['import']['max_file_size'];

    if ($file['size'] > $maxSize) {
        http_response_code(413);
        return ['error' => 'File too large. Max: ' . Helpers::formatSize($maxSize)];
    }

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $config['import']['allowed_extensions'])) {
        http_response_code(400);
        return ['error' => 'Invalid file type. Allowed: ' . implode(', ', $config['import']['allowed_extensions'])];
    }

    $database = Security::sanitizeIdentifier($_POST['database'] ?? '');
    $progressId = bin2hex(random_bytes(8));

    $conn = getConnection();
    $importer = new SQLImporter($conn);
    $result = $importer->import($file['tmp_name'], $database, $progressId);

    return [
        'success' => true,
        'total_statements' => $result->totalStatements,
        'executed' => $result->executedStatements,
        'failed' => $result->failedStatements,
        'errors' => array_slice($result->errors, 0, 20),
    ];
});

$router->post('/api/import/csv', function () use ($authMiddleware, $config): array {
    if ($err = ($authMiddleware)()) return $err;

    if (!isset($_FILES['file'])) {
        http_response_code(400);
        return ['error' => 'No file uploaded'];
    }

    $file = $_FILES['file'];
    if ($file['size'] > $config['import']['max_file_size']) {
        http_response_code(413);
        return ['error' => 'File too large. Max: ' . Helpers::formatSize($config['import']['max_file_size'])];
    }

    $database = Security::sanitizeIdentifier($_POST['database'] ?? '');
    $table = Security::sanitizeIdentifier($_POST['table'] ?? '');

    $conn = getConnection();
    $importer = new CSVImporter($conn);
    $result = $importer->import(
        filePath: $file['tmp_name'],
        database: $database,
        table: $table,
        delimiter: $_POST['delimiter'] ?? ',',
        hasHeader: ($_POST['has_header'] ?? '1') === '1',
    );

    return [
        'success' => true,
        'total_rows' => $result->totalStatements,
        'imported' => $result->executedStatements,
        'failed' => $result->failedStatements,
        'errors' => array_slice($result->errors, 0, 20),
    ];
});

$router->get('/api/import/progress/{id}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $id = $params['id'];
    return $_SESSION['import_progress'][$id] ?? ['error' => 'Progress not found'];
});

// === Server Routes ===
$router->get('/api/server/status', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $info = new ServerInfo($conn);
    return $info->getStatus();
});

$router->get('/api/server/variables', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $info = new ServerInfo($conn);
    $search = $_GET['search'] ?? null;
    return ['variables' => $info->getVariables($search)];
});

$router->get('/api/server/processes', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $info = new ServerInfo($conn);
    return ['processes' => $info->getProcessList()];
});

$router->post('/api/server/kill/{id}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $processId = (int)$params['id'];
    $conn->query("KILL {$processId}");
    return ['success' => true];
});

// === User Routes ===
$router->get('/api/users', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    return ['users' => $userMgr->getUsers()];
});

$router->get('/api/users/{user}/{host}/privileges', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    return ['privileges' => $userMgr->getPrivileges($params['user'], $params['host'])];
});

$router->post('/api/users', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    $userMgr->createUser($input['user'], $input['host'] ?? '%', $input['password']);
    return ['success' => true];
});

$router->delete('/api/users/{user}/{host}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    $userMgr->dropUser($params['user'], $params['host']);
    return ['success' => true];
});

// === Routine Routes ===
$router->get('/api/routines/{db}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $conn = getConnection();
    $conn->select_db($db);

    $escapedDb = $conn->real_escape_string($db);

    $procedures = $conn->query("SHOW PROCEDURE STATUS WHERE Db = '{$escapedDb}'")->fetch_all(MYSQLI_ASSOC);
    $functions = $conn->query("SHOW FUNCTION STATUS WHERE Db = '{$escapedDb}'")->fetch_all(MYSQLI_ASSOC);
    $triggers = $conn->query("SELECT * FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = '{$escapedDb}'")->fetch_all(MYSQLI_ASSOC);
    $events = $conn->query("SELECT * FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA = '{$escapedDb}'")->fetch_all(MYSQLI_ASSOC);
    $views = $conn->query("SELECT TABLE_NAME, VIEW_DEFINITION, CHECK_OPTION, IS_UPDATABLE FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA = '{$escapedDb}'")->fetch_all(MYSQLI_ASSOC);

    return [
        'procedures' => $procedures,
        'functions' => $functions,
        'triggers' => $triggers,
        'events' => $events,
        'views' => $views,
    ];
});

// === Schema Compare Routes ===
$router->post('/api/schema/compare', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    $source = Security::sanitizeIdentifier($input['source']);
    $target = Security::sanitizeIdentifier($input['target']);
    $conn = getConnection();
    $compare = new SchemaCompare($conn);
    return $compare->compare($source, $target);
});

// === Dispatch ===
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Remove script path prefix for subdirectory installations
$scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
$basePath = dirname($scriptName);
if ($basePath !== '/' && $basePath !== '\\') {
    if (str_starts_with($uri, $basePath)) {
        $uri = substr($uri, strlen($basePath));
    }
}
// Also strip the script filename itself (e.g., /databrowse.php)
$scriptBasename = basename($scriptName);
if (str_starts_with($uri, '/' . $scriptBasename)) {
    $uri = substr($uri, strlen('/' . $scriptBasename));
}
if ($uri === '' || $uri === false) {
    $uri = '/';
}

// API routes
if (str_starts_with($uri, '/api/')) {
    header('Content-Type: application/json; charset=utf-8');
    $result = $router->dispatch($method, $uri);
    if ($result !== null) {
        echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
    exit;
}

// Frontend SPA — serve embedded HTML
header('Content-Type: text/html; charset=utf-8');
$html = str_replace('{{CSP_NONCE}}', $nonce, FRONTEND_HTML);
$html = str_replace('{{VERSION}}', DATABROWSE_VERSION, $html);
echo $html;

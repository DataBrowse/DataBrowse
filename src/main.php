<?php
declare(strict_types=1);
// === Main Dispatch Point ===

$router = new Router();
if (!isset($config)) $config = loadConfig();
$nonce = $cspNonce ?? '';
$ipWhitelist = is_array($config['security']['ip_whitelist'] ?? null)
    ? $config['security']['ip_whitelist']
    : [];

// Security headers
if ($config['security']['csp_enabled']) {
    Security::setSecurityHeaders($nonce);
}

// IP whitelist check
$trustedProxies = is_array($config['security']['trusted_proxies'] ?? null)
    ? $config['security']['trusted_proxies']
    : [];
if (!Security::checkIPWhitelist($ipWhitelist, $trustedProxies)) {
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
$router->post('/api/auth/login', function (array $_params) use ($config): array {
    $input = getJsonInput();
    $trustedProxies = is_array($config['security']['trusted_proxies'] ?? null)
        ? $config['security']['trusted_proxies']
        : [];
    $allowedHosts = is_array($config['security']['allowed_db_hosts'] ?? null)
        ? $config['security']['allowed_db_hosts']
        : ['127.0.0.1', 'localhost'];
    if ($allowedHosts === []) {
        $allowedHosts = ['127.0.0.1', 'localhost'];
    }
    $host = (string)($input['host'] ?? '127.0.0.1');
    $port = (int)($input['port'] ?? 3306);

    // Rate limit check
    $ip = Security::getClientIP($trustedProxies);
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

    // Prevent arbitrary outbound DB probing
    if (!in_array($host, $allowedHosts, true)) {
        http_response_code(403);
        return ['error' => 'Target host is not allowed'];
    }

    if ($port < 1 || $port > 65535) {
        http_response_code(400);
        return ['error' => 'Invalid port'];
    }

    try {
        $conn = ConnectionManager::connect(
            host: $host,
            username: $input['username'] ?? '',
            password: $input['password'] ?? '',
            port: $port,
            socket: $input['socket'] ?? null,
        );

        // Save session (password encrypted at rest)
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        $_SESSION['host'] = $host;
        $_SESSION['username'] = $input['username'] ?? '';
        $_SESSION['port'] = $port;
        $_SESSION['socket'] = $input['socket'] ?? null;
        // Encrypt password so it's not plaintext in session files
        $sessKey = getSessionEncryptionKey();
        $iv = random_bytes(12);
        $encrypted = openssl_encrypt($input['password'] ?? '', 'aes-256-gcm', $sessKey, 0, $iv, $tag);
        if (!is_string($encrypted)) {
            throw new \RuntimeException('Failed to protect session credentials');
        }
        $_SESSION['password'] = base64_encode($iv . $tag . $encrypted);
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
        return ['error' => 'Authentication failed. Please check your credentials and try again.'];
    }
});

$router->post('/api/auth/logout', function (): array {
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION = [];
        session_destroy();
    }
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
        if (session_status() === PHP_SESSION_ACTIVE) { session_destroy(); }
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
    if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'], true) && $config['security']['csrf_enabled']) {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!Security::validateCSRFToken($token)) {
            http_response_code(403);
            return ['error' => 'Invalid CSRF token'];
        }
    }

    // Read-only mode: block write operations
    if ($config['security']['read_only_mode'] && in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
        // Use parsed path only (no query string) to prevent bypass
        $checkUri = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        $writeExempt = ['/api/auth/', '/api/export/'];
        $isExempt = false;
        foreach ($writeExempt as $prefix) {
            if (str_starts_with($checkUri, $prefix)) { $isExempt = true; break; }
        }
        if (!$isExempt) {
            http_response_code(403);
            return ['error' => 'Server is in read-only mode. Write operations are disabled.'];
        }
    }

    return null; // Auth passed
};

// Helper: parse JSON request body — exits with 400 on invalid input
function getJsonInput(): array {
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Request body is empty']);
        exit;
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid JSON in request body']);
        exit;
    }
    return $data;
}

// Helper: require fields from input, return 400 if missing
function requireFields(array $input, array $fields): ?array {
    $missing = [];
    foreach ($fields as $f) {
        if (!isset($input[$f])) $missing[] = $f;
    }
    if (!empty($missing)) {
        http_response_code(400);
        return ['error' => 'Missing required fields: ' . implode(', ', $missing)];
    }
    return null;
}

function getUploadErrorMessage(int $errorCode): string {
    return match ($errorCode) {
        UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Uploaded file exceeds size limits',
        UPLOAD_ERR_PARTIAL => 'Uploaded file was only partially received',
        UPLOAD_ERR_NO_FILE => 'No file uploaded',
        UPLOAD_ERR_NO_TMP_DIR => 'Temporary upload directory is missing',
        UPLOAD_ERR_CANT_WRITE => 'Failed to write uploaded file',
        UPLOAD_ERR_EXTENSION => 'Upload blocked by a PHP extension',
        default => 'Unknown upload error',
    };
}

function validateUploadedFile(
    array $file,
    int $maxSize,
    array $allowedExtensions,
    array $allowedMimes
): ?array {
    $uploadError = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($uploadError !== UPLOAD_ERR_OK) {
        http_response_code(400);
        return ['error' => getUploadErrorMessage($uploadError)];
    }

    $tmpName = (string)($file['tmp_name'] ?? '');
    if ($tmpName === '' || !is_uploaded_file($tmpName)) {
        http_response_code(400);
        return ['error' => 'Invalid upload source'];
    }

    $size = (int)($file['size'] ?? 0);
    if ($size < 0 || $size > $maxSize) {
        http_response_code(413);
        return ['error' => 'File too large. Max: ' . Helpers::formatSize($maxSize)];
    }

    $name = (string)($file['name'] ?? '');
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if ($ext === '' || !in_array($ext, $allowedExtensions, true)) {
        http_response_code(400);
        return ['error' => 'Invalid file type'];
    }

    $mime = '';
    if (class_exists('finfo')) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($tmpName) ?: '';
    } elseif (function_exists('mime_content_type')) {
        $mime = mime_content_type($tmpName) ?: '';
    }

    if ($mime !== '' && !in_array($mime, $allowedMimes, true)) {
        http_response_code(400);
        return ['error' => 'Invalid file MIME type'];
    }

    return null;
}

function getSessionEncryptionKey(): string {
    $security = $GLOBALS['config']['security'] ?? [];
    $configuredSecret = $security['session_secret'] ?? '';
    if (is_string($configuredSecret) && $configuredSecret !== '') {
        return hash('sha256', $configuredSecret, true);
    }

    $encoded = $_SESSION['_enc_key'] ?? '';
    $decoded = is_string($encoded) ? base64_decode($encoded, true) : false;
    if (is_string($decoded) && strlen($decoded) === 32) {
        return $decoded;
    }

    $generated = random_bytes(32);
    $_SESSION['_enc_key'] = base64_encode($generated);
    return $generated;
}

// Helper: decrypt session password
function decryptSessionPassword(): string {
    $key = getSessionEncryptionKey();
    $blob = base64_decode((string)($_SESSION['password'] ?? ''), true);
    if (!is_string($blob)) return '';
    if (strlen($blob) < 28 || strlen($key) < 32) return '';
    $iv = substr($blob, 0, 12);
    $tag = substr($blob, 12, 16);
    $encrypted = substr($blob, 28);
    $decrypted = openssl_decrypt($encrypted, 'aes-256-gcm', $key, 0, $iv, $tag);
    return $decrypted !== false ? $decrypted : '';
}

// Helper: get authenticated connection
function getConnection(): mysqli {
    return ConnectionManager::connect(
        host: $_SESSION['host'],
        username: $_SESSION['username'],
        password: decryptSessionPassword(),
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

    if (!isset($input['columns']) || !is_array($input['columns']) || $input['columns'] === []) {
        http_response_code(400);
        return ['error' => 'At least one column definition is required'];
    }

    $columns = [];
    foreach ($input['columns'] as $col) {
        if (!is_array($col) || !isset($col['name'], $col['type'])) {
            http_response_code(400);
            return ['error' => 'Each column must include name and type'];
        }

        $colName = (string)$col['name'];
        $rawType = (string)$col['type'];
        $colType = strtoupper(trim($rawType));
        if (!in_array($colType, $allowedTypes, true)) {
            http_response_code(400);
            return ['error' => 'Invalid column type: ' . htmlspecialchars((string)$col['type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')];
        }
        try {
            $safeColName = Security::sanitizeIdentifier($colName);
        } catch (\InvalidArgumentException) {
            http_response_code(400);
            return ['error' => 'Invalid column name: ' . htmlspecialchars($colName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')];
        }

        $def = '`' . $safeColName . '` ' . strtoupper(trim($rawType));

        if (isset($col['length']) && $col['length'] !== '' && $col['length'] !== null) {
            if (!is_numeric($col['length']) || (int)$col['length'] < 1) {
                http_response_code(400);
                return ['error' => 'Invalid column length for ' . htmlspecialchars($colName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')];
            }
            $def .= '(' . (int)$col['length'] . ')';
        }
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
    if ($sort) { $sort = Security::sanitizeIdentifier($sort); }
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
    if ($err = requireFields($input, ['row'])) return $err;
    if (!is_array($input['row']) || empty($input['row'])) {
        http_response_code(400);
        return ['error' => 'Row data cannot be empty'];
    }
    $insertId = $dm->insertRow($db, $table, $input['row']);
    return ['success' => true, 'insert_id' => $insertId];
});

$router->put('/api/data/{db}/{table}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $input = getJsonInput();

    $conn = getConnection();
    $dm = new DataManager($conn);
    if ($err = requireFields($input, ['row', 'where'])) return $err;
    $affected = $dm->updateRow($db, $table, $input['row'], $input['where']);
    return ['success' => true, 'affected_rows' => $affected];
});

$router->delete('/api/data/{db}/{table}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $input = getJsonInput();

    $conn = getConnection();
    $dm = new DataManager($conn);
    if ($err = requireFields($input, ['where'])) return $err;
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
    if ($err = requireFields($input, ['rows'])) return $err;
    $affected = $dm->batchDelete($db, $table, $input['rows']);
    return ['success' => true, 'affected_rows' => $affected];
});

// === Query Routes ===
$router->post('/api/query/execute', function () use ($authMiddleware, $config): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    $sql = (string)($input['sql'] ?? '');
    $database = $input['database'] ?? null;
    $maxQueryLimit = max(1, (int)($config['security']['max_query_limit'] ?? 5000));
    $maxSqlLength = max(1, (int)($config['security']['max_sql_length'] ?? 200000));
    $maxHistorySqlLength = max(1, (int)($config['security']['max_history_sql_length'] ?? 4000));
    $requestedLimit = (int)($input['limit'] ?? 1000);
    $limit = max(1, min($maxQueryLimit, $requestedLimit));
    if (mb_strlen($sql, 'UTF-8') > $maxSqlLength) {
        http_response_code(413);
        return ['error' => 'SQL statement is too long'];
    }

    $conn = getConnection();
    if ($database) {
        $conn->select_db(Security::sanitizeIdentifier($database));
    }

    $executor = new QueryExecutor($conn);
    $result = $executor->execute($sql, $limit);

    // Save to session history
    if (!isset($_SESSION['query_history'])) {
        $_SESSION['query_history'] = [];
    }
    $historySql = mb_substr($sql, 0, $maxHistorySqlLength, 'UTF-8');
    array_unshift($_SESSION['query_history'], [
        'sql' => $historySql,
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
    $sql = (string)($input['sql'] ?? '');
    $security = $GLOBALS['config']['security'] ?? [];
    $maxSqlLength = max(1, (int)($security['max_sql_length'] ?? 200000));
    if (mb_strlen($sql, 'UTF-8') > $maxSqlLength) {
        http_response_code(413);
        return ['error' => 'SQL statement is too long'];
    }
    $database = $input['database'] ?? null;

    $conn = getConnection();
    if ($database) {
        $conn->select_db(Security::sanitizeIdentifier($database));
    }

    $executor = new QueryExecutor($conn);
    return $executor->explain($sql)->toArray();
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
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $validationError = validateUploadedFile(
        $file,
        $maxSize,
        ['sql'],
        ['text/plain', 'application/sql', 'application/x-sql', 'text/x-sql', 'application/octet-stream']
    );
    if ($validationError !== null) {
        return $validationError;
    }
    if ($ext !== 'sql' || !in_array($ext, $config['import']['allowed_extensions'], true)) {
        http_response_code(400);
        return ['error' => 'Invalid file type. Allowed: sql'];
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
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $validationError = validateUploadedFile(
        $file,
        $config['import']['max_file_size'],
        ['csv'],
        ['text/plain', 'text/csv', 'application/csv', 'application/vnd.ms-excel', 'application/octet-stream']
    );
    if ($validationError !== null) {
        return $validationError;
    }
    if ($ext !== 'csv' || !in_array($ext, $config['import']['allowed_extensions'], true)) {
        http_response_code(400);
        return ['error' => 'Invalid file type. Allowed: csv'];
    }

    $database = Security::sanitizeIdentifier($_POST['database'] ?? '');
    $table = Security::sanitizeIdentifier($_POST['table'] ?? '');

    $conn = getConnection();
    $importer = new CSVImporter($conn);
    $result = $importer->import(
        filePath: $file['tmp_name'],
        database: $database,
        table: $table,
        delimiter: substr($_POST['delimiter'] ?? ',', 0, 1) ?: ',',
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
    $processId = filter_var($params['id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if ($processId === false) {
        http_response_code(400);
        return ['error' => 'Invalid process id'];
    }
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
    if ($err = requireFields($input, ['user', 'password'])) return $err;
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

    $fetchForSchema = static function (mysqli $conn, string $sql, string $schema): array {
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('s', $schema);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    };

    $procedures = $fetchForSchema(
        $conn,
        "SELECT ROUTINE_NAME AS Name, ROUTINE_TYPE AS Type, DEFINER, CREATED, LAST_ALTERED, SECURITY_TYPE
         FROM INFORMATION_SCHEMA.ROUTINES
         WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'PROCEDURE'
         ORDER BY ROUTINE_NAME",
        $db
    );
    $functions = $fetchForSchema(
        $conn,
        "SELECT ROUTINE_NAME AS Name, ROUTINE_TYPE AS Type, DEFINER, CREATED, LAST_ALTERED, SECURITY_TYPE
         FROM INFORMATION_SCHEMA.ROUTINES
         WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'FUNCTION'
         ORDER BY ROUTINE_NAME",
        $db
    );
    $triggers = $fetchForSchema(
        $conn,
        "SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_TIMING, ACTION_STATEMENT, DEFINER
         FROM INFORMATION_SCHEMA.TRIGGERS
         WHERE TRIGGER_SCHEMA = ?
         ORDER BY TRIGGER_NAME",
        $db
    );
    $events = $fetchForSchema(
        $conn,
        "SELECT EVENT_NAME, STATUS, EVENT_TYPE, EXECUTE_AT, INTERVAL_VALUE, INTERVAL_FIELD, DEFINER
         FROM INFORMATION_SCHEMA.EVENTS
         WHERE EVENT_SCHEMA = ?
         ORDER BY EVENT_NAME",
        $db
    );
    $views = $fetchForSchema(
        $conn,
        "SELECT TABLE_NAME, VIEW_DEFINITION, CHECK_OPTION, IS_UPDATABLE
         FROM INFORMATION_SCHEMA.VIEWS
         WHERE TABLE_SCHEMA = ?
         ORDER BY TABLE_NAME",
        $db
    );

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

// Determine the base path by finding where the script sits
// Works with: Apache/Nginx rewrite, subdirectory installs, PHP built-in server
$scriptName = $_SERVER['SCRIPT_FILENAME'] ?? $_SERVER['SCRIPT_NAME'] ?? '';
$scriptBasename = basename($scriptName);

// If URI contains the script filename (e.g., /subdir/databrowse.php/api/...), strip it
if ($scriptBasename && str_contains($scriptBasename, '.php')) {
    $pos = strpos($uri, $scriptBasename);
    if ($pos !== false) {
        $uri = substr($uri, $pos + strlen($scriptBasename));
    }
}

// For subdirectory installs without script name in URL (rewrite rules)
// Strip the directory prefix if SCRIPT_NAME tells us the base
$sn = $_SERVER['SCRIPT_NAME'] ?? '';
if (str_contains($sn, '.php')) {
    $basePath = dirname($sn);
    if ($basePath !== '/' && $basePath !== '\\' && str_starts_with($uri, $basePath)) {
        $uri = substr($uri, strlen($basePath));
    }
}

if ($uri === '' || $uri === false) {
    $uri = '/';
}
// Ensure URI starts with /
if ($uri[0] !== '/') {
    $uri = '/' . $uri;
}

// API routes
if (str_starts_with($uri, '/api/')) {
    header('Content-Type: application/json; charset=utf-8');
    $result = $router->dispatch($method, $uri);
    if ($result !== null) {
        echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
    }
    exit;
}

// Frontend SPA — serve embedded HTML
header('Content-Type: text/html; charset=utf-8');
$html = str_replace('{{CSP_NONCE}}', $nonce, FRONTEND_HTML);
$html = str_replace('{{VERSION}}', DATABROWSE_VERSION, $html);
echo $html;

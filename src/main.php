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
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        echo json_encode(['error' => 'Access denied'], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    } else {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>403 Forbidden</h1><p>Your IP address is not allowed.</p></body></html>';
    }
    exit;
}
if (!headers_sent()) {
    header('X-Request-ID: ' . DATABROWSE_REQUEST_ID);
}

// === Auth Routes (CSRF exempt) ===
$router->post('/api/auth/login', function (array $_params) use ($config): array {
    if ($originErr = validateMutatingRequestOrigin()) {
        http_response_code(403);
        return $originErr;
    }

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
    $username = (string)($input['username'] ?? '');
    $password = (string)($input['password'] ?? '');
    $socket = isset($input['socket']) ? (string)$input['socket'] : null;

    if ($username === '' || strlen($username) > 128) {
        http_response_code(400);
        return ['error' => 'Invalid username'];
    }
    if (strlen($password) > 4096) {
        http_response_code(400);
        return ['error' => 'Password is too long'];
    }
    if ($socket !== null && strlen($socket) > 512) {
        http_response_code(400);
        return ['error' => 'Socket path is too long'];
    }

    // Rate limit check
    $ip = Security::getClientIP($trustedProxies);
    $loginKey = "login:{$ip}:" . hash('sha256', mb_strtolower($username, 'UTF-8'));
    if (!Security::checkRateLimit(
        $loginKey,
        $config['security']['max_login_attempts'],
        $config['security']['lockout_duration']
    )) {
        http_response_code(429);
        return ['error' => 'Too many login attempts. Try again later.'];
    }

    // Root login check
    if (!$config['security']['allow_root_login'] && $username === 'root') {
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
            username: $username,
            password: $password,
            port: $port,
            socket: $socket,
        );

        // Save session (password encrypted at rest)
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        $_SESSION['host'] = $host;
        $_SESSION['username'] = $username;
        $_SESSION['port'] = $port;
        $_SESSION['socket'] = $socket;
        // Encrypt password so it's not plaintext in session files
        $sessKey = getSessionEncryptionKey();
        $iv = random_bytes(12);
        $encrypted = openssl_encrypt($password, 'aes-256-gcm', $sessKey, 0, $iv, $tag);
        if (!is_string($encrypted)) {
            throw new \RuntimeException('Failed to protect session credentials');
        }
        $_SESSION['password'] = base64_encode($iv . $tag . $encrypted);
        $_SESSION['login_time'] = time();
        $_SESSION['csrf_token'] = Security::generateCSRFToken();

        $serverInfo = ConnectionManager::getServerInfo($conn);
        writeAuditLog('auth.login_success', [
            'host' => $host,
            'port' => $port,
            'username' => $username,
        ]);

        return [
            'success' => true,
            'server' => $serverInfo,
            'csrf_token' => $_SESSION['csrf_token'],
        ];
    } catch (\mysqli_sql_exception $e) {
        writeAuditLog('auth.login_failed', [
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'error_code' => $e->getCode(),
        ]);
        http_response_code(401);
        return ['error' => 'Authentication failed. Please check your credentials and try again.'];
    }
});

$router->post('/api/auth/logout', function () use ($config): array {
    if ($originErr = validateMutatingRequestOrigin()) {
        http_response_code(403);
        return $originErr;
    }
    if (
        !empty($_SESSION['authenticated'])
        && (bool)($config['security']['csrf_enabled'] ?? true)
        && !Security::validateCSRFToken((string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))
    ) {
        http_response_code(403);
        return ['error' => 'Invalid CSRF token'];
    }
    $logoutUser = (string)($_SESSION['username'] ?? '');
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION = [];
        session_destroy();
    }
    if (PHP_SAPI !== 'cli' && !headers_sent()) {
        setcookie('databrowse_csrf', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => false,
            'samesite' => 'Strict',
        ]);
    }
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    session_regenerate_id(true);
    writeAuditLog('auth.logout', ['username' => $logoutUser]);
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

        $hostHeader = (string)($_SERVER['HTTP_HOST'] ?? '');
        $origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
        $referer = (string)($_SERVER['HTTP_REFERER'] ?? '');
        if ($hostHeader !== '') {
            if ($origin !== '' && !isSameOriginUrl($origin, $hostHeader)) {
                http_response_code(403);
                return ['error' => 'Invalid request origin'];
            }
            if ($origin === '' && $referer !== '' && !isSameOriginUrl($referer, $hostHeader)) {
                http_response_code(403);
                return ['error' => 'Invalid request referer'];
            }
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

// Helper: parse JSON request body
function getJsonInput(): array {
    $contentType = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? ''));
    if ($contentType !== '' && !str_starts_with($contentType, 'application/json')) {
        throw new ApiException('Content-Type must be application/json', 415);
    }

    $security = $GLOBALS['config']['security'] ?? [];
    $maxBodyBytes = max(1024, (int)($security['max_request_body_bytes'] ?? 1048576));
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($contentLength > $maxBodyBytes) {
        throw new ApiException('Request body too large', 413);
    }

    $raw = file_get_contents('php://input');
    if ($raw !== false && strlen($raw) > $maxBodyBytes) {
        throw new ApiException('Request body too large', 413);
    }
    if ($raw === '' || $raw === false) {
        throw new ApiException('Request body is empty', 400);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        throw new ApiException('Invalid JSON in request body', 400);
    }
    return $data;
}

function isSameOriginUrl(string $url, string $hostHeader): bool {
    $urlHost = parse_url($url, PHP_URL_HOST);
    if (!is_string($urlHost) || $urlHost === '') {
        return false;
    }
    $urlPort = parse_url($url, PHP_URL_PORT);
    $host = strtolower($hostHeader);
    $hostOnly = strtolower((string)preg_replace('/:\d+$/', '', $host));
    if ($hostOnly !== strtolower($urlHost)) {
        return false;
    }

    $hostPort = null;
    if (preg_match('/:(\d+)$/', $host, $m) === 1) {
        $hostPort = (int)$m[1];
    }
    if ($urlPort !== null && $hostPort !== null && (int)$urlPort !== $hostPort) {
        return false;
    }

    return true;
}

function validateMutatingRequestOrigin(): ?array {
    $hostHeader = (string)($_SERVER['HTTP_HOST'] ?? '');
    if ($hostHeader === '') {
        return null;
    }

    $origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
    $referer = (string)($_SERVER['HTTP_REFERER'] ?? '');
    if ($origin !== '' && !isSameOriginUrl($origin, $hostHeader)) {
        return ['error' => 'Invalid request origin'];
    }
    if ($origin === '' && $referer !== '' && !isSameOriginUrl($referer, $hostHeader)) {
        return ['error' => 'Invalid request referer'];
    }

    return null;
}

function enforceApiRateLimit(array $config, string $method, string $uri): ?array {
    $security = $config['security'] ?? [];
    $trustedProxies = is_array($security['trusted_proxies'] ?? null)
        ? $security['trusted_proxies']
        : [];
    $ip = Security::getClientIP($trustedProxies);

    $max = max(10, (int)($security['api_rate_limit_max'] ?? 300));
    $window = max(1, (int)($security['api_rate_limit_window'] ?? 60));
    if (!Security::checkRateLimit("api:{$ip}", $max, $window)) {
        http_response_code(429);
        return ['error' => 'Too many API requests. Please slow down.'];
    }

    if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        $writeMax = max(1, (int)($security['api_write_rate_limit_max'] ?? 120));
        $writeWindow = max(1, (int)($security['api_write_rate_limit_window'] ?? 60));
        if (!Security::checkRateLimit("api-write:{$ip}", $writeMax, $writeWindow)) {
            http_response_code(429);
            return ['error' => 'Too many write requests. Please slow down.'];
        }
    }

    // Tighten polling-heavy endpoints less aggressively by including path key.
    if (str_starts_with($uri, '/api/import/progress/')) {
        if (!Security::checkRateLimit("api-progress:{$ip}", 600, 60)) {
            http_response_code(429);
            return ['error' => 'Too many progress polling requests.'];
        }
    }

    return null;
}

function normalizeSqlForSecurityCheck(string $sql): string {
    $sql = preg_replace('/\/\*.*?\*\//s', ' ', $sql) ?? $sql;
    $sql = preg_replace('/--[^\r\n]*/', ' ', $sql) ?? $sql;
    $sql = preg_replace('/#[^\r\n]*/', ' ', $sql) ?? $sql;
    $sql = strtoupper($sql);
    $sql = preg_replace('/\s+/', ' ', $sql) ?? $sql;
    return trim($sql);
}

function findBlockedSqlPattern(string $sql, array $blockedPatterns): ?string {
    $normalizedSql = normalizeSqlForSecurityCheck($sql);
    foreach ($blockedPatterns as $pattern) {
        if (!is_string($pattern) || $pattern === '') {
            continue;
        }
        $normalizedPattern = preg_replace('/\s+/', ' ', strtoupper(trim($pattern)));
        if (is_string($normalizedPattern) && $normalizedPattern !== '' && str_contains($normalizedSql, $normalizedPattern)) {
            return $pattern;
        }
    }
    return null;
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

// Helper: validate associative array keys as SQL identifiers
function validateIdentifierMap(array $map, string $fieldName, bool $allowEmpty = false): ?array {
    if (!$allowEmpty && $map === []) {
        http_response_code(400);
        return ['error' => "{$fieldName} cannot be empty"];
    }

    foreach ($map as $key => $_value) {
        if (!is_string($key) || $key === '') {
            http_response_code(400);
            return ['error' => "Invalid key in {$fieldName}"];
        }
        try {
            Security::sanitizeIdentifier($key);
        } catch (\InvalidArgumentException) {
            http_response_code(400);
            return ['error' => "Invalid key '{$key}' in {$fieldName}"];
        }
    }

    return null;
}

function validateAccountPart(string $value, string $field, int $maxLen): ?array {
    if ($value === '' || strlen($value) > $maxLen) {
        http_response_code(400);
        return ['error' => "{$field} must be 1-{$maxLen} characters"];
    }
    if (preg_match('/[[:cntrl:]]/', $value) === 1) {
        http_response_code(400);
        return ['error' => "Invalid {$field} characters"];
    }
    if (preg_match('/^[\p{L}\p{N}_.%:@$-]+$/u', $value) !== 1) {
        http_response_code(400);
        return ['error' => "Invalid {$field} format"];
    }
    return null;
}

function writeAuditLog(string $event, array $context = []): void {
    $security = $GLOBALS['config']['security'] ?? [];
    if (!(bool)($security['audit_log_enabled'] ?? true)) {
        return;
    }

    $trustedProxies = is_array($security['trusted_proxies'] ?? null)
        ? $security['trusted_proxies']
        : [];
    $ip = Security::getClientIP($trustedProxies);
    $username = (string)($_SESSION['username'] ?? '');
    $scriptDir = dirname((string)($_SERVER['SCRIPT_FILENAME'] ?? __FILE__));
    $defaultPath = rtrim($scriptDir, '/\\') . DIRECTORY_SEPARATOR . 'databrowse.audit.log';
    $configuredPath = (string)($security['audit_log_path'] ?? '');
    $path = $configuredPath !== '' ? $configuredPath : $defaultPath;

    // Prevent path traversal — audit log must stay within script directory or temp
    $realPath = realpath(dirname($path));
    $allowedDirs = [realpath($scriptDir), realpath(sys_get_temp_dir())];
    $allowedDirs = array_filter($allowedDirs, fn($d) => $d !== false);
    $pathAllowed = false;
    foreach ($allowedDirs as $allowed) {
        if ($realPath !== false && str_starts_with($realPath, $allowed)) {
            $pathAllowed = true;
            break;
        }
    }
    if (!$pathAllowed && $configuredPath !== '') {
        error_log('[DataBrowse] Audit log path rejected (outside allowed directories): ' . $configuredPath);
        $path = $defaultPath;
    }

    $record = [
        'ts' => gmdate('c'),
        'request_id' => defined('DATABROWSE_REQUEST_ID') ? DATABROWSE_REQUEST_ID : null,
        'event' => $event,
        'ip' => $ip,
        'session_user' => $username,
        'context' => $context,
    ];

    $json = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    if (!is_string($json)) {
        return;
    }
    $json .= PHP_EOL;

    try {
        file_put_contents($path, $json, FILE_APPEND | LOCK_EX);
    } catch (\Throwable) {
        // Ignore audit logging errors to avoid breaking API functionality.
    }
}

function generateOperationId(): string {
    try {
        return bin2hex(random_bytes(8));
    } catch (\Throwable) {
        return substr(sha1((string)microtime(true)), 0, 16);
    }
}

function parseIdempotencyKey(): array {
    $key = trim((string)($_SERVER['HTTP_X_IDEMPOTENCY_KEY'] ?? ''));
    if ($key === '') {
        return ['key' => null];
    }
    if (strlen($key) > 128 || preg_match('/^[A-Za-z0-9._:-]+$/', $key) !== 1) {
        http_response_code(400);
        return ['key' => null, 'error' => ['error' => 'Invalid idempotency key']];
    }
    return ['key' => $key];
}

function createDeterministicHash(mixed $value): string {
    $normalize = static function (mixed $input) use (&$normalize): mixed {
        if (is_array($input)) {
            $isList = array_keys($input) === range(0, count($input) - 1);
            if ($isList) {
                return array_map($normalize, $input);
            }
            $out = [];
            $keys = array_keys($input);
            sort($keys, SORT_STRING);
            foreach ($keys as $k) {
                $out[(string)$k] = $normalize($input[$k]);
            }
            return $out;
        }
        if (is_bool($input) || is_int($input) || is_float($input) || is_string($input) || $input === null) {
            return $input;
        }
        return (string)$input;
    };

    $normalized = $normalize($value);
    $json = json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    return hash('sha256', is_string($json) ? $json : serialize($normalized));
}

function getIdempotencyFilePath(string $scope, string $key): string {
    $user = (string)($_SESSION['username'] ?? '');
    $host = (string)($_SESSION['host'] ?? '');
    $identity = $scope . '|' . $user . '@' . $host . '|' . $key;
    $dir = sys_get_temp_dir() . '/databrowse_idempotency';
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new \RuntimeException('Unable to initialize idempotency storage');
    }
    return $dir . '/' . hash('sha256', $identity) . '.json';
}

function beginIdempotentJsonOperation(string $scope, ?string $key, string $bodyHash, int $ttlSeconds): array {
    if ($key === null) {
        return ['enabled' => false];
    }

    try {
        $path = getIdempotencyFilePath($scope, $key);
    } catch (\Throwable) {
        return ['enabled' => false];
    }
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        return ['enabled' => false];
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            return ['enabled' => false];
        }

        rewind($handle);
        $raw = stream_get_contents($handle);
        $record = [];
        if (is_string($raw) && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $record = $decoded;
            }
        }

        $now = time();
        $expiresAt = (int)($record['updated_at'] ?? 0) + max(30, $ttlSeconds);
        $isFresh = $record !== [] && $expiresAt >= $now;
        if ($isFresh) {
            $existingHash = (string)($record['body_hash'] ?? '');
            if ($existingHash !== $bodyHash) {
                return [
                    'enabled' => true,
                    'conflict' => true,
                    'status' => 409,
                    'response' => ['error' => 'Idempotency key already used with a different payload'],
                ];
            }

            $state = (string)($record['state'] ?? 'in_progress');
            if ($state === 'done') {
                $status = (int)($record['status'] ?? 200);
                $response = $record['response'] ?? null;
                if (is_array($response)) {
                    return [
                        'enabled' => true,
                        'replay' => true,
                        'status' => $status,
                        'response' => $response,
                    ];
                }
            }

            return [
                'enabled' => true,
                'conflict' => true,
                'status' => 409,
                'response' => ['error' => 'Operation with this idempotency key is already in progress'],
            ];
        }

        $next = [
            'scope' => $scope,
            'state' => 'in_progress',
            'body_hash' => $bodyHash,
            'created_at' => $record['created_at'] ?? $now,
            'updated_at' => $now,
        ];
        $json = json_encode($next, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($json)) {
            return ['enabled' => false];
        }
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, $json);
        fflush($handle);

        return [
            'enabled' => true,
            'path' => $path,
            'scope' => $scope,
            'key' => $key,
            'body_hash' => $bodyHash,
        ];
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function completeIdempotentJsonOperation(array $token, int $status, array $response): void {
    if (!(bool)($token['enabled'] ?? false)) {
        return;
    }
    $path = $token['path'] ?? null;
    $bodyHash = $token['body_hash'] ?? null;
    if (!is_string($path) || $path === '' || !is_string($bodyHash) || $bodyHash === '') {
        return;
    }

    $handle = fopen($path, 'c+');
    if ($handle === false) {
        return;
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            return;
        }
        rewind($handle);
        $raw = stream_get_contents($handle);
        $record = [];
        if (is_string($raw) && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $record = $decoded;
            }
        }
        if (($record['body_hash'] ?? '') !== $bodyHash) {
            return;
        }
        $record['state'] = 'done';
        $record['updated_at'] = time();
        $record['status'] = max(100, min(599, $status));
        $record['response'] = $response;
        $json = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($json)) {
            return;
        }
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, $json);
        fflush($handle);
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
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
    if ($name === '' || strlen($name) > 255 || str_contains($name, "\0") || str_contains($name, '/') || str_contains($name, '\\')) {
        http_response_code(400);
        return ['error' => 'Invalid file name'];
    }
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

    $sample = file_get_contents($tmpName, false, null, 0, 4096);
    if (is_string($sample) && str_contains($sample, "\0")) {
        http_response_code(400);
        return ['error' => 'Binary file content is not allowed'];
    }

    return null;
}

function getSessionEncryptionKey(): string {
    $security = $GLOBALS['config']['security'] ?? [];
    $configuredSecret = $security['session_secret'] ?? '';
    if (is_string($configuredSecret) && $configuredSecret !== '') {
        return hash('sha256', $configuredSecret, true);
    }

    // Derive key from server-level constants + session ID + install-time entropy.
    // A persistent random salt is generated once and stored alongside the script,
    // so the key cannot be reconstructed from publicly guessable values alone.
    $saltFile = sys_get_temp_dir() . '/databrowse_install_salt.bin';
    if (file_exists($saltFile)) {
        $salt = file_get_contents($saltFile);
    } else {
        $salt = random_bytes(32);
        file_put_contents($saltFile, $salt, LOCK_EX);
        if (function_exists('chmod')) {
            @chmod($saltFile, 0600);
        }
    }
    $material = $salt . '|' . __FILE__ . '|' . php_uname('n') . '|' . session_id();
    return hash('sha256', $material, true);
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
    writeAuditLog('db.create_database', ['database' => $name, 'charset' => $charset, 'collation' => $collation]);
    return ['success' => true, 'database' => $name];
});

$router->delete('/api/databases/{name}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $name = Security::sanitizeIdentifier($params['name']);
    $conn = getConnection();
    $conn->query("DROP DATABASE `{$name}`");
    writeAuditLog('db.drop_database', ['database' => $name]);
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
    writeAuditLog('db.create_table', ['database' => $db, 'table' => $tableName, 'engine' => $engine, 'charset' => $charset]);
    return ['success' => true, 'table' => $tableName, 'sql' => $sql];
});

$router->delete('/api/tables/{db}/{table}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $conn = getConnection();
    $conn->select_db($db);
    $conn->query("DROP TABLE `{$table}`");
    writeAuditLog('db.drop_table', ['database' => $db, 'table' => $table]);
    return ['success' => true];
});

$router->post('/api/tables/{db}/{table}/truncate', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $db = Security::sanitizeIdentifier($params['db']);
    $table = Security::sanitizeIdentifier($params['table']);
    $conn = getConnection();
    $conn->select_db($db);
    $conn->query("TRUNCATE TABLE `{$table}`");
    writeAuditLog('db.truncate_table', ['database' => $db, 'table' => $table]);
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
    $order = strtoupper($_GET['order'] ?? 'ASC') === 'DESC' ? 'DESC' : 'ASC';
    $search = $_GET['search'] ?? null;
    if ($search !== null && mb_strlen($search, 'UTF-8') > 200) {
        $search = mb_substr($search, 0, 200, 'UTF-8');
    }

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
    if ($err = validateIdentifierMap($input['row'], 'row')) return $err;
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
    if (!is_array($input['row']) || !is_array($input['where'])) {
        http_response_code(400);
        return ['error' => 'row and where must be objects'];
    }
    if ($err = validateIdentifierMap($input['row'], 'row')) return $err;
    if ($err = validateIdentifierMap($input['where'], 'where')) return $err;
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
    if (!is_array($input['where'])) {
        http_response_code(400);
        return ['error' => 'where must be an object'];
    }
    if ($err = validateIdentifierMap($input['where'], 'where')) return $err;
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
    if (!is_array($input['rows']) || $input['rows'] === []) {
        http_response_code(400);
        return ['error' => 'rows must be a non-empty array'];
    }
    foreach ($input['rows'] as $index => $where) {
        if (!is_array($where)) {
            http_response_code(400);
            return ['error' => "rows[{$index}] must be an object"];
        }
        if ($err = validateIdentifierMap($where, "rows[{$index}]")) return $err;
    }
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
    $maxStatements = max(1, (int)($config['security']['max_statements_per_query'] ?? 25));
    if (mb_strlen($sql, 'UTF-8') > $maxSqlLength) {
        http_response_code(413);
        return ['error' => 'SQL statement is too long'];
    }
    if (!$config['security']['allow_dangerous_sql']) {
        $blockedPatterns = is_array($config['security']['blocked_sql_patterns'] ?? null)
            ? $config['security']['blocked_sql_patterns']
            : [];
        $blocked = findBlockedSqlPattern($sql, $blockedPatterns);
        if ($blocked !== null) {
            http_response_code(403);
            return ['error' => 'Blocked SQL pattern detected: ' . $blocked];
        }
    }

    $conn = getConnection();
    if ($database) {
        $conn->select_db(Security::sanitizeIdentifier($database));
    }

    $executor = new QueryExecutor($conn);
    $queries = $executor->splitQueries($sql);

    // Read-only mode: block write queries at the SQL level (not just HTTP method)
    if ($config['security']['read_only_mode']) {
        $readOnlyAllowed = [QueryType::SELECT, QueryType::SHOW, QueryType::DESCRIBE, QueryType::EXPLAIN];
        foreach ($queries as $q) {
            $trimmed = trim($q);
            if ($trimmed === '') continue;
            $token = strtok($trimmed, " \t\n\r");
            $type = $token !== false ? (QueryType::tryFrom(strtoupper($token)) ?? QueryType::OTHER) : QueryType::OTHER;
            if (!in_array($type, $readOnlyAllowed, true)) {
                http_response_code(403);
                return ['error' => 'Write queries are disabled in read-only mode'];
            }
        }
    }
    $queryCount = count($queries);
    if ($queryCount > $maxStatements) {
        http_response_code(400);
        return ['error' => "Too many SQL statements. Max allowed: {$maxStatements}"];
    }

    $result = $executor->execute($sql, $limit);
    $sqlFingerprint = hash('sha256', normalizeSqlForSecurityCheck($sql));
    writeAuditLog('query.execute', [
        'database' => $database,
        'type' => $result->type->value,
        'success' => $result->success,
        'row_count' => $result->rowCount,
        'affected_rows' => $result->affectedRows,
        'elapsed_ms' => $result->elapsed,
        'statement_count' => $queryCount,
        'sql_fingerprint' => $sqlFingerprint,
    ]);

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
    if (!(bool)($security['allow_dangerous_sql'] ?? false)) {
        $blockedPatterns = is_array($security['blocked_sql_patterns'] ?? null)
            ? $security['blocked_sql_patterns']
            : [];
        $blocked = findBlockedSqlPattern($sql, $blockedPatterns);
        if ($blocked !== null) {
            http_response_code(403);
            return ['error' => 'Blocked SQL pattern detected: ' . $blocked];
        }
    }
    $database = $input['database'] ?? null;

    $conn = getConnection();
    if ($database) {
        $conn->select_db(Security::sanitizeIdentifier($database));
    }

    $executor = new QueryExecutor($conn);
    $result = $executor->explain($sql);
    writeAuditLog('query.explain', [
        'database' => $database,
        'success' => $result->success,
        'row_count' => $result->rowCount,
        'elapsed_ms' => $result->elapsed,
        'sql_fingerprint' => hash('sha256', normalizeSqlForSecurityCheck($sql)),
    ]);
    return $result->toArray();
});

$router->get('/api/query/history', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    return ['history' => $_SESSION['query_history'] ?? []];
});

// === Export Routes ===
$router->post('/api/export/sql', function () use ($authMiddleware): void {
    $operationId = generateOperationId();
    if (!headers_sent()) {
        header('X-Operation-ID: ' . $operationId);
    }
    if ($err = ($authMiddleware)()) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        $err['operation_id'] = $operationId;
        echo json_encode($err, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        return;
    }
    $input = getJsonInput();
    $db = Security::sanitizeIdentifier($input['database']);

    $conn = getConnection();
    $exporter = new SQLExporter($conn);

    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $db);
    header('Content-Type: application/sql');
    header("Content-Disposition: attachment; filename=\"{$safeName}_" . date('Y-m-d_His') . ".sql\"");
    writeAuditLog('export.sql', ['database' => $db, 'operation_id' => $operationId]);

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
    $operationId = generateOperationId();
    if (!headers_sent()) {
        header('X-Operation-ID: ' . $operationId);
    }
    if ($err = ($authMiddleware)()) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        $err['operation_id'] = $operationId;
        echo json_encode($err, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        return;
    }
    $input = getJsonInput();
    $db = Security::sanitizeIdentifier($input['database']);
    $table = Security::sanitizeIdentifier($input['table']);

    $conn = getConnection();
    $exporter = new CSVExporter($conn);

    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $table);
    header('Content-Type: text/csv; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"{$safeName}_" . date('Y-m-d_His') . ".csv\"");
    writeAuditLog('export.csv', ['database' => $db, 'table' => $table, 'operation_id' => $operationId]);

    foreach ($exporter->export($db, $table) as $chunk) {
        echo $chunk;
        flush();
    }
});

$router->post('/api/export/json', function () use ($authMiddleware): void {
    $operationId = generateOperationId();
    if (!headers_sent()) {
        header('X-Operation-ID: ' . $operationId);
    }
    if ($err = ($authMiddleware)()) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        $err['operation_id'] = $operationId;
        echo json_encode($err, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        return;
    }
    $input = getJsonInput();
    $db = Security::sanitizeIdentifier($input['database']);
    $table = Security::sanitizeIdentifier($input['table']);

    $conn = getConnection();
    $exporter = new JSONExporter($conn);

    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $table);
    header('Content-Type: application/json');
    header("Content-Disposition: attachment; filename=\"{$safeName}_" . date('Y-m-d_His') . ".json\"");
    writeAuditLog('export.json', ['database' => $db, 'table' => $table, 'operation_id' => $operationId]);

    foreach ($exporter->export($db, $table) as $chunk) {
        echo $chunk;
        flush();
    }
});

// === Import Routes ===
$router->post('/api/import/sql', function () use ($authMiddleware, $config): array {
    if ($err = ($authMiddleware)()) return $err;
    $operationId = generateOperationId();
    if (!headers_sent()) {
        header('X-Operation-ID: ' . $operationId);
    }

    if (!isset($_FILES['file'])) {
        http_response_code(400);
        return ['error' => 'No file uploaded', 'operation_id' => $operationId];
    }

    $file = $_FILES['file'];
    $maxSize = $config['import']['max_file_size'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $validationError = validateUploadedFile(
        $file,
        $maxSize,
        ['sql'],
        ['text/plain', 'application/sql', 'application/x-sql', 'text/x-sql']
    );
    if ($validationError !== null) {
        $validationError['operation_id'] = $operationId;
        return $validationError;
    }
    if ($ext !== 'sql' || !in_array($ext, $config['import']['allowed_extensions'], true)) {
        http_response_code(400);
        return ['error' => 'Invalid file type. Allowed: sql', 'operation_id' => $operationId];
    }

    $database = Security::sanitizeIdentifier($_POST['database'] ?? '');
    $stopOnError = (bool)($config['import']['stop_on_error'] ?? false);
    $idempotency = parseIdempotencyKey();
    if (isset($idempotency['error']) && is_array($idempotency['error'])) {
        $response = $idempotency['error'];
        $response['operation_id'] = $operationId;
        return $response;
    }
    $idempotencyKey = is_string($idempotency['key'] ?? null) ? $idempotency['key'] : null;
    $fileHash = hash_file('sha256', (string)$file['tmp_name']);
    if (!is_string($fileHash) || $fileHash === '') {
        $fileHash = hash('sha256', (string)($file['name'] ?? '') . '|' . (string)($file['size'] ?? 0));
    }
    $bodyHash = createDeterministicHash([
        'database' => $database,
        'file_name' => (string)($file['name'] ?? ''),
        'file_size' => (int)($file['size'] ?? 0),
        'file_hash' => $fileHash,
        'stop_on_error' => $stopOnError,
    ]);
    $idempotencyToken = beginIdempotentJsonOperation(
        'import.sql',
        $idempotencyKey,
        $bodyHash,
        (int)($config['security']['idempotency_ttl'] ?? 900)
    );
    if (($idempotencyToken['conflict'] ?? false) === true) {
        http_response_code((int)($idempotencyToken['status'] ?? 409));
        $response = is_array($idempotencyToken['response'] ?? null)
            ? $idempotencyToken['response']
            : ['error' => 'Idempotency conflict'];
        $response['operation_id'] = $operationId;
        return $response;
    }
    if (($idempotencyToken['replay'] ?? false) === true) {
        http_response_code((int)($idempotencyToken['status'] ?? 200));
        if (!headers_sent()) {
            header('X-Idempotent-Replay: 1');
        }
        $response = is_array($idempotencyToken['response'] ?? null)
            ? $idempotencyToken['response']
            : ['error' => 'Invalid idempotency replay payload'];
        if (!isset($response['operation_id'])) {
            $response['operation_id'] = $operationId;
        }
        return $response;
    }

    $progressId = bin2hex(random_bytes(8));

    try {
        $conn = getConnection();
        $importer = new SQLImporter($conn);
        $result = $importer->import($file['tmp_name'], $database, $progressId, $stopOnError);
        writeAuditLog('import.sql', [
            'database' => $database,
            'filename' => (string)($file['name'] ?? ''),
            'size' => (int)($file['size'] ?? 0),
            'executed' => $result->executedStatements,
            'failed' => $result->failedStatements,
            'operation_id' => $operationId,
        ]);

        $response = [
            'success' => true,
            'total_statements' => $result->totalStatements,
            'executed' => $result->executedStatements,
            'failed' => $result->failedStatements,
            'errors' => array_slice($result->errors, 0, 20),
            'progress_id' => $progressId,
            'operation_id' => $operationId,
        ];
        if ($idempotencyKey !== null) {
            $response['idempotency_key'] = $idempotencyKey;
        }
        completeIdempotentJsonOperation($idempotencyToken, http_response_code(), $response);
        return $response;
    } catch (\Throwable $e) {
        writeAuditLog('import.sql_failed', [
            'database' => $database,
            'filename' => (string)($file['name'] ?? ''),
            'operation_id' => $operationId,
            'error' => $e->getMessage(),
        ]);
        http_response_code(500);
        $response = ['error' => 'SQL import failed', 'operation_id' => $operationId];
        if ($idempotencyKey !== null) {
            $response['idempotency_key'] = $idempotencyKey;
        }
        completeIdempotentJsonOperation($idempotencyToken, 500, $response);
        return $response;
    }
});

$router->post('/api/import/csv', function () use ($authMiddleware, $config): array {
    if ($err = ($authMiddleware)()) return $err;
    $operationId = generateOperationId();
    if (!headers_sent()) {
        header('X-Operation-ID: ' . $operationId);
    }

    if (!isset($_FILES['file'])) {
        http_response_code(400);
        return ['error' => 'No file uploaded', 'operation_id' => $operationId];
    }

    $file = $_FILES['file'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $validationError = validateUploadedFile(
        $file,
        $config['import']['max_file_size'],
        ['csv'],
        ['text/plain', 'text/csv', 'application/csv', 'application/vnd.ms-excel']
    );
    if ($validationError !== null) {
        $validationError['operation_id'] = $operationId;
        return $validationError;
    }
    if ($ext !== 'csv' || !in_array($ext, $config['import']['allowed_extensions'], true)) {
        http_response_code(400);
        return ['error' => 'Invalid file type. Allowed: csv', 'operation_id' => $operationId];
    }

    $database = Security::sanitizeIdentifier($_POST['database'] ?? '');
    $table = Security::sanitizeIdentifier($_POST['table'] ?? '');
    $delimiter = substr($_POST['delimiter'] ?? ',', 0, 1) ?: ',';
    $hasHeader = ($_POST['has_header'] ?? '1') === '1';
    $idempotency = parseIdempotencyKey();
    if (isset($idempotency['error']) && is_array($idempotency['error'])) {
        $response = $idempotency['error'];
        $response['operation_id'] = $operationId;
        return $response;
    }
    $idempotencyKey = is_string($idempotency['key'] ?? null) ? $idempotency['key'] : null;
    $fileHash = hash_file('sha256', (string)$file['tmp_name']);
    if (!is_string($fileHash) || $fileHash === '') {
        $fileHash = hash('sha256', (string)($file['name'] ?? '') . '|' . (string)($file['size'] ?? 0));
    }
    $bodyHash = createDeterministicHash([
        'database' => $database,
        'table' => $table,
        'delimiter' => $delimiter,
        'has_header' => $hasHeader,
        'file_name' => (string)($file['name'] ?? ''),
        'file_size' => (int)($file['size'] ?? 0),
        'file_hash' => $fileHash,
    ]);
    $idempotencyToken = beginIdempotentJsonOperation(
        'import.csv',
        $idempotencyKey,
        $bodyHash,
        (int)($config['security']['idempotency_ttl'] ?? 900)
    );
    if (($idempotencyToken['conflict'] ?? false) === true) {
        http_response_code((int)($idempotencyToken['status'] ?? 409));
        $response = is_array($idempotencyToken['response'] ?? null)
            ? $idempotencyToken['response']
            : ['error' => 'Idempotency conflict'];
        $response['operation_id'] = $operationId;
        return $response;
    }
    if (($idempotencyToken['replay'] ?? false) === true) {
        http_response_code((int)($idempotencyToken['status'] ?? 200));
        if (!headers_sent()) {
            header('X-Idempotent-Replay: 1');
        }
        $response = is_array($idempotencyToken['response'] ?? null)
            ? $idempotencyToken['response']
            : ['error' => 'Invalid idempotency replay payload'];
        if (!isset($response['operation_id'])) {
            $response['operation_id'] = $operationId;
        }
        return $response;
    }

    try {
        $conn = getConnection();
        $importer = new CSVImporter($conn);
        $result = $importer->import(
            filePath: $file['tmp_name'],
            database: $database,
            table: $table,
            delimiter: $delimiter,
            hasHeader: $hasHeader,
        );
        writeAuditLog('import.csv', [
            'database' => $database,
            'table' => $table,
            'filename' => (string)($file['name'] ?? ''),
            'size' => (int)($file['size'] ?? 0),
            'imported' => $result->executedStatements,
            'failed' => $result->failedStatements,
            'operation_id' => $operationId,
        ]);

        $response = [
            'success' => true,
            'total_rows' => $result->totalStatements,
            'imported' => $result->executedStatements,
            'failed' => $result->failedStatements,
            'errors' => array_slice($result->errors, 0, 20),
            'operation_id' => $operationId,
        ];
        if ($idempotencyKey !== null) {
            $response['idempotency_key'] = $idempotencyKey;
        }
        completeIdempotentJsonOperation($idempotencyToken, http_response_code(), $response);
        return $response;
    } catch (\Throwable $e) {
        writeAuditLog('import.csv_failed', [
            'database' => $database,
            'table' => $table,
            'filename' => (string)($file['name'] ?? ''),
            'operation_id' => $operationId,
            'error' => $e->getMessage(),
        ]);
        http_response_code(500);
        $response = ['error' => 'CSV import failed', 'operation_id' => $operationId];
        if ($idempotencyKey !== null) {
            $response['idempotency_key'] = $idempotencyKey;
        }
        completeIdempotentJsonOperation($idempotencyToken, 500, $response);
        return $response;
    }
});

$router->get('/api/import/progress/{id}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $id = $params['id'];
    if (!preg_match('/^[a-f0-9]{16}$/', $id)) {
        http_response_code(400);
        return ['error' => 'Invalid progress id'];
    }
    $progress = SQLImporter::readProgress($id);
    return $progress ?? ['error' => 'Progress not found'];
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
    writeAuditLog('server.kill_process', ['process_id' => $processId]);
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
    $user = $params['user'];
    $host = $params['host'];
    if ($err = validateAccountPart($user, 'user', 32)) return $err;
    if ($err = validateAccountPart($host, 'host', 255)) return $err;
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    return ['privileges' => $userMgr->getPrivileges($user, $host)];
});

$router->post('/api/users/{user}/{host}/grant', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    if ($err = requireFields($input, ['privilege'])) return $err;

    $user = $params['user'];
    $host = $params['host'];
    if ($err = validateAccountPart($user, 'user', 32)) return $err;
    if ($err = validateAccountPart($host, 'host', 255)) return $err;

    $privilege = strtoupper(trim((string)$input['privilege']));
    $database = (string)($input['database'] ?? '*');
    $table = (string)($input['table'] ?? '*');
    $database = $database === '*' ? '*' : Security::sanitizeIdentifier($database);
    $table = $table === '*' ? '*' : Security::sanitizeIdentifier($table);

    $conn = getConnection();
    $userMgr = new UserManager($conn);
    try {
        $userMgr->grantPrivilege($user, $host, $privilege, $database, $table);
    } catch (\InvalidArgumentException $e) {
        http_response_code(400);
        return ['error' => $e->getMessage()];
    }
    writeAuditLog('user.grant_privilege', [
        'user' => $user,
        'host' => $host,
        'privilege' => $privilege,
        'database' => $database,
        'table' => $table,
    ]);
    return ['success' => true];
});

$router->post('/api/users/{user}/{host}/revoke', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    if ($err = requireFields($input, ['privilege'])) return $err;

    $user = $params['user'];
    $host = $params['host'];
    if ($err = validateAccountPart($user, 'user', 32)) return $err;
    if ($err = validateAccountPart($host, 'host', 255)) return $err;

    $privilege = strtoupper(trim((string)$input['privilege']));
    $database = (string)($input['database'] ?? '*');
    $table = (string)($input['table'] ?? '*');
    $database = $database === '*' ? '*' : Security::sanitizeIdentifier($database);
    $table = $table === '*' ? '*' : Security::sanitizeIdentifier($table);

    $conn = getConnection();
    $userMgr = new UserManager($conn);
    try {
        $userMgr->revokePrivilege($user, $host, $privilege, $database, $table);
    } catch (\InvalidArgumentException $e) {
        http_response_code(400);
        return ['error' => $e->getMessage()];
    }
    writeAuditLog('user.revoke_privilege', [
        'user' => $user,
        'host' => $host,
        'privilege' => $privilege,
        'database' => $database,
        'table' => $table,
    ]);
    return ['success' => true];
});

$router->post('/api/users', function () use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $input = getJsonInput();
    if ($err = requireFields($input, ['user', 'password'])) return $err;
    $user = (string)$input['user'];
    $host = (string)($input['host'] ?? '%');
    if ($err = validateAccountPart($user, 'user', 32)) return $err;
    if ($err = validateAccountPart($host, 'host', 255)) return $err;
    if (!is_string($input['password']) || $input['password'] === '' || strlen($input['password']) > 4096) {
        http_response_code(400);
        return ['error' => 'Password must be 1-4096 characters'];
    }
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    $userMgr->createUser($user, $host, $input['password']);
    writeAuditLog('user.create', ['user' => $user, 'host' => $host]);
    return ['success' => true];
});

$router->delete('/api/users/{user}/{host}', function (array $params) use ($authMiddleware): array {
    if ($err = ($authMiddleware)()) return $err;
    $user = $params['user'];
    $host = $params['host'];
    if ($err = validateAccountPart($user, 'user', 32)) return $err;
    if ($err = validateAccountPart($host, 'host', 255)) return $err;
    $conn = getConnection();
    $userMgr = new UserManager($conn);
    $userMgr->dropUser($user, $host);
    writeAuditLog('user.drop', ['user' => $user, 'host' => $host]);
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
    if ($rateError = enforceApiRateLimit($config, $method, $uri)) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        $encodedRate = json_encode($rateError, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        echo $encodedRate !== false ? $encodedRate : '{"error":"Too many requests"}';
        exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    $result = $router->dispatch($method, $uri);
    if ($result !== null) {
        $encoded = json_encode($result, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($encoded === false) {
            http_response_code(500);
            echo '{"error":"Failed to encode response"}';
            exit;
        }
        echo $encoded;
    }
    exit;
}

// Frontend SPA — serve embedded HTML
header('Content-Type: text/html; charset=utf-8');
$html = str_replace('{{CSP_NONCE}}', $nonce, FRONTEND_HTML);
$html = str_replace('{{VERSION}}', DATABROWSE_VERSION, $html);
echo $html;

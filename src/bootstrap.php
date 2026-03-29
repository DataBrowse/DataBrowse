<?php
declare(strict_types=1);

// === Version & Constants ===
define('DATABROWSE_VERSION', '0.0.2');
define('DATABROWSE_MIN_PHP', '8.2.0');
if (!defined('DATABROWSE_DEBUG')) {
    $debugEnv = getenv('DATABROWSE_DEBUG');
    $debug = is_string($debugEnv) && filter_var($debugEnv, FILTER_VALIDATE_BOOLEAN);
    define('DATABROWSE_DEBUG', $debug);
}
if (!defined('DATABROWSE_REQUEST_ID')) {
    try {
        define('DATABROWSE_REQUEST_ID', bin2hex(random_bytes(8)));
    } catch (\Throwable) {
        define('DATABROWSE_REQUEST_ID', substr(sha1((string)microtime(true)), 0, 16));
    }
}

// Production-safe defaults
error_reporting(E_ALL);
ini_set('display_errors', DATABROWSE_DEBUG ? '1' : '0');
ini_set('display_startup_errors', DATABROWSE_DEBUG ? '1' : '0');
ini_set('log_errors', '1');
ini_set('html_errors', '0');

// PHP version check
if (version_compare(PHP_VERSION, DATABROWSE_MIN_PHP, '<')) {
    die('DataBrowse requires PHP ' . DATABROWSE_MIN_PHP . '+. Current: ' . PHP_VERSION);
}

// Required extensions check
$required = ['mysqli', 'json', 'mbstring', 'session', 'openssl'];
$missing = array_filter($required, fn(string $ext) => !extension_loaded($ext));
if (!empty($missing)) {
    die('Missing PHP extensions: ' . implode(', ', $missing));
}

// Error handling — production mode
set_error_handler(function (int $errno, string $errstr, string $file, int $line): bool {
    if (!(error_reporting() & $errno)) return false;
    throw new ErrorException($errstr, 0, $errno, $file, $line);
});

// Typed API exception — carries an HTTP status code and a user-safe message.
class ApiException extends \RuntimeException {
    public function __construct(string $message, int $httpStatus = 400, ?\Throwable $previous = null) {
        parent::__construct($message, $httpStatus, $previous);
    }
    public function getHttpStatus(): int {
        return $this->code;
    }
}

set_exception_handler(function (\Throwable $e): void {
    $requestId = DATABROWSE_REQUEST_ID;

    // ApiException: expected error, don't log as unexpected
    if ($e instanceof ApiException) {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (str_contains($uri, '/api/') || str_contains(strtolower($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json')) {
            http_response_code($e->getHttpStatus());
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'error' => $e->getMessage(),
                'request_id' => $requestId,
            ], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        } else {
            http_response_code($e->getHttpStatus());
            header('Content-Type: text/plain; charset=utf-8');
            echo $e->getMessage();
        }
        exit(1);
    }

    error_log(sprintf(
        '[DataBrowse][%s] %s in %s:%d | %s',
        $requestId,
        $e::class,
        $e->getFile(),
        $e->getLine(),
        $e->getMessage()
    ));

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $isApi = str_contains($uri, '/api/');
    if ($isApi) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'error' => true,
            'message' => 'Internal server error',
            'request_id' => $requestId,
            'detail' => defined('DATABROWSE_DEBUG') && DATABROWSE_DEBUG
                ? $e->getMessage() : null,
        ], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    } else {
        http_response_code(500);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>DataBrowse Error</title></head><body>';
        echo '<h1>DataBrowse Error</h1><p>An unexpected error occurred.</p>';
        echo '<p>Request ID: ' . htmlspecialchars($requestId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
        if (defined('DATABROWSE_DEBUG') && DATABROWSE_DEBUG) {
            echo '<pre>' . htmlspecialchars($e->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</pre>';
        }
        echo '</body></html>';
    }
    exit(1);
});

// Session configuration (skip in CLI mode for testing)
if (PHP_SAPI !== 'cli') {
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        ini_set('session.cookie_secure', '1');
    }
    session_name('databrowse_sid');
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// Config loader
function loadConfig(): array {
    $configFile = __DIR__ . '/databrowse.config.json';
    // Single file mode: config in same directory as script
    if (!file_exists($configFile) && isset($_SERVER['SCRIPT_FILENAME'])) {
        $configFile = dirname($_SERVER['SCRIPT_FILENAME']) . '/databrowse.config.json';
    }
    if (!file_exists($configFile)) {
        return getDefaultConfig();
    }

    // Warn if config file is world-readable (may contain session_secret)
    if (PHP_OS_FAMILY !== 'Windows') {
        $perms = @fileperms($configFile);
        if ($perms !== false && ($perms & 0004)) {
            error_log('[DataBrowse] WARNING: Config file is world-readable. Run: chmod 600 ' . $configFile);
        }
    }

    $json = file_get_contents($configFile);
    if ($json === false) {
        error_log('[DataBrowse] Failed to read config file, using defaults');
        return getDefaultConfig();
    }

    try {
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
        error_log('[DataBrowse] Invalid config JSON, using defaults: ' . $e->getMessage());
        return getDefaultConfig();
    }

    if (!is_array($decoded)) {
        error_log('[DataBrowse] Config root must be a JSON object, using defaults');
        return getDefaultConfig();
    }

    return validateConfig(array_replace_recursive(getDefaultConfig(), $decoded));
}

function clampInt(mixed $value, int $min, int $max, int $fallback): int {
    if (!is_int($value) && !is_string($value) && !is_float($value)) {
        return $fallback;
    }
    $int = (int)$value;
    if ($int < $min) return $min;
    if ($int > $max) return $max;
    return $int;
}

function normalizeStringList(mixed $value, int $maxLen = 255): array {
    if (!is_array($value)) return [];
    $out = [];
    foreach ($value as $item) {
        if (!is_string($item)) continue;
        $trimmed = trim($item);
        if ($trimmed === '' || strlen($trimmed) > $maxLen) continue;
        $out[] = $trimmed;
    }
    return array_values(array_unique($out));
}

function validateConfig(array $config): array {
    $config['security']['max_login_attempts'] = clampInt(
        $config['security']['max_login_attempts'] ?? null,
        1,
        50,
        5
    );
    $config['security']['lockout_duration'] = clampInt(
        $config['security']['lockout_duration'] ?? null,
        30,
        86400,
        900
    );
    $config['security']['session_timeout'] = clampInt(
        $config['security']['session_timeout'] ?? null,
        60,
        86400,
        1800
    );
    $config['security']['max_query_limit'] = clampInt(
        $config['security']['max_query_limit'] ?? null,
        1,
        100000,
        5000
    );
    $config['security']['max_sql_length'] = clampInt(
        $config['security']['max_sql_length'] ?? null,
        1000,
        2000000,
        200000
    );
    $config['security']['max_history_sql_length'] = clampInt(
        $config['security']['max_history_sql_length'] ?? null,
        100,
        20000,
        4000
    );
    $config['security']['max_statements_per_query'] = clampInt(
        $config['security']['max_statements_per_query'] ?? null,
        1,
        200,
        25
    );
    $config['security']['max_request_body_bytes'] = clampInt(
        $config['security']['max_request_body_bytes'] ?? null,
        1024,
        10485760,
        1048576
    );
    $config['security']['api_rate_limit_max'] = clampInt(
        $config['security']['api_rate_limit_max'] ?? null,
        10,
        10000,
        300
    );
    $config['security']['api_rate_limit_window'] = clampInt(
        $config['security']['api_rate_limit_window'] ?? null,
        1,
        3600,
        60
    );
    $config['security']['api_write_rate_limit_max'] = clampInt(
        $config['security']['api_write_rate_limit_max'] ?? null,
        1,
        10000,
        120
    );
    $config['security']['api_write_rate_limit_window'] = clampInt(
        $config['security']['api_write_rate_limit_window'] ?? null,
        1,
        3600,
        60
    );
    $config['security']['idempotency_ttl'] = clampInt(
        $config['security']['idempotency_ttl'] ?? null,
        30,
        86400,
        900
    );
    $config['ui']['rows_per_page'] = clampInt(
        $config['ui']['rows_per_page'] ?? null,
        1,
        500,
        25
    );
    $config['ui']['max_text_preview'] = clampInt(
        $config['ui']['max_text_preview'] ?? null,
        20,
        2000,
        200
    );
    $config['export']['sql_chunk_size'] = clampInt(
        $config['export']['sql_chunk_size'] ?? null,
        1,
        10000,
        1000
    );
    $config['import']['max_file_size'] = clampInt(
        $config['import']['max_file_size'] ?? null,
        1024,
        536870912,
        52428800
    );

    $config['security']['force_https'] = (bool)($config['security']['force_https'] ?? false);
    $config['security']['allow_root_login'] = (bool)($config['security']['allow_root_login'] ?? false);
    $config['security']['read_only_mode'] = (bool)($config['security']['read_only_mode'] ?? false);
    $config['security']['csrf_enabled'] = (bool)($config['security']['csrf_enabled'] ?? true);
    $config['security']['csp_enabled'] = (bool)($config['security']['csp_enabled'] ?? true);
    $config['security']['allow_dangerous_sql'] = (bool)($config['security']['allow_dangerous_sql'] ?? false);
    $config['security']['audit_log_enabled'] = (bool)($config['security']['audit_log_enabled'] ?? true);
    $config['ui']['show_sql_editor'] = (bool)($config['ui']['show_sql_editor'] ?? true);
    $config['ui']['confirm_destructive'] = (bool)($config['ui']['confirm_destructive'] ?? true);
    $config['export']['include_drop_table'] = (bool)($config['export']['include_drop_table'] ?? true);
    $config['import']['stop_on_error'] = (bool)($config['import']['stop_on_error'] ?? false);

    $allowedHosts = normalizeStringList($config['security']['allowed_db_hosts'] ?? []);
    $config['security']['allowed_db_hosts'] = $allowedHosts !== [] ? $allowedHosts : ['127.0.0.1', 'localhost'];
    $config['security']['ip_whitelist'] = normalizeStringList($config['security']['ip_whitelist'] ?? []);
    $config['security']['trusted_proxies'] = normalizeStringList($config['security']['trusted_proxies'] ?? []);

    $allowedExt = ['sql', 'csv', 'json'];
    $extList = normalizeStringList($config['import']['allowed_extensions'] ?? [], 16);
    $extList = array_values(array_intersect(array_map('strtolower', $extList), $allowedExt));
    $config['import']['allowed_extensions'] = $extList !== [] ? $extList : $allowedExt;
    $blockedSqlPatterns = normalizeStringList($config['security']['blocked_sql_patterns'] ?? [], 64);
    $blockedSqlPatterns = array_values(array_map(static fn(string $p): string => strtoupper($p), $blockedSqlPatterns));
    $config['security']['blocked_sql_patterns'] = $blockedSqlPatterns !== []
        ? $blockedSqlPatterns
        : ['INTO OUTFILE', 'INTO DUMPFILE', 'LOAD DATA', 'LOAD_FILE('];

    $config['security']['session_secret'] = is_string($config['security']['session_secret'] ?? null)
        ? $config['security']['session_secret']
        : '';
    $config['security']['audit_log_path'] = is_string($config['security']['audit_log_path'] ?? null)
        ? trim($config['security']['audit_log_path'])
        : '';

    return $config;
}

function getDefaultConfig(): array {
    return [
        'servers' => [],
        'security' => [
            'ip_whitelist' => [],
            'trusted_proxies' => [],
            'allowed_db_hosts' => ['127.0.0.1', 'localhost'],
            'max_login_attempts' => 5,
            'lockout_duration' => 900,
            'session_timeout' => 1800,
            'session_secret' => '',
            'max_query_limit' => 5000,
            'max_sql_length' => 200000,
            'max_history_sql_length' => 4000,
            'max_statements_per_query' => 25,
            'max_request_body_bytes' => 1048576,
            'api_rate_limit_max' => 300,
            'api_rate_limit_window' => 60,
            'api_write_rate_limit_max' => 120,
            'api_write_rate_limit_window' => 60,
            'idempotency_ttl' => 900,
            'allow_dangerous_sql' => false,
            'blocked_sql_patterns' => ['INTO OUTFILE', 'INTO DUMPFILE', 'LOAD DATA', 'LOAD_FILE('],
            'audit_log_enabled' => true,
            'audit_log_path' => '',
            'force_https' => false,
            'allow_root_login' => false,
            'read_only_mode' => false,
            'csrf_enabled' => true,
            'csp_enabled' => true,
        ],
        'ui' => [
            'default_theme' => 'system',
            'default_language' => 'en',
            'rows_per_page' => 25,
            'max_text_preview' => 200,
            'show_sql_editor' => true,
            'confirm_destructive' => true,
        ],
        'export' => [
            'default_format' => 'sql',
            'sql_chunk_size' => 1000,
            'include_drop_table' => true,
        ],
        'import' => [
            'max_file_size' => 52428800,
            'allowed_extensions' => ['sql', 'csv', 'json'],
            'stop_on_error' => false,
        ],
    ];
}

if (!defined('DATABROWSE_TESTING')) {
    $config = loadConfig();

    // HTTPS force
    if ($config['security']['force_https'] && !empty($_SERVER['HTTP_HOST']) && empty($_SERVER['HTTPS'])) {
        $safeHost = preg_replace('/[^a-zA-Z0-9.\-:]/', '', $_SERVER['HTTP_HOST']);
        $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
        if (!is_string($requestUri) || $requestUri === '') {
            $requestUri = '/';
        }
        $requestUri = str_replace(["\r", "\n"], '', $requestUri);
        header('Location: https://' . $safeHost . $requestUri, true, 301);
        exit;
    }

    // CSP nonce generation
    $cspNonce = base64_encode(random_bytes(16));
}

<?php
declare(strict_types=1);

// === Version & Constants ===
define('DATABROWSE_VERSION', '0.0.2');
define('DATABROWSE_MIN_PHP', '8.2.0');

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

set_exception_handler(function (\Throwable $e): void {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $isApi = str_contains($uri, '/api/');
    if ($isApi) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => true,
            'message' => 'Internal server error',
            'detail' => defined('DATABROWSE_DEBUG') && DATABROWSE_DEBUG
                ? $e->getMessage() : null,
        ]);
    } else {
        http_response_code(500);
        echo '<!DOCTYPE html><html><head><title>DataBrowse Error</title></head><body>';
        echo '<h1>DataBrowse Error</h1><p>An unexpected error occurred.</p>';
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

    $json = file_get_contents($configFile);
    $config = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    return array_replace_recursive(getDefaultConfig(), $config);
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
            'force_https' => false,
            'allow_root_login' => true,
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

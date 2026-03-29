<?php
declare(strict_types=1);

// Tell bootstrap.php we're in test mode and skip runtime initialization.
define('DATABROWSE_TESTING', true);

// Initialize globals used by source code.
if (!isset($_SESSION)) $_SESSION = [];
if (!isset($_SERVER['REQUEST_URI'])) $_SERVER['REQUEST_URI'] = '/';
if (!isset($_SERVER['REMOTE_ADDR'])) $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

// Load source files.
require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/../src/Helpers.php';
require_once __DIR__ . '/../src/Security.php';
require_once __DIR__ . '/../src/Router.php';
require_once __DIR__ . '/../src/ConnectionManager.php';
require_once __DIR__ . '/../src/SchemaInspector.php';
require_once __DIR__ . '/../src/SQLTokenizer.php';
require_once __DIR__ . '/../src/QueryExecutor.php';
require_once __DIR__ . '/../src/DataManager.php';
require_once __DIR__ . '/../src/ExportEngine.php';
require_once __DIR__ . '/../src/ImportEngine.php';
require_once __DIR__ . '/../src/UserManager.php';
require_once __DIR__ . '/../src/ServerInfo.php';
require_once __DIR__ . '/../src/SchemaCompare.php';

// Initialize Config for tests.
Config::init(getDefaultConfig());

// Restore PHPUnit handlers (bootstrap.php overrides them).
restore_error_handler();
restore_exception_handler();

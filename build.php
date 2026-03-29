<?php
/**
 * DataBrowse Build Script
 *
 * Concatenates all src/ files into a single databrowse.php file.
 * Usage: php build.php
 */

$output = "<?php\n";
$output .= "declare(strict_types=1);\n";
$output .= "/**\n";
$output .= " * DataBrowse — Modern MySQL/MariaDB Management Platform\n";
$output .= " * Version: " . trim(file_get_contents(__DIR__ . '/VERSION')) . "\n";
$output .= " * https://databrowse.dev\n";
$output .= " * License: MIT\n";
$output .= " * Built: " . date('Y-m-d H:i:s') . "\n";
$output .= " */\n\n";

// PHP source files in dependency order
$sources = [
    'src/bootstrap.php',
    'src/Helpers.php',
    'src/Security.php',
    'src/Router.php',
    'src/ConnectionManager.php',
    'src/SchemaInspector.php',
    'src/QueryExecutor.php',
    'src/SQLTokenizer.php',
    'src/DataManager.php',
    'src/ExportEngine.php',
    'src/ImportEngine.php',
    'src/UserManager.php',
    'src/ServerInfo.php',
    'src/SchemaCompare.php',
];

foreach ($sources as $file) {
    $path = __DIR__ . '/' . $file;
    if (!file_exists($path)) {
        echo "ERROR: Missing source file: {$file}\n";
        exit(1);
    }
    $content = file_get_contents($path);
    // Strip PHP opening/closing tags
    $content = preg_replace('/^<\?php\s*/', '', $content);
    $content = preg_replace('/\?>\s*$/', '', $content);
    // Strip declare(strict_types=1) — only needed once at top
    $content = preg_replace('/declare\s*\(\s*strict_types\s*[:=]\s*1\s*\)\s*;\s*\n?/', '', $content);
    $output .= "// === " . basename($file) . " ===\n";
    $output .= trim($content) . "\n\n";
}

// Embed frontend HTML as heredoc
$frontendPath = __DIR__ . '/src/frontend.html';
if (!file_exists($frontendPath)) {
    echo "ERROR: Missing frontend file: src/frontend.html\n";
    exit(1);
}
$frontend = file_get_contents($frontendPath);
$output .= "// === Frontend SPA ===\n";
$output .= "define('FRONTEND_HTML', <<<'FRONTEND_EOF'\n";
$output .= $frontend . "\n";
$output .= "FRONTEND_EOF);\n\n";

// Append main routing/dispatch
$mainPath = __DIR__ . '/src/main.php';
if (!file_exists($mainPath)) {
    echo "ERROR: Missing main file: src/main.php\n";
    exit(1);
}
$mainContent = file_get_contents($mainPath);
$mainContent = preg_replace('/^<\?php\s*/', '', $mainContent);
$mainContent = preg_replace('/declare\s*\(\s*strict_types\s*[:=]\s*1\s*\)\s*;\s*\n?/', '', $mainContent);
$output .= "// === Main Dispatch ===\n";
$output .= trim($mainContent) . "\n";

// Write output
$outputPath = __DIR__ . '/databrowse.php';
file_put_contents($outputPath, $output);
$size = round(filesize($outputPath) / 1024);

echo "Built databrowse.php ({$size}KB)\n";

// Size validation
if ($size > 600) {
    echo "WARNING: Output exceeds 600KB target ({$size}KB)\n";
}

// Syntax check
$syntaxCheck = [];
exec('php -l ' . escapeshellarg($outputPath) . ' 2>&1', $syntaxCheck, $exitCode);
if ($exitCode !== 0) {
    echo "ERROR: Syntax check failed!\n";
    echo implode("\n", $syntaxCheck) . "\n";
    exit(1);
} else {
    echo "Syntax check: OK\n";
}

echo "Done.\n";

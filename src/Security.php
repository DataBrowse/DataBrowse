<?php
declare(strict_types=1);

final class Security {
    private const TOKEN_LENGTH = 64;

    // CSRF Token management
    public static function generateCSRFToken(): string {
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH / 2));
        $_SESSION['csrf_token'] = $token;
        $_SESSION['csrf_time'] = time();
        if (PHP_SAPI !== 'cli' && !headers_sent()) {
            setcookie('databrowse_csrf', $token, [
                'expires' => 0,
                'path' => '/',
                'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                'httponly' => false,
                'samesite' => 'Strict',
            ]);
        }
        return $token;
    }

    public static function validateCSRFToken(string $token): bool {
        if (!isset($_SESSION['csrf_token'], $_SESSION['csrf_time'])) {
            return false;
        }

        // Token valid for 1 hour
        if (time() - $_SESSION['csrf_time'] > 3600) {
            return false;
        }

        $cookieToken = $_COOKIE['databrowse_csrf'] ?? null;
        if (is_string($cookieToken) && $cookieToken !== '' && !hash_equals($cookieToken, $token)) {
            return false;
        }

        return hash_equals($_SESSION['csrf_token'], $token);
    }

    // Rate limiting — file-based, independent of session (cannot be bypassed by dropping cookies)
    public static function checkRateLimit(string $key, int $maxAttempts, int $window): bool {
        if ($maxAttempts < 1 || $window < 1) {
            throw new \InvalidArgumentException('Rate limit parameters must be greater than zero');
        }

        $dir = sys_get_temp_dir() . '/databrowse_ratelimit';
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            return false;
        }

        // Probabilistic cleanup of stale rate limit files (1% chance per call)
        if (random_int(1, 100) === 1) {
            self::cleanupRateLimitFiles($dir, $window);
        }

        $file = $dir . '/' . hash('sha256', $key) . '.json';
        $handle = fopen($file, 'c+');
        if ($handle === false) {
            return false;
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                return false;
            }

            rewind($handle);
            $raw = stream_get_contents($handle);
            $attempts = [];
            if (is_string($raw) && $raw !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    $attempts = $decoded;
                }
            }

            // Clean expired entries
            $now = time();
            $attempts = array_values(array_filter($attempts, fn(mixed $t): bool => is_int($t) && $now - $t < $window));

            if (count($attempts) >= $maxAttempts) {
                return false;
            }

            $attempts[] = $now;
            $json = json_encode($attempts, JSON_THROW_ON_ERROR);
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, $json);
            fflush($handle);

            return true;
        } catch (\JsonException) {
            return false;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function cleanupRateLimitFiles(string $dir, int $window): void {
        $files = glob($dir . '/*.json');
        if (!is_array($files)) return;
        $now = time();
        foreach ($files as $f) {
            $mtime = @filemtime($f);
            if ($mtime !== false && ($now - $mtime) > $window * 2) {
                @unlink($f);
            }
        }
    }

    // IP whitelist check with CIDR support
    public static function checkIPWhitelist(array $whitelist, array $trustedProxies = []): bool {
        if (empty($whitelist)) return true;

        $clientIP = self::getClientIP($trustedProxies);
        foreach ($whitelist as $allowed) {
            if (str_contains($allowed, '/')) {
                if (self::ipInCIDR($clientIP, $allowed)) return true;
            } else {
                if ($clientIP === $allowed) return true;
            }
        }
        return false;
    }

    // Content Security Policy and security headers
    public static function setSecurityHeaders(string $nonce): void {
        header("Content-Security-Policy: default-src 'self'; "
            . "script-src 'self' 'nonce-{$nonce}' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
            . "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            . "font-src 'self' https://cdn.jsdelivr.net; "
            . "connect-src 'self'; "
            . "img-src 'self' data:; "
            . "object-src 'none'; "
            . "frame-ancestors 'none'; "
            . "base-uri 'self'; "
            . "form-action 'self'");

        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
        header("Cross-Origin-Opener-Policy: same-origin");
        header("Cross-Origin-Resource-Policy: same-origin");
        header("X-Permitted-Cross-Domain-Policies: none");
        header("Origin-Agent-Cluster: ?1");
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
        }
    }

    // SQL identifier validation
    public static function sanitizeIdentifier(string $identifier): string {
        if ($identifier === '' || !preg_match('/^[a-zA-Z0-9_\-$]+$/', $identifier)) {
            throw new \InvalidArgumentException("Invalid SQL identifier: {$identifier}");
        }
        return $identifier;
    }

    // Get client IP — trust proxy headers only if REMOTE_ADDR is in trusted proxies.
    public static function getClientIP(array $trustedProxies = []): string {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $remoteAddr = filter_var($remoteAddr, FILTER_VALIDATE_IP) !== false ? $remoteAddr : '0.0.0.0';

        if (!self::isTrustedProxy($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($forwarded !== '') {
            $ips = array_map('trim', explode(',', $forwarded));
            foreach ($ips as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    return $ip;
                }
            }
        }

        $realIp = $_SERVER['HTTP_X_REAL_IP'] ?? '';
        if (filter_var($realIp, FILTER_VALIDATE_IP) !== false) {
            return $realIp;
        }

        return $remoteAddr;
    }

    // Check if IP is within CIDR range (supports IPv4 and IPv6)
    private static function ipInCIDR(string $ip, string $cidr): bool {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2) return false;
        [$subnet, $maskStr] = $parts;
        $mask = (int)$maskStr;

        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            if ($mask < 0 || $mask > 32) return false;
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            if ($ipLong === false || $subnetLong === false) return false;
            $maskLong = $mask === 0 ? 0 : ~((1 << (32 - $mask)) - 1);
            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        }

        // IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            if ($mask < 0 || $mask > 128) return false;
            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);
            if ($ipBin === false || $subnetBin === false) return false;

            // Build bitmask for IPv6 (128 bits = 16 bytes)
            $maskBin = str_repeat("\xff", intdiv($mask, 8));
            $remainder = $mask % 8;
            if ($remainder > 0) {
                $maskBin .= chr(0xff << (8 - $remainder) & 0xff);
            }
            $maskBin = str_pad($maskBin, 16, "\x00");

            return ($ipBin & $maskBin) === ($subnetBin & $maskBin);
        }

        return false;
    }

    private static function isTrustedProxy(string $remoteAddr, array $trustedProxies): bool {
        foreach ($trustedProxies as $proxy) {
            if (!is_string($proxy) || $proxy === '') {
                continue;
            }
            if (str_contains($proxy, '/')) {
                if (self::ipInCIDR($remoteAddr, $proxy)) {
                    return true;
                }
            } elseif ($remoteAddr === $proxy) {
                return true;
            }
        }

        return false;
    }

}

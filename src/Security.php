<?php
declare(strict_types=1);

final class Security {
    private const TOKEN_LENGTH = 64;

    // CSRF Token management
    public static function generateCSRFToken(): string {
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH / 2));
        $_SESSION['csrf_token'] = $token;
        $_SESSION['csrf_time'] = time();
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

        $file = $dir . '/' . md5($key) . '.json';
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
            . "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net https://unpkg.com https://cdn.tailwindcss.com; "
            . "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            . "font-src 'self' https://cdn.jsdelivr.net; "
            . "connect-src 'self'; "
            . "img-src 'self' data:; "
            . "frame-ancestors 'none'; "
            . "base-uri 'self'; "
            . "form-action 'self'");

        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
    }

    // SQL identifier validation
    public static function sanitizeIdentifier(string $identifier): string {
        if (!preg_match('/^[a-zA-Z0-9_\-$.]+$/', $identifier)) {
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

    // Check if IP is within CIDR range
    private static function ipInCIDR(string $ip, string $cidr): bool {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }

        $parts = explode('/', $cidr);
        if (count($parts) !== 2) return false;
        [$subnet, $mask] = $parts;
        if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }
        $mask = (int)$mask;
        if ($mask < 0 || $mask > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $maskLong = $mask === 0 ? 0 : ~((1 << (32 - $mask)) - 1);
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
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

    private static function isPrivateIP(string $ip): bool {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}

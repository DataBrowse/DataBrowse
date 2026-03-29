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

    // Rate limiting (session-based, sliding window)
    public static function checkRateLimit(string $key, int $maxAttempts, int $window): bool {
        $attempts = $_SESSION['rate_limits'][$key] ?? [];

        // Clean expired entries
        $attempts = array_filter(
            $attempts,
            fn(int $time) => time() - $time < $window
        );

        if (count($attempts) >= $maxAttempts) {
            return false;
        }

        $attempts[] = time();
        $_SESSION['rate_limits'][$key] = array_values($attempts);
        return true;
    }

    // IP whitelist check with CIDR support
    public static function checkIPWhitelist(array $whitelist): bool {
        if (empty($whitelist)) return true;

        $clientIP = self::getClientIP();
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

    // Get client IP — uses REMOTE_ADDR by default (safe).
    // X-Forwarded-For is only used when REMOTE_ADDR is a private/loopback IP (behind reverse proxy).
    public static function getClientIP(): string {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
        if ($forwarded && self::isPrivateIP($remoteAddr)) {
            $ips = array_map('trim', explode(',', $forwarded));
            $clientIP = filter_var($ips[0], FILTER_VALIDATE_IP);
            if ($clientIP !== false) return $clientIP;
        }
        return $_SERVER['HTTP_X_REAL_IP']
            ?? $_SERVER['REMOTE_ADDR']
            ?? '0.0.0.0';
    }

    // Check if IP is within CIDR range
    private static function ipInCIDR(string $ip, string $cidr): bool {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2) return false;
        [$subnet, $mask] = $parts;
        $mask = (int)$mask;
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        $maskLong = ~((1 << (32 - $mask)) - 1);
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }

    private static function isPrivateIP(string $ip): bool {
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}

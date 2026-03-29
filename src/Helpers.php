<?php
declare(strict_types=1);

final class Helpers {
    public static function formatSize(int $bytes): string {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $size = (float)$bytes;
        while ($size >= 1024 && $i < count($units) - 1) {
            $size /= 1024;
            $i++;
        }
        return round($size, 2) . ' ' . $units[$i];
    }

    public static function formatDuration(int $seconds): string {
        if ($seconds < 60) return "{$seconds}s";
        if ($seconds < 3600) return floor($seconds / 60) . 'm ' . ($seconds % 60) . 's';
        if ($seconds < 86400) return floor($seconds / 3600) . 'h ' . floor(($seconds % 3600) / 60) . 'm';
        return floor($seconds / 86400) . 'd ' . floor(($seconds % 86400) / 3600) . 'h';
    }

}

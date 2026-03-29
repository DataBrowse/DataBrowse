<?php
declare(strict_types=1);

final class SQLTokenizer {
    /**
     * Split SQL text into statements while preserving strings, backticks, and comments.
     *
     * @return array<int, string>
     */
    public static function splitStatements(string $sql): array {
        $queries = [];
        $current = '';
        $inString = false;
        $inBacktick = false;
        $stringChar = '';
        $escaped = false;

        for ($i = 0, $len = strlen($sql); $i < $len; $i++) {
            $char = $sql[$i];

            if ($escaped) {
                $current .= $char;
                $escaped = false;
                continue;
            }

            if ($char === '\\' && $inString) {
                $current .= $char;
                $escaped = true;
                continue;
            }

            if ($inBacktick) {
                $current .= $char;
                if ($char === '`') {
                    if ($i + 1 < $len && $sql[$i + 1] === '`') {
                        $current .= $sql[++$i];
                    } else {
                        $inBacktick = false;
                    }
                }
                continue;
            }

            if ($inString) {
                $current .= $char;
                if ($char === $stringChar) {
                    $inString = false;
                }
                continue;
            }

            if ($char === '-' && $i + 1 < $len && $sql[$i + 1] === '-') {
                $eol = strpos($sql, "\n", $i);
                if ($eol === false) {
                    $current .= substr($sql, $i);
                    break;
                }
                $current .= substr($sql, $i, $eol - $i + 1);
                $i = $eol;
                continue;
            }

            if ($char === '#') {
                $eol = strpos($sql, "\n", $i);
                if ($eol === false) {
                    $current .= substr($sql, $i);
                    break;
                }
                $current .= substr($sql, $i, $eol - $i + 1);
                $i = $eol;
                continue;
            }

            if ($char === '/' && $i + 1 < $len && $sql[$i + 1] === '*') {
                $end = strpos($sql, '*/', $i + 2);
                if ($end === false) {
                    $current .= substr($sql, $i);
                    break;
                }
                $current .= substr($sql, $i, $end - $i + 2);
                $i = $end + 1;
                continue;
            }

            if ($char === '`') {
                $inBacktick = true;
                $current .= $char;
                continue;
            }

            if ($char === '\'' || $char === '"') {
                $inString = true;
                $stringChar = $char;
                $current .= $char;
                continue;
            }

            if ($char === ';') {
                $trimmed = trim($current);
                if ($trimmed !== '') {
                    $queries[] = $trimmed;
                }
                $current = '';
                continue;
            }

            $current .= $char;
        }

        $trimmed = trim($current);
        if ($trimmed !== '') {
            $queries[] = $trimmed;
        }

        return $queries;
    }
}

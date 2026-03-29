<?php
declare(strict_types=1);

final class SchemaCompare {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    private const MAX_TABLES = 200;

    public function compare(string $sourceDb, string $targetDb): array {
        $inspector = new SchemaInspector($this->conn);
        $sourceTables = $inspector->getTables($sourceDb);
        $targetTables = $inspector->getTables($targetDb);

        if (count($sourceTables) > self::MAX_TABLES || count($targetTables) > self::MAX_TABLES) {
            throw new \RuntimeException(
                'Schema compare is limited to ' . self::MAX_TABLES . ' tables per database. '
                . "Source has " . count($sourceTables) . ", target has " . count($targetTables) . "."
            );
        }

        $sourceNames = array_column($sourceTables, 'name');
        $targetNames = array_column($targetTables, 'name');

        $diff = [
            'only_in_source' => array_values(array_diff($sourceNames, $targetNames)),
            'only_in_target' => array_values(array_diff($targetNames, $sourceNames)),
            'different' => [],
            'identical' => [],
            'alter_statements' => [],
        ];

        $common = array_intersect($sourceNames, $targetNames);
        foreach ($common as $table) {
            $sourceCreate = $inspector->getCreateStatement($sourceDb, $table);
            $targetCreate = $inspector->getCreateStatement($targetDb, $table);

            if ($sourceCreate === $targetCreate) {
                $diff['identical'][] = $table;
            } else {
                $sourceCols = $inspector->getColumns($sourceDb, $table);
                $targetCols = $inspector->getColumns($targetDb, $table);

                $sourceColMap = array_column($sourceCols, null, 'name');
                $targetColMap = array_column($targetCols, null, 'name');

                $changes = [];
                $alters = [];

                $escTable = str_replace('`', '``', $table);

                // Columns only in source (to add)
                foreach (array_diff_key($sourceColMap, $targetColMap) as $name => $col) {
                    $escName = str_replace('`', '``', $name);
                    $changes[] = ['type' => 'add_column', 'column' => $name, 'definition' => $col];
                    $alters[] = "ALTER TABLE `{$escTable}` ADD COLUMN `{$escName}` {$col['column_type']};";
                }

                // Columns only in target (to drop)
                foreach (array_diff_key($targetColMap, $sourceColMap) as $name => $col) {
                    $escName = str_replace('`', '``', $name);
                    $changes[] = ['type' => 'drop_column', 'column' => $name];
                    $alters[] = "ALTER TABLE `{$escTable}` DROP COLUMN `{$escName}`;";
                }

                // Modified columns
                foreach (array_intersect_key($sourceColMap, $targetColMap) as $name => $sourceCol) {
                    $targetCol = $targetColMap[$name];
                    if ($sourceCol['column_type'] !== $targetCol['column_type'] ||
                        $sourceCol['nullable'] !== $targetCol['nullable'] ||
                        $sourceCol['default_value'] !== $targetCol['default_value']) {
                        $escName = str_replace('`', '``', $name);
                        $changes[] = [
                            'type' => 'modify_column',
                            'column' => $name,
                            'source' => $sourceCol,
                            'target' => $targetCol,
                        ];
                        $nullable = $sourceCol['nullable'] === 'YES' ? '' : ' NOT NULL';
                        $defaultValue = $sourceCol['default_value'];
                        $expressionDefaults = ['CURRENT_TIMESTAMP', 'CURRENT_DATE', 'CURRENT_TIME', 'NULL', 'TRUE', 'FALSE'];
                        if ($defaultValue === null) {
                            $default = $sourceCol['nullable'] === 'YES' ? ' DEFAULT NULL' : '';
                        } elseif (in_array(strtoupper($defaultValue), $expressionDefaults, true)) {
                            $default = ' DEFAULT ' . strtoupper($defaultValue);
                        } elseif (is_numeric($defaultValue)) {
                            $default = ' DEFAULT ' . $defaultValue;
                        } else {
                            $default = " DEFAULT '" . $this->conn->real_escape_string($defaultValue) . "'";
                        }
                        $alters[] = "ALTER TABLE `{$escTable}` MODIFY COLUMN `{$escName}` {$sourceCol['column_type']}{$nullable}{$default};";
                    }
                }

                if (!empty($changes)) {
                    $diff['different'][] = ['table' => $table, 'changes' => $changes];
                    $diff['alter_statements'] = array_merge($diff['alter_statements'], $alters);
                }
            }
        }

        return $diff;
    }
}

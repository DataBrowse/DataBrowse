<?php
declare(strict_types=1);

final class SchemaCompare {
    public function __construct(
        private readonly mysqli $conn,
    ) {}

    public function compare(string $sourceDb, string $targetDb): array {
        $inspector = new SchemaInspector($this->conn);
        $sourceTables = $inspector->getTables($sourceDb);
        $targetTables = $inspector->getTables($targetDb);

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

                // Columns only in source (to add)
                foreach (array_diff_key($sourceColMap, $targetColMap) as $name => $col) {
                    $changes[] = ['type' => 'add_column', 'column' => $name, 'definition' => $col];
                    $alters[] = "ALTER TABLE `{$table}` ADD COLUMN `{$name}` {$col['column_type']};";
                }

                // Columns only in target (to drop)
                foreach (array_diff_key($targetColMap, $sourceColMap) as $name => $col) {
                    $changes[] = ['type' => 'drop_column', 'column' => $name];
                    $alters[] = "ALTER TABLE `{$table}` DROP COLUMN `{$name}`;";
                }

                // Modified columns
                foreach (array_intersect_key($sourceColMap, $targetColMap) as $name => $sourceCol) {
                    $targetCol = $targetColMap[$name];
                    if ($sourceCol['column_type'] !== $targetCol['column_type'] ||
                        $sourceCol['nullable'] !== $targetCol['nullable'] ||
                        $sourceCol['default_value'] !== $targetCol['default_value']) {
                        $changes[] = [
                            'type' => 'modify_column',
                            'column' => $name,
                            'source' => $sourceCol,
                            'target' => $targetCol,
                        ];
                        $nullable = $sourceCol['nullable'] === 'YES' ? '' : ' NOT NULL';
                        $default = $sourceCol['default_value'] !== null
                            ? " DEFAULT '" . $this->conn->real_escape_string($sourceCol['default_value']) . "'"
                            : '';
                        $alters[] = "ALTER TABLE `{$table}` MODIFY COLUMN `{$name}` {$sourceCol['column_type']}{$nullable}{$default};";
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

# Database Migration Guide

## Overview
This migration updates database column types for better performance and data integrity:

- `patch_id`: TEXT → BIGINT (patches, assets, vulnerabilities tables)
- `asset_id`: TEXT → BIGINT (assets table)  
- `data_lancamento`: TEXT → TIMESTAMP (patches, assets tables)

## Migration Process

### 1. Run the Migration Script
```bash
python migrate_database_columns.py
```

### 2. What the Migration Does
- **Automatically creates backup tables** (`patches_backup`, `assets_backup`, `vulnerabilities_backup`)
- **Validates existing data** before conversion
- **Safely migrates** numeric TEXT values to BIGINT
- **Converts date strings** to proper TIMESTAMP format
- **Preserves data integrity** with NULL for invalid values

### 3. Migration Safety Features
- **Backup Creation**: Original data is backed up before any changes
- **Data Validation**: Only valid numeric/date values are migrated
- **Rollback Capability**: Backup tables allow manual rollback if needed
- **Error Handling**: Failed conversions result in NULL rather than errors

### 4. After Migration
- **Test your application** thoroughly with the new data types
- **Verify data integrity** by comparing counts and spot-checking values
- **Remove backup tables** when confident: `DROP TABLE patches_backup, assets_backup, vulnerabilities_backup`

## Code Changes Made

### getOSpatchsPostgres.py Updates
1. **Table schemas** updated with correct data types
2. **Data processing functions** updated to handle:
   - Integer conversion for patch_id/asset_id
   - Datetime objects for data_lancamento
   - Proper NULL handling for invalid values
3. **Migration detection** automatically warns if old schema detected

### Migration Script Features
- **Interactive confirmation** before running
- **Progress logging** throughout the process  
- **Cleanup options** for old columns
- **Comprehensive error handling**

## Troubleshooting

### If Migration Fails
1. Check the log output for specific errors
2. Examine backup tables for data comparison
3. Manually inspect problematic records:
   ```sql
   SELECT * FROM patches WHERE patch_id !~ '^[0-9]+$';
   ```

### Data Validation Queries
```sql
-- Check migration success
SELECT COUNT(*) FROM patches WHERE patch_id IS NOT NULL;
SELECT COUNT(*) FROM assets WHERE asset_id IS NOT NULL;  
SELECT COUNT(*) FROM patches WHERE data_lancamento IS NOT NULL;

-- Compare with backups
SELECT COUNT(*) FROM patches_backup;
SELECT COUNT(*) FROM assets_backup;
```

### Manual Rollback (if needed)
```sql
-- Only if migration completely fails
DROP TABLE patches, assets, vulnerabilities;
ALTER TABLE patches_backup RENAME TO patches;
ALTER TABLE assets_backup RENAME TO assets;  
ALTER TABLE vulnerabilities_backup RENAME TO vulnerabilities;
```

## Performance Benefits
- **Faster joins** on integer keys vs text
- **Reduced storage** for numeric values
- **Proper date operations** with TIMESTAMP columns
- **Better indexing** performance on numeric columns
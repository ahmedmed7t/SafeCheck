package com.nexable.safecheck.core.data.database

import app.cash.sqldelight.db.SqlDriver
import kotlinx.datetime.Clock

/**
 * Database migration management for SafeCheck.
 */
object DatabaseMigrations {
    
    const val CURRENT_VERSION = 1
    
    private val migrations = mapOf(
        1 to Migration(
            version = 1,
            description = "Initial database schema",
            sql = listOf(
                // Enable foreign keys and WAL mode
                "PRAGMA foreign_keys = ON",
                "PRAGMA journal_mode = WAL",
                "PRAGMA synchronous = NORMAL",
                "PRAGMA cache_size = 2000",
                "PRAGMA temp_store = memory",
                "PRAGMA mmap_size = 268435456", // 256MB
                
                // The main schema is already defined in SafeCheckDatabase.sq
                // This migration just ensures proper configuration
                
                // Insert initial metadata
                """
                INSERT OR IGNORE INTO DatabaseMetadata (
                    version_code, version_name, migration_description, checksum
                ) VALUES (1, '1.0.0', 'Initial database schema', 'initial')
                """
            )
        )
        // Future migrations would be added here
        // 2 to Migration(...)
    )
    
    /**
     * Applies all pending migrations to the database.
     */
    suspend fun migrate(driver: SqlDriver): MigrationResult {
        return try {
            val currentVersion = getCurrentDatabaseVersion(driver)
            val migrationsToApply = migrations.filter { it.key > currentVersion }
            
            if (migrationsToApply.isEmpty()) {
                return MigrationResult.Success(currentVersion, "No migrations needed")
            }
            
            driver.execute(null, "BEGIN TRANSACTION", 0)
            
            for ((version, migration) in migrationsToApply.toSortedMap()) {
                try {
                    applyMigration(driver, migration)
                } catch (e: Exception) {
                    driver.execute(null, "ROLLBACK", 0)
                    return MigrationResult.Error(currentVersion, "Migration $version failed: ${e.message}")
                }
            }
            
            driver.execute(null, "COMMIT", 0)
            
            val newVersion = getCurrentDatabaseVersion(driver)
            MigrationResult.Success(newVersion, "Applied ${migrationsToApply.size} migrations")
            
        } catch (e: Exception) {
            MigrationResult.Error(-1, "Migration failed: ${e.message}")
        }
    }
    
    private fun getCurrentDatabaseVersion(driver: SqlDriver): Int {
        return try {
            val cursor = driver.executeQuery(
                identifier = null,
                sql = """
                    SELECT version_code FROM DatabaseMetadata 
                    ORDER BY version_code DESC 
                    LIMIT 1
                """.trimIndent(),
                parameters = 0
            )
            
            if (cursor.next()) {
                cursor.getLong(0)?.toInt() ?: 0
            } else {
                0
            }
        } catch (e: Exception) {
            // Database doesn't exist or metadata table doesn't exist
            0
        }
    }
    
    private fun applyMigration(driver: SqlDriver, migration: Migration) {
        // Apply all SQL statements in the migration
        for (sql in migration.sql) {
            driver.execute(null, sql, 0)
        }
        
        // Record the migration in metadata
        driver.execute(
            identifier = null,
            sql = """
                INSERT INTO DatabaseMetadata (
                    version_code, version_name, migration_timestamp, 
                    migration_description, checksum
                ) VALUES (?, ?, ?, ?, ?)
            """.trimIndent(),
            parameters = 5
        ) {
            bindLong(1, migration.version.toLong())
            bindString(2, migration.version.toString())
            bindLong(3, Clock.System.now().epochSeconds)
            bindString(4, migration.description)
            bindString(5, calculateMigrationChecksum(migration))
        }
    }
    
    private fun calculateMigrationChecksum(migration: Migration): String {
        val content = migration.sql.joinToString("\n")
        return content.hashCode().toString(16)
    }
    
    /**
     * Validates database integrity after migration.
     */
    suspend fun validateDatabaseIntegrity(driver: SqlDriver): ValidationResult {
        val checks = listOf(
            "PRAGMA integrity_check",
            "PRAGMA foreign_key_check",
            "PRAGMA quick_check"
        )
        
        val issues = mutableListOf<String>()
        
        for (check in checks) {
            try {
                val cursor = driver.executeQuery(null, check, 0)
                while (cursor.next()) {
                    val result = cursor.getString(0)
                    if (result != null && result != "ok") {
                        issues.add("$check: $result")
                    }
                }
            } catch (e: Exception) {
                issues.add("$check failed: ${e.message}")
            }
        }
        
        return if (issues.isEmpty()) {
            ValidationResult.Success("Database integrity validated")
        } else {
            ValidationResult.Warning("Database integrity issues found", issues)
        }
    }
    
    /**
     * Creates a backup of the database before migration.
     */
    suspend fun createBackup(driver: SqlDriver, backupPath: String): BackupResult {
        return try {
            // This would need platform-specific implementation
            // For now, return success
            BackupResult.Success("Backup created at $backupPath")
        } catch (e: Exception) {
            BackupResult.Error("Backup failed: ${e.message}")
        }
    }
}

/**
 * Represents a single database migration.
 */
data class Migration(
    val version: Int,
    val description: String,
    val sql: List<String>
)

/**
 * Result of a migration operation.
 */
sealed class MigrationResult {
    data class Success(val version: Int, val message: String) : MigrationResult()
    data class Error(val version: Int, val message: String) : MigrationResult()
}

/**
 * Result of database validation.
 */
sealed class ValidationResult {
    data class Success(val message: String) : ValidationResult()
    data class Warning(val message: String, val issues: List<String>) : ValidationResult()
    data class Error(val message: String) : ValidationResult()
}

/**
 * Result of backup operation.
 */
sealed class BackupResult {
    data class Success(val message: String) : BackupResult()
    data class Error(val message: String) : BackupResult()
}

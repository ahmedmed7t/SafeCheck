package com.nexable.safecheck.core.data.database

import app.cash.sqldelight.db.SqlDriver
import kotlinx.coroutines.delay
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Database maintenance and cleanup procedures for SafeCheck.
 */
class DatabaseMaintenance(private val driver: SqlDriver) {
    
    companion object {
        // Default retention periods (in seconds)
        const val DEFAULT_SCAN_HISTORY_RETENTION = 90 * 24 * 60 * 60L // 90 days
        const val DEFAULT_CACHE_RETENTION = 7 * 24 * 60 * 60L // 7 days
        const val DEFAULT_LOG_RETENTION = 30 * 24 * 60 * 60L // 30 days
        
        // Cleanup batch sizes
        const val CLEANUP_BATCH_SIZE = 1000
        const val VACUUM_THRESHOLD_MB = 50
    }
    
    /**
     * Performs comprehensive database maintenance.
     */
    suspend fun performMaintenance(config: MaintenanceConfig = MaintenanceConfig()): MaintenanceResult {
        val startTime = Clock.System.now()
        val operations = mutableListOf<String>()
        val errors = mutableListOf<String>()
        
        try {
            // 1. Clean expired cache entries
            if (config.cleanExpiredCache) {
                try {
                    val cleanedCache = cleanExpiredCache()
                    operations.add("Cleaned $cleanedCache expired cache entries")
                } catch (e: Exception) {
                    errors.add("Cache cleanup failed: ${e.message}")
                }
            }
            
            // 2. Clean old scan history
            if (config.cleanOldScans) {
                try {
                    val cleanedScans = cleanOldScanHistory(config.scanRetentionSeconds)
                    operations.add("Cleaned $cleanedScans old scan history entries")
                } catch (e: Exception) {
                    errors.add("Scan history cleanup failed: ${e.message}")
                }
            }
            
            // 3. Update cache statistics
            if (config.updateCacheStats) {
                try {
                    updateCacheStatistics()
                    operations.add("Updated cache statistics")
                } catch (e: Exception) {
                    errors.add("Cache statistics update failed: ${e.message}")
                }
            }
            
            // 4. Optimize database
            if (config.optimizeDatabase) {
                try {
                    val optimizationResult = optimizeDatabase()
                    operations.add("Database optimization: $optimizationResult")
                } catch (e: Exception) {
                    errors.add("Database optimization failed: ${e.message}")
                }
            }
            
            // 5. Vacuum database if needed
            if (config.vacuumDatabase) {
                try {
                    val vacuumResult = vacuumIfNeeded()
                    if (vacuumResult.isNotEmpty()) {
                        operations.add("Database vacuum: $vacuumResult")
                    }
                } catch (e: Exception) {
                    errors.add("Database vacuum failed: ${e.message}")
                }
            }
            
            // 6. Validate database integrity
            if (config.validateIntegrity) {
                try {
                    val validationResult = validateIntegrity()
                    operations.add("Database integrity: $validationResult")
                } catch (e: Exception) {
                    errors.add("Database validation failed: ${e.message}")
                }
            }
            
            val endTime = Clock.System.now()
            val duration = endTime.epochSeconds - startTime.epochSeconds
            
            return MaintenanceResult.Success(
                duration = duration,
                operations = operations,
                errors = errors
            )
            
        } catch (e: Exception) {
            return MaintenanceResult.Error(
                message = "Maintenance failed: ${e.message}",
                errors = errors
            )
        }
    }
    
    /**
     * Cleans expired cache entries.
     */
    suspend fun cleanExpiredCache(): Int {
        val currentTime = Clock.System.now().epochSeconds
        
        // First, count how many entries will be deleted
        val countCursor = driver.executeQuery(
            identifier = null,
            sql = "SELECT COUNT(*) FROM Cache WHERE expires_at <= ?",
            parameters = 1
        ) {
            bindLong(1, currentTime)
        }
        
        val count = if (countCursor.next()) {
            countCursor.getLong(0)?.toInt() ?: 0
        } else 0
        
        // Delete expired entries
        driver.execute(
            identifier = null,
            sql = "DELETE FROM Cache WHERE expires_at <= ?",
            parameters = 1
        ) {
            bindLong(1, currentTime)
        }
        
        return count
    }
    
    /**
     * Cleans old scan history entries.
     */
    suspend fun cleanOldScanHistory(retentionSeconds: Long = DEFAULT_SCAN_HISTORY_RETENTION): Int {
        val cutoffTime = Clock.System.now().epochSeconds - retentionSeconds
        
        // Count entries to be deleted
        val countCursor = driver.executeQuery(
            identifier = null,
            sql = "SELECT COUNT(*) FROM ScanHistory WHERE scanned_at < ?",
            parameters = 1
        ) {
            bindLong(1, cutoffTime)
        }
        
        val count = if (countCursor.next()) {
            countCursor.getLong(0)?.toInt() ?: 0
        } else 0
        
        // Delete old entries in batches to avoid locking
        var totalDeleted = 0
        while (totalDeleted < count) {
            val deleted = driver.executeQuery(
                identifier = null,
                sql = """
                    DELETE FROM ScanHistory 
                    WHERE id IN (
                        SELECT id FROM ScanHistory 
                        WHERE scanned_at < ? 
                        LIMIT ?
                    )
                """.trimIndent(),
                parameters = 2
            ) {
                bindLong(1, cutoffTime)
                bindLong(2, CLEANUP_BATCH_SIZE.toLong())
            }
            
            totalDeleted += CLEANUP_BATCH_SIZE
            
            // Small delay to prevent database locking
            delay(10)
        }
        
        return count
    }
    
    /**
     * Updates cache hit statistics and removes least-used entries.
     */
    suspend fun updateCacheStatistics() {
        // Remove least-used cache entries if cache is too large
        val cacheCountCursor = driver.executeQuery(
            identifier = null,
            sql = "SELECT COUNT(*) FROM Cache",
            parameters = 0
        )
        
        val cacheCount = if (cacheCountCursor.next()) {
            cacheCountCursor.getLong(0)?.toInt() ?: 0
        } else 0
        
        // If cache has more than 10,000 entries, remove least-used 20%
        if (cacheCount > 10_000) {
            val toRemove = (cacheCount * 0.2).toInt()
            
            driver.execute(
                identifier = null,
                sql = """
                    DELETE FROM Cache 
                    WHERE id IN (
                        SELECT id FROM Cache 
                        ORDER BY hit_count ASC, last_accessed ASC 
                        LIMIT ?
                    )
                """.trimIndent(),
                parameters = 1
            ) {
                bindLong(1, toRemove.toLong())
            }
        }
    }
    
    /**
     * Optimizes database performance.
     */
    suspend fun optimizeDatabase(): String {
        val operations = mutableListOf<String>()
        
        // Analyze tables to update statistics
        val tables = listOf("ScanHistory", "Cache", "BrandDomains", "DisposableDomains", "UserSettings")
        
        for (table in tables) {
            try {
                driver.execute(null, "ANALYZE $table", 0)
                operations.add("Analyzed $table")
            } catch (e: Exception) {
                operations.add("Failed to analyze $table: ${e.message}")
            }
        }
        
        // Reindex tables if needed
        try {
            driver.execute(null, "REINDEX", 0)
            operations.add("Reindexed database")
        } catch (e: Exception) {
            operations.add("Reindex failed: ${e.message}")
        }
        
        return operations.joinToString(", ")
    }
    
    /**
     * Vacuums database if it's fragmented.
     */
    suspend fun vacuumIfNeeded(): String {
        // Check database size and fragmentation
        val sizeCursor = driver.executeQuery(
            identifier = null,
            sql = "PRAGMA page_count",
            parameters = 0
        )
        
        val pageCount = if (sizeCursor.next()) {
            sizeCursor.getLong(0) ?: 0
        } else 0
        
        val freePagesCursor = driver.executeQuery(
            identifier = null,
            sql = "PRAGMA freelist_count",
            parameters = 0
        )
        
        val freePages = if (freePagesCursor.next()) {
            freePagesCursor.getLong(0) ?: 0
        } else 0
        
        // Calculate database size in MB (assuming 4KB pages)
        val sizeInMB = (pageCount * 4) / 1024
        val fragmentationPercent = if (pageCount > 0) (freePages * 100) / pageCount else 0
        
        // Vacuum if database is large enough and fragmented
        return if (sizeInMB > VACUUM_THRESHOLD_MB && fragmentationPercent > 10) {
            driver.execute(null, "VACUUM", 0)
            "Vacuumed database (${sizeInMB}MB, ${fragmentationPercent}% fragmented)"
        } else {
            ""
        }
    }
    
    /**
     * Validates database integrity.
     */
    suspend fun validateIntegrity(): String {
        val checks = listOf(
            "PRAGMA integrity_check" to "integrity",
            "PRAGMA foreign_key_check" to "foreign_keys",
            "PRAGMA quick_check" to "quick"
        )
        
        val results = mutableListOf<String>()
        
        for ((pragma, name) in checks) {
            try {
                val cursor = driver.executeQuery(null, pragma, 0)
                if (cursor.next()) {
                    val result = cursor.getString(0) ?: "unknown"
                    results.add("$name: $result")
                }
            } catch (e: Exception) {
                results.add("$name: failed (${e.message})")
            }
        }
        
        return results.joinToString(", ")
    }
    
    /**
     * Gets database statistics.
     */
    suspend fun getDatabaseStatistics(): DatabaseStatistics {
        val stats = mutableMapOf<String, Any>()
        
        // Get table sizes
        val tables = listOf("ScanHistory", "Cache", "BrandDomains", "DisposableDomains", "UserSettings")
        
        for (table in tables) {
            try {
                val cursor = driver.executeQuery(
                    identifier = null,
                    sql = "SELECT COUNT(*) FROM $table",
                    parameters = 0
                )
                
                if (cursor.next()) {
                    stats["${table}_count"] = cursor.getLong(0) ?: 0L
                }
            } catch (e: Exception) {
                stats["${table}_count"] = "error: ${e.message}"
            }
        }
        
        // Get database size
        try {
            val sizeCursor = driver.executeQuery(null, "PRAGMA page_count", 0)
            val pageSize = driver.executeQuery(null, "PRAGMA page_size", 0)
            
            val pages = if (sizeCursor.next()) sizeCursor.getLong(0) ?: 0L else 0L
            val size = if (pageSize.next()) pageSize.getLong(0) ?: 4096L else 4096L
            
            stats["database_size_bytes"] = pages * size
            stats["database_size_mb"] = (pages * size) / (1024 * 1024)
        } catch (e: Exception) {
            stats["database_size"] = "error: ${e.message}"
        }
        
        return DatabaseStatistics(
            timestamp = Clock.System.now(),
            statistics = stats
        )
    }
}

/**
 * Configuration for database maintenance operations.
 */
data class MaintenanceConfig(
    val cleanExpiredCache: Boolean = true,
    val cleanOldScans: Boolean = true,
    val updateCacheStats: Boolean = true,
    val optimizeDatabase: Boolean = true,
    val vacuumDatabase: Boolean = true,
    val validateIntegrity: Boolean = true,
    val scanRetentionSeconds: Long = DatabaseMaintenance.DEFAULT_SCAN_HISTORY_RETENTION
)

/**
 * Result of maintenance operations.
 */
sealed class MaintenanceResult {
    data class Success(
        val duration: Long,
        val operations: List<String>,
        val errors: List<String>
    ) : MaintenanceResult()
    
    data class Error(
        val message: String,
        val errors: List<String>
    ) : MaintenanceResult()
}

/**
 * Database statistics snapshot.
 */
data class DatabaseStatistics(
    val timestamp: Instant,
    val statistics: Map<String, Any>
)

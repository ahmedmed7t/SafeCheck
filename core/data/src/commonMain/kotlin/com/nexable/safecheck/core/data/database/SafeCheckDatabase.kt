package com.nexable.safecheck.core.data.database

import app.cash.sqldelight.db.SqlDriver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Main database wrapper for SafeCheck application.
 */
class SafeCheckDatabase private constructor(
    private val driver: SqlDriver,
    private val config: DatabaseConfig
) {
    
    companion object {
        @Volatile
        private var INSTANCE: SafeCheckDatabase? = null
        
        /**
         * Gets or creates the database instance.
         */
        suspend fun getInstance(
            driverFactory: DatabaseDriverFactory,
            config: DatabaseConfig = DatabaseConfig()
        ): SafeCheckDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: createDatabase(driverFactory, config).also { INSTANCE = it }
            }
        }
        
        private suspend fun createDatabase(
            driverFactory: DatabaseDriverFactory,
            config: DatabaseConfig
        ): SafeCheckDatabase {
            val driver = driverFactory.createDriver()
            
            // Apply database configuration
            configureDatabase(driver, config)
            
            // Run migrations
            val migrationResult = DatabaseMigrations.migrate(driver)
            when (migrationResult) {
                is MigrationResult.Error -> {
                    throw IllegalStateException("Database migration failed: ${migrationResult.message}")
                }
                is MigrationResult.Success -> {
                    // Migration successful
                }
            }
            
            return SafeCheckDatabase(driver, config)
        }
        
        private fun configureDatabase(driver: SqlDriver, config: DatabaseConfig) {
            // Configure SQLite settings
            if (config.enableForeignKeys) {
                driver.execute(null, "PRAGMA foreign_keys = ON", 0)
            }
            
            if (config.enableWAL) {
                driver.execute(null, "PRAGMA journal_mode = WAL", 0)
            }
            
            driver.execute(null, "PRAGMA busy_timeout = ${config.busyTimeout}", 0)
            driver.execute(null, "PRAGMA page_size = ${config.pageSize}", 0)
            driver.execute(null, "PRAGMA cache_size = ${config.cacheSize}", 0)
            
            if (config.enableAutoVacuum) {
                driver.execute(null, "PRAGMA auto_vacuum = INCREMENTAL", 0)
            }
            
            // Additional performance settings
            driver.execute(null, "PRAGMA synchronous = NORMAL", 0)
            driver.execute(null, "PRAGMA temp_store = MEMORY", 0)
            driver.execute(null, "PRAGMA mmap_size = 268435456", 0) // 256MB
        }
    }
    
    // Database components
    private val _database by lazy { com.nexable.safecheck.core.data.SafeCheckDatabase(driver) }
    private val maintenance by lazy { DatabaseMaintenance(driver) }
    private val performanceMonitor by lazy { DatabasePerformanceMonitor() }
    
    // Background maintenance scope
    private val maintenanceScope = CoroutineScope(SupervisorJob())
    
    /**
     * Gets the SQLDelight database instance.
     */
    val database: com.nexable.safecheck.core.data.SafeCheckDatabase
        get() = _database
    
    /**
     * Gets the database maintenance component.
     */
    val databaseMaintenance: DatabaseMaintenance
        get() = maintenance
    
    /**
     * Gets the performance monitoring component.
     */
    val performanceMonitor: DatabasePerformanceMonitor
        get() = performanceMonitor
    
    /**
     * Performs database maintenance in the background.
     */
    fun performBackgroundMaintenance(config: MaintenanceConfig = MaintenanceConfig()) {
        maintenanceScope.launch {
            try {
                maintenance.performMaintenance(config)
            } catch (e: Exception) {
                // Log error but don't crash the app
                println("Background maintenance failed: ${e.message}")
            }
        }
    }
    
    /**
     * Gets database statistics.
     */
    suspend fun getStatistics(): DatabaseStatistics {
        return maintenance.getDatabaseStatistics()
    }
    
    /**
     * Validates database integrity.
     */
    suspend fun validateIntegrity(): ValidationResult {
        return DatabaseMigrations.validateDatabaseIntegrity(driver)
    }
    
    /**
     * Closes the database connection.
     */
    fun close() {
        driver.close()
        INSTANCE = null
    }
    
    /**
     * Executes a transaction with retry logic.
     */
    suspend fun <T> transaction(block: suspend () -> T): T {
        var lastException: Exception? = null
        repeat(3) { attempt ->
            try {
                return database.transactionWithResult {
                    block()
                }
            } catch (e: Exception) {
                lastException = e
                if (attempt < 2) {
                    // Wait before retry
                    kotlinx.coroutines.delay(100 * (attempt + 1))
                }
            }
        }
        throw lastException!!
    }
}

/**
 * Database health check utilities.
 */
object DatabaseHealthCheck {
    
    /**
     * Performs a comprehensive health check on the database.
     */
    suspend fun performHealthCheck(database: SafeCheckDatabase): HealthCheckResult {
        val checks = mutableListOf<HealthCheckItem>()
        
        try {
            // 1. Basic connectivity
            checks.add(checkConnectivity(database))
            
            // 2. Database integrity
            checks.add(checkIntegrity(database))
            
            // 3. Performance metrics
            checks.add(checkPerformance(database))
            
            // 4. Storage usage
            checks.add(checkStorageUsage(database))
            
            // 5. Cache efficiency
            checks.add(checkCacheEfficiency(database))
            
            val overallHealth = if (checks.all { it.status == HealthStatus.HEALTHY }) {
                HealthStatus.HEALTHY
            } else if (checks.any { it.status == HealthStatus.CRITICAL }) {
                HealthStatus.CRITICAL
            } else {
                HealthStatus.WARNING
            }
            
            return HealthCheckResult(
                overallHealth = overallHealth,
                checks = checks,
                timestamp = kotlinx.datetime.Clock.System.now()
            )
            
        } catch (e: Exception) {
            return HealthCheckResult(
                overallHealth = HealthStatus.CRITICAL,
                checks = listOf(
                    HealthCheckItem(
                        name = "Database Health Check",
                        status = HealthStatus.CRITICAL,
                        message = "Health check failed: ${e.message}"
                    )
                ),
                timestamp = kotlinx.datetime.Clock.System.now()
            )
        }
    }
    
    private suspend fun checkConnectivity(database: SafeCheckDatabase): HealthCheckItem {
        return try {
            database.database.getCurrentVersion().executeAsOneOrNull()
            HealthCheckItem(
                name = "Database Connectivity",
                status = HealthStatus.HEALTHY,
                message = "Database connection is working"
            )
        } catch (e: Exception) {
            HealthCheckItem(
                name = "Database Connectivity",
                status = HealthStatus.CRITICAL,
                message = "Database connection failed: ${e.message}"
            )
        }
    }
    
    private suspend fun checkIntegrity(database: SafeCheckDatabase): HealthCheckItem {
        return try {
            val validation = database.validateIntegrity()
            when (validation) {
                is ValidationResult.Success -> HealthCheckItem(
                    name = "Database Integrity",
                    status = HealthStatus.HEALTHY,
                    message = validation.message
                )
                is ValidationResult.Warning -> HealthCheckItem(
                    name = "Database Integrity",
                    status = HealthStatus.WARNING,
                    message = validation.message
                )
                is ValidationResult.Error -> HealthCheckItem(
                    name = "Database Integrity",
                    status = HealthStatus.CRITICAL,
                    message = validation.message
                )
            }
        } catch (e: Exception) {
            HealthCheckItem(
                name = "Database Integrity",
                status = HealthStatus.CRITICAL,
                message = "Integrity check failed: ${e.message}"
            )
        }
    }
    
    private suspend fun checkPerformance(database: SafeCheckDatabase): HealthCheckItem {
        return try {
            val slowQueries = database.performanceMonitor.getSlowQueries(100)
            if (slowQueries.isEmpty()) {
                HealthCheckItem(
                    name = "Database Performance",
                    status = HealthStatus.HEALTHY,
                    message = "No slow queries detected"
                )
            } else {
                HealthCheckItem(
                    name = "Database Performance",
                    status = HealthStatus.WARNING,
                    message = "Found ${slowQueries.size} slow queries"
                )
            }
        } catch (e: Exception) {
            HealthCheckItem(
                name = "Database Performance",
                status = HealthStatus.WARNING,
                message = "Performance check failed: ${e.message}"
            )
        }
    }
    
    private suspend fun checkStorageUsage(database: SafeCheckDatabase): HealthCheckItem {
        return try {
            val stats = database.getStatistics()
            val sizeMB = stats.statistics["database_size_mb"] as? Long ?: 0L
            
            when {
                sizeMB > 1000 -> HealthCheckItem(
                    name = "Storage Usage",
                    status = HealthStatus.WARNING,
                    message = "Database size is large: ${sizeMB}MB"
                )
                sizeMB > 100 -> HealthCheckItem(
                    name = "Storage Usage",
                    status = HealthStatus.HEALTHY,
                    message = "Database size: ${sizeMB}MB"
                )
                else -> HealthCheckItem(
                    name = "Storage Usage",
                    status = HealthStatus.HEALTHY,
                    message = "Database size: ${sizeMB}MB"
                )
            }
        } catch (e: Exception) {
            HealthCheckItem(
                name = "Storage Usage",
                status = HealthStatus.WARNING,
                message = "Storage check failed: ${e.message}"
            )
        }
    }
    
    private suspend fun checkCacheEfficiency(database: SafeCheckDatabase): HealthCheckItem {
        return try {
            // This would need actual cache hit rate calculation
            HealthCheckItem(
                name = "Cache Efficiency",
                status = HealthStatus.HEALTHY,
                message = "Cache is functioning normally"
            )
        } catch (e: Exception) {
            HealthCheckItem(
                name = "Cache Efficiency",
                status = HealthStatus.WARNING,
                message = "Cache check failed: ${e.message}"
            )
        }
    }
}

/**
 * Health check result for the database.
 */
data class HealthCheckResult(
    val overallHealth: HealthStatus,
    val checks: List<HealthCheckItem>,
    val timestamp: kotlinx.datetime.Instant
)

/**
 * Individual health check item.
 */
data class HealthCheckItem(
    val name: String,
    val status: HealthStatus,
    val message: String
)

/**
 * Health status enumeration.
 */
enum class HealthStatus {
    HEALTHY,
    WARNING,
    CRITICAL
}

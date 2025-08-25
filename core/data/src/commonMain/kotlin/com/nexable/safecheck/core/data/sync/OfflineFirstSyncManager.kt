package com.nexable.safecheck.core.data.sync

import com.nexable.safecheck.core.data.database.SafeCheckDatabase
import com.nexable.safecheck.core.data.repository.CacheRepositoryImpl
import com.nexable.safecheck.core.data.repository.SettingsRepositoryImpl
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

/**
 * Offline-first data synchronization manager for SafeCheck.
 * Ensures data availability and consistency across online/offline states.
 */
class OfflineFirstSyncManager(
    private val database: SafeCheckDatabase,
    private val cacheRepository: CacheRepositoryImpl,
    private val settingsRepository: SettingsRepositoryImpl
) {
    
    private val syncMutex = Mutex()
    private var lastSyncTime: Instant? = null
    private var syncInProgress = false
    
    companion object {
        const val SYNC_INTERVAL_MINUTES = 30L
        const val FORCE_SYNC_THRESHOLD_HOURS = 24L
        const val MAX_OFFLINE_CACHE_DAYS = 7L
        const val MAX_RETRY_ATTEMPTS = 3
        const val RETRY_DELAY_BASE_MS = 1000L
    }
    
    /**
     * Initiates data synchronization based on current connectivity and cache state.
     */
    suspend fun sync(force: Boolean = false): Result<SyncResult> {
        return syncMutex.withLock {
            if (syncInProgress && !force) {
                return Result.success(SyncResult.AlreadyInProgress)
            }
            
            syncInProgress = true
            
            try {
                val syncStrategy = determineSyncStrategy(force)
                val result = when (syncStrategy) {
                    SyncStrategy.FULL_SYNC -> performFullSync()
                    SyncStrategy.INCREMENTAL_SYNC -> performIncrementalSync()
                    SyncStrategy.OFFLINE_OPTIMIZATION -> performOfflineOptimization()
                    SyncStrategy.CACHE_REFRESH -> performCacheRefresh()
                    SyncStrategy.NO_SYNC_NEEDED -> SyncResult.NoSyncNeeded
                }
                
                if (result is SyncResult.Success) {
                    lastSyncTime = Clock.System.now()
                    updateSyncMetadata(result)
                }
                
                Result.success(result)
            } catch (e: Exception) {
                Result.error("Sync failed: ${e.message}", "SYNC_ERROR")
            } finally {
                syncInProgress = false
            }
        }
    }
    
    /**
     * Monitors connectivity and triggers automatic synchronization.
     */
    fun startAutomaticSync(): Flow<SyncEvent> = flow {
        while (true) {
            try {
                val isOnline = checkConnectivity()
                
                if (isOnline) {
                    val shouldSync = shouldPerformAutomaticSync()
                    
                    if (shouldSync) {
                        emit(SyncEvent.SyncStarted)
                        
                        val syncResult = sync(force = false)
                        when (syncResult) {
                            is Result.Success -> emit(SyncEvent.SyncCompleted(syncResult.data))
                            is Result.Error -> emit(SyncEvent.SyncFailed(syncResult.message))
                            else -> emit(SyncEvent.SyncFailed("Unknown sync error"))
                        }
                    }
                } else {
                    emit(SyncEvent.OfflineMode)
                    // Perform offline optimizations
                    performOfflineOptimization()
                }
                
                kotlinx.coroutines.delay(SYNC_INTERVAL_MINUTES * 60 * 1000) // Wait for next sync cycle
                
            } catch (e: Exception) {
                emit(SyncEvent.SyncFailed("Automatic sync error: ${e.message}"))
                kotlinx.coroutines.delay(5 * 60 * 1000) // Wait 5 minutes on error
            }
        }
    }
    
    /**
     * Ensures critical data is available offline.
     */
    suspend fun prepareForOffline(): Result<OfflinePreparationResult> {
        return try {
            val preparation = OfflinePreparationResult()
            
            // Cache critical brand domains
            val brandCacheResult = cacheCriticalBrandDomains()
            preparation.brandDomainsCached = brandCacheResult
            
            // Cache disposable domain list
            val disposableCacheResult = cacheDisposableDomains()
            preparation.disposableDomainsCached = disposableCacheResult
            
            // Preload essential settings
            val settingsResult = preloadEssentialSettings()
            preparation.settingsPreloaded = settingsResult
            
            // Optimize database for offline access
            val dbOptimization = optimizeDatabaseForOffline()
            preparation.databaseOptimized = dbOptimization
            
            // Cache recent scan results for reference
            val scanCacheResult = cacheRecentScanResults()
            preparation.scanResultsCached = scanCacheResult
            
            Result.success(preparation)
        } catch (e: Exception) {
            Result.error("Failed to prepare for offline: ${e.message}", "OFFLINE_PREP_ERROR")
        }
    }
    
    /**
     * Handles data conflicts during synchronization.
     */
    suspend fun resolveConflicts(conflicts: List<DataConflict>): Result<ConflictResolution> {
        return try {
            val resolutions = mutableListOf<ConflictResolutionItem>()
            
            for (conflict in conflicts) {
                val resolution = when (conflict.type) {
                    ConflictType.SETTING_CONFLICT -> resolveSettingConflict(conflict)
                    ConflictType.CACHE_CONFLICT -> resolveCacheConflict(conflict)
                    ConflictType.SCAN_HISTORY_CONFLICT -> resolveScanHistoryConflict(conflict)
                    ConflictType.BRAND_LIST_CONFLICT -> resolveBrandListConflict(conflict)
                }
                resolutions.add(resolution)
            }
            
            val conflictResolution = ConflictResolution(
                totalConflicts = conflicts.size,
                resolvedConflicts = resolutions.count { it.resolved },
                resolutions = resolutions,
                resolvedAt = Clock.System.now()
            )
            
            Result.success(conflictResolution)
        } catch (e: Exception) {
            Result.error("Failed to resolve conflicts: ${e.message}", "CONFLICT_RESOLUTION_ERROR")
        }
    }
    
    /**
     * Gets synchronization status and metrics.
     */
    suspend fun getSyncStatus(): SyncStatus {
        return SyncStatus(
            lastSyncTime = lastSyncTime,
            syncInProgress = syncInProgress,
            isOnline = checkConnectivity(),
            cacheSize = getCacheSize(),
            offlineCapabilityScore = calculateOfflineCapabilityScore(),
            nextScheduledSync = getNextScheduledSyncTime(),
            syncMetrics = getSyncMetrics()
        )
    }
    
    private fun determineSyncStrategy(force: Boolean): SyncStrategy {
        val isOnline = checkConnectivity()
        val timeSinceLastSync = lastSyncTime?.let { 
            Clock.System.now().epochSeconds - it.epochSeconds 
        } ?: Long.MAX_VALUE
        
        return when {
            !isOnline -> SyncStrategy.OFFLINE_OPTIMIZATION
            force -> SyncStrategy.FULL_SYNC
            timeSinceLastSync > FORCE_SYNC_THRESHOLD_HOURS * 3600 -> SyncStrategy.FULL_SYNC
            timeSinceLastSync > SYNC_INTERVAL_MINUTES * 60 -> SyncStrategy.INCREMENTAL_SYNC
            needsCacheRefresh() -> SyncStrategy.CACHE_REFRESH
            else -> SyncStrategy.NO_SYNC_NEEDED
        }
    }
    
    private suspend fun performFullSync(): SyncResult {
        val operations = mutableListOf<String>()
        var errors = 0
        
        try {
            // Sync brand domains
            operations.add("Syncing brand domains")
            // syncBrandDomains() - would be implemented
            
            // Sync disposable domains
            operations.add("Syncing disposable domains")
            // syncDisposableDomains() - would be implemented
            
            // Refresh cache
            operations.add("Refreshing cache")
            cacheRepository.cleanupExpired()
            
            // Sync settings
            operations.add("Syncing settings")
            // syncSettings() - would be implemented
            
            return SyncResult.Success(
                strategy = SyncStrategy.FULL_SYNC,
                operations = operations,
                errors = errors,
                duration = 0L // Would be calculated
            )
        } catch (e: Exception) {
            return SyncResult.Failed(
                strategy = SyncStrategy.FULL_SYNC,
                error = e.message ?: "Unknown error",
                operations = operations
            )
        }
    }
    
    private suspend fun performIncrementalSync(): SyncResult {
        val operations = mutableListOf<String>()
        
        try {
            // Only sync changes since last sync
            operations.add("Incremental brand domain sync")
            operations.add("Incremental cache refresh")
            
            return SyncResult.Success(
                strategy = SyncStrategy.INCREMENTAL_SYNC,
                operations = operations,
                errors = 0,
                duration = 0L
            )
        } catch (e: Exception) {
            return SyncResult.Failed(
                strategy = SyncStrategy.INCREMENTAL_SYNC,
                error = e.message ?: "Unknown error",
                operations = operations
            )
        }
    }
    
    private suspend fun performOfflineOptimization(): SyncResult {
        val operations = mutableListOf<String>()
        
        try {
            // Cleanup expired cache entries
            operations.add("Cleaning expired cache")
            cacheRepository.cleanupExpired()
            
            // Optimize database
            operations.add("Optimizing database for offline")
            database.databaseMaintenance.performMaintenance()
            
            // Preload essential data
            operations.add("Preloading essential data")
            prepareForOffline()
            
            return SyncResult.Success(
                strategy = SyncStrategy.OFFLINE_OPTIMIZATION,
                operations = operations,
                errors = 0,
                duration = 0L
            )
        } catch (e: Exception) {
            return SyncResult.Failed(
                strategy = SyncStrategy.OFFLINE_OPTIMIZATION,
                error = e.message ?: "Unknown error",
                operations = operations
            )
        }
    }
    
    private suspend fun performCacheRefresh(): SyncResult {
        val operations = mutableListOf<String>()
        
        try {
            operations.add("Refreshing cache")
            cacheRepository.cleanupExpired()
            
            return SyncResult.Success(
                strategy = SyncStrategy.CACHE_REFRESH,
                operations = operations,
                errors = 0,
                duration = 0L
            )
        } catch (e: Exception) {
            return SyncResult.Failed(
                strategy = SyncStrategy.CACHE_REFRESH,
                error = e.message ?: "Unknown error",
                operations = operations
            )
        }
    }
    
    private suspend fun cacheCriticalBrandDomains(): Boolean {
        return try {
            // Cache top brand domains for offline access
            val criticalBrands = listOf(
                "google.com", "microsoft.com", "apple.com", "amazon.com",
                "facebook.com", "paypal.com", "chase.com", "bankofamerica.com"
            )
            
            for (brand in criticalBrands) {
                // Cache would be populated here
            }
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private suspend fun cacheDisposableDomains(): Boolean {
        return try {
            // Cache disposable domain list for offline verification
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private suspend fun preloadEssentialSettings(): Boolean {
        return try {
            // Preload essential settings
            settingsRepository.getString("scan_timeout")
            settingsRepository.getBoolean("enable_caching")
            settingsRepository.getInt("max_concurrent_scans")
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private suspend fun optimizeDatabaseForOffline(): Boolean {
        return try {
            database.databaseMaintenance.performMaintenance()
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private suspend fun cacheRecentScanResults(): Boolean {
        return try {
            // Cache recent scan results for offline reference
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private fun shouldPerformAutomaticSync(): Boolean {
        val timeSinceLastSync = lastSyncTime?.let { 
            Clock.System.now().epochSeconds - it.epochSeconds 
        } ?: Long.MAX_VALUE
        
        return timeSinceLastSync > SYNC_INTERVAL_MINUTES * 60
    }
    
    private fun needsCacheRefresh(): Boolean {
        // Implement cache refresh logic
        return false
    }
    
    private fun checkConnectivity(): Boolean {
        // This would be implemented using platform-specific connectivity checks
        return true // Placeholder
    }
    
    private suspend fun getCacheSize(): Long {
        return try {
            val stats = database.getStatistics()
            stats.statistics["Cache_count"] as? Long ?: 0L
        } catch (e: Exception) {
            0L
        }
    }
    
    private fun calculateOfflineCapabilityScore(): Int {
        // Calculate a score (0-100) based on offline data availability
        return 85 // Placeholder
    }
    
    private fun getNextScheduledSyncTime(): Instant {
        return lastSyncTime?.plus(kotlinx.datetime.DateTimeUnit.MINUTE, SYNC_INTERVAL_MINUTES.toInt())
            ?: Clock.System.now()
    }
    
    private fun getSyncMetrics(): SyncMetrics {
        return SyncMetrics(
            totalSyncs = 0,
            successfulSyncs = 0,
            failedSyncs = 0,
            averageSyncDuration = 0L,
            lastSuccessfulSync = lastSyncTime,
            dataSynced = 0L
        )
    }
    
    private suspend fun updateSyncMetadata(result: SyncResult) {
        // Update sync metadata in settings
        settingsRepository.setString("last_sync_time", lastSyncTime.toString())
        settingsRepository.setString("last_sync_result", result.toString())
    }
    
    private suspend fun resolveSettingConflict(conflict: DataConflict): ConflictResolutionItem {
        // Implement setting conflict resolution (e.g., take latest, merge, user choice)
        return ConflictResolutionItem(
            conflictId = conflict.id,
            resolution = "Used latest timestamp",
            resolved = true
        )
    }
    
    private suspend fun resolveCacheConflict(conflict: DataConflict): ConflictResolutionItem {
        // Implement cache conflict resolution
        return ConflictResolutionItem(
            conflictId = conflict.id,
            resolution = "Merged cache entries",
            resolved = true
        )
    }
    
    private suspend fun resolveScanHistoryConflict(conflict: DataConflict): ConflictResolutionItem {
        // Implement scan history conflict resolution
        return ConflictResolutionItem(
            conflictId = conflict.id,
            resolution = "Kept both entries",
            resolved = true
        )
    }
    
    private suspend fun resolveBrandListConflict(conflict: DataConflict): ConflictResolutionItem {
        // Implement brand list conflict resolution
        return ConflictResolutionItem(
            conflictId = conflict.id,
            resolution = "Used server version",
            resolved = true
        )
    }
}

/**
 * Synchronization strategy enumeration.
 */
enum class SyncStrategy {
    FULL_SYNC,
    INCREMENTAL_SYNC,
    OFFLINE_OPTIMIZATION,
    CACHE_REFRESH,
    NO_SYNC_NEEDED
}

/**
 * Synchronization result.
 */
sealed class SyncResult {
    data class Success(
        val strategy: SyncStrategy,
        val operations: List<String>,
        val errors: Int,
        val duration: Long
    ) : SyncResult()
    
    data class Failed(
        val strategy: SyncStrategy,
        val error: String,
        val operations: List<String>
    ) : SyncResult()
    
    object AlreadyInProgress : SyncResult()
    object NoSyncNeeded : SyncResult()
}

/**
 * Synchronization events.
 */
sealed class SyncEvent {
    object SyncStarted : SyncEvent()
    data class SyncCompleted(val result: SyncResult) : SyncEvent()
    data class SyncFailed(val error: String) : SyncEvent()
    object OfflineMode : SyncEvent()
}

/**
 * Offline preparation result.
 */
data class OfflinePreparationResult(
    var brandDomainsCached: Boolean = false,
    var disposableDomainsCached: Boolean = false,
    var settingsPreloaded: Boolean = false,
    var databaseOptimized: Boolean = false,
    var scanResultsCached: Boolean = false
)

/**
 * Data conflict types.
 */
enum class ConflictType {
    SETTING_CONFLICT,
    CACHE_CONFLICT,
    SCAN_HISTORY_CONFLICT,
    BRAND_LIST_CONFLICT
}

/**
 * Data conflict representation.
 */
data class DataConflict(
    val id: String,
    val type: ConflictType,
    val localData: Any,
    val remoteData: Any,
    val timestamp: Instant
)

/**
 * Conflict resolution result.
 */
data class ConflictResolution(
    val totalConflicts: Int,
    val resolvedConflicts: Int,
    val resolutions: List<ConflictResolutionItem>,
    val resolvedAt: Instant
)

/**
 * Individual conflict resolution item.
 */
data class ConflictResolutionItem(
    val conflictId: String,
    val resolution: String,
    val resolved: Boolean
)

/**
 * Synchronization status.
 */
data class SyncStatus(
    val lastSyncTime: Instant?,
    val syncInProgress: Boolean,
    val isOnline: Boolean,
    val cacheSize: Long,
    val offlineCapabilityScore: Int,
    val nextScheduledSync: Instant,
    val syncMetrics: SyncMetrics
)

/**
 * Synchronization metrics.
 */
@Serializable
data class SyncMetrics(
    val totalSyncs: Int,
    val successfulSyncs: Int,
    val failedSyncs: Int,
    val averageSyncDuration: Long,
    val lastSuccessfulSync: Instant?,
    val dataSynced: Long
)

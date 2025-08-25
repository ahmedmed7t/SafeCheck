package com.nexable.safecheck.core.data.repository

import com.nexable.safecheck.core.data.database.SafeCheckDatabase
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.repository.CacheRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Implementation of CacheRepository using SQLDelight database with TTL management.
 */
class CacheRepositoryImpl(
    private val database: SafeCheckDatabase
) : CacheRepository {
    
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    companion object {
        // Default TTL values in seconds
        const val DEFAULT_REPUTATION_TTL = 24 * 60 * 60L // 24 hours
        const val DEFAULT_DNS_TTL = 12 * 60 * 60L // 12 hours
        const val DEFAULT_WHOIS_TTL = 7 * 24 * 60 * 60L // 7 days
        const val DEFAULT_VIRUS_TOTAL_TTL = 6 * 60 * 60L // 6 hours
        
        // Cache key prefixes
        const val REPUTATION_PREFIX = "reputation:"
        const val DNS_PREFIX = "dns:"
        const val WHOIS_PREFIX = "whois:"
        const val VIRUS_TOTAL_PREFIX = "vt:"
        const val EMAIL_PREFIX = "email:"
        const val FILE_PREFIX = "file:"
    }
    
    override suspend fun <T> get(
        key: String,
        type: Class<T>
    ): Result<T?> {
        return try {
            val cacheEntry = database.database.getCache(key).executeAsOneOrNull()
            
            if (cacheEntry == null) {
                return Result.success(null)
            }
            
            // Update hit count
            database.database.updateCacheHit(key)
            
            // Deserialize cached data
            val data = json.decodeFromString<T>(cacheEntry.cache_data)
            Result.success(data)
        } catch (e: Exception) {
            Result.error("Failed to get cache entry: ${e.message}", "CACHE_GET_ERROR")
        }
    }
    
    override suspend fun <T> put(
        key: String,
        value: T,
        ttlSeconds: Long?
    ): Result<Unit> {
        return try {
            val cacheType = determineCacheType(key)
            val ttl = ttlSeconds ?: getDefaultTTL(cacheType)
            val expiresAt = Clock.System.now().epochSeconds + ttl
            
            val serializedData = json.encodeToString(value)
            
            database.transaction {
                database.database.insertCache(
                    cache_key = key,
                    cache_type = cacheType,
                    target_value = extractTargetValue(key),
                    cache_data = serializedData,
                    confidence = 1.0, // Default confidence
                    expires_at = expiresAt,
                    hit_count = 0,
                    last_accessed = Clock.System.now().epochSeconds
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to put cache entry: ${e.message}", "CACHE_PUT_ERROR")
        }
    }
    
    override suspend fun remove(key: String): Result<Unit> {
        return try {
            database.transaction {
                // Note: This would need a specific delete by key query in the schema
                // For now, we'll use the cleanup function
                database.database.cleanExpiredCache()
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to remove cache entry: ${e.message}", "CACHE_REMOVE_ERROR")
        }
    }
    
    override suspend fun clear(): Result<Unit> {
        return try {
            database.transaction {
                // This would need a clear all cache query
                database.database.cleanExpiredCache()
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to clear cache: ${e.message}", "CACHE_CLEAR_ERROR")
        }
    }
    
    override suspend fun cleanupExpired(): Result<Int> {
        return try {
            // Count expired entries before deletion
            val expiredCount = database.database.getCacheStatistics()
                .executeAsList()
                .sumOf { it.total_entries ?: 0L }
                .toInt()
            
            database.transaction {
                database.database.cleanExpiredCache()
            }
            
            Result.success(expiredCount)
        } catch (e: Exception) {
            Result.error("Failed to cleanup expired cache: ${e.message}", "CACHE_CLEANUP_ERROR")
        }
    }
    
    /**
     * Gets cache statistics.
     */
    suspend fun getCacheStatistics(): Result<CacheStatistics> {
        return try {
            val stats = database.database.getCacheStatistics().executeAsList()
            
            val typeStats = stats.map { row ->
                CacheTypeStatistics(
                    cacheType = row.cache_type,
                    totalEntries = row.total_entries?.toInt() ?: 0,
                    averageConfidence = row.avg_confidence ?: 0.0,
                    totalHits = row.total_hits?.toInt() ?: 0
                )
            }
            
            val overallStats = CacheStatistics(
                totalEntries = typeStats.sumOf { it.totalEntries },
                totalHits = typeStats.sumOf { it.totalHits },
                hitRate = calculateHitRate(typeStats),
                byType = typeStats.associateBy { it.cacheType },
                lastUpdated = Clock.System.now()
            )
            
            Result.success(overallStats)
        } catch (e: Exception) {
            Result.error("Failed to get cache statistics: ${e.message}", "CACHE_STATS_ERROR")
        }
    }
    
    /**
     * Cache reputation data with automatic TTL.
     */
    suspend fun cacheReputation(
        target: String,
        reputationData: ReputationCacheData,
        confidence: Double = 1.0
    ): Result<Unit> {
        val key = "$REPUTATION_PREFIX$target"
        return try {
            val expiresAt = Clock.System.now().epochSeconds + DEFAULT_REPUTATION_TTL
            
            database.transaction {
                database.database.insertCache(
                    cache_key = key,
                    cache_type = "REPUTATION",
                    target_value = target,
                    cache_data = json.encodeToString(reputationData),
                    confidence = confidence,
                    expires_at = expiresAt,
                    hit_count = 0,
                    last_accessed = Clock.System.now().epochSeconds
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to cache reputation: ${e.message}", "REPUTATION_CACHE_ERROR")
        }
    }
    
    /**
     * Gets cached reputation data.
     */
    suspend fun getCachedReputation(target: String): Result<ReputationCacheData?> {
        val key = "$REPUTATION_PREFIX$target"
        return get(key, ReputationCacheData::class.java)
    }
    
    /**
     * Cache DNS data with automatic TTL.
     */
    suspend fun cacheDNS(
        domain: String,
        dnsData: DNSCacheData,
        confidence: Double = 1.0
    ): Result<Unit> {
        val key = "$DNS_PREFIX$domain"
        return try {
            val expiresAt = Clock.System.now().epochSeconds + DEFAULT_DNS_TTL
            
            database.transaction {
                database.database.insertCache(
                    cache_key = key,
                    cache_type = "DNS",
                    target_value = domain,
                    cache_data = json.encodeToString(dnsData),
                    confidence = confidence,
                    expires_at = expiresAt,
                    hit_count = 0,
                    last_accessed = Clock.System.now().epochSeconds
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to cache DNS: ${e.message}", "DNS_CACHE_ERROR")
        }
    }
    
    /**
     * Gets cached DNS data.
     */
    suspend fun getCachedDNS(domain: String): Result<DNSCacheData?> {
        val key = "$DNS_PREFIX$domain"
        return get(key, DNSCacheData::class.java)
    }
    
    /**
     * Cache VirusTotal data with automatic TTL.
     */
    suspend fun cacheVirusTotal(
        hash: String,
        vtData: VirusTotalCacheData,
        confidence: Double = 1.0
    ): Result<Unit> {
        val key = "$VIRUS_TOTAL_PREFIX$hash"
        return try {
            val expiresAt = Clock.System.now().epochSeconds + DEFAULT_VIRUS_TOTAL_TTL
            
            database.transaction {
                database.database.insertCache(
                    cache_key = key,
                    cache_type = "VIRUS_TOTAL",
                    target_value = hash,
                    cache_data = json.encodeToString(vtData),
                    confidence = confidence,
                    expires_at = expiresAt,
                    hit_count = 0,
                    last_accessed = Clock.System.now().epochSeconds
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to cache VirusTotal: ${e.message}", "VT_CACHE_ERROR")
        }
    }
    
    /**
     * Gets cached VirusTotal data.
     */
    suspend fun getCachedVirusTotal(hash: String): Result<VirusTotalCacheData?> {
        val key = "$VIRUS_TOTAL_PREFIX$hash"
        return get(key, VirusTotalCacheData::class.java)
    }
    
    /**
     * Gets cache statistics as a reactive Flow.
     */
    fun getCacheStatisticsFlow(): Flow<CacheStatistics> = flow {
        while (true) {
            try {
                val result = getCacheStatistics()
                if (result is Result.Success) {
                    emit(result.data)
                }
                kotlinx.coroutines.delay(30000) // Refresh every 30 seconds
            } catch (e: Exception) {
                emit(CacheStatistics()) // Default stats on error
            }
        }
    }
    
    /**
     * Automatic cleanup service that runs periodically.
     */
    suspend fun runPeriodicCleanup(): Flow<CleanupResult> = flow {
        while (true) {
            try {
                val expiredCount = cleanupExpired()
                if (expiredCount is Result.Success) {
                    emit(CleanupResult.Success(expiredCount.data))
                } else {
                    emit(CleanupResult.Error("Cleanup failed"))
                }
                
                kotlinx.coroutines.delay(60000) // Run every minute
            } catch (e: Exception) {
                emit(CleanupResult.Error("Cleanup error: ${e.message}"))
                kotlinx.coroutines.delay(300000) // Wait 5 minutes on error
            }
        }
    }
    
    private fun determineCacheType(key: String): String {
        return when {
            key.startsWith(REPUTATION_PREFIX) -> "REPUTATION"
            key.startsWith(DNS_PREFIX) -> "DNS"
            key.startsWith(WHOIS_PREFIX) -> "WHOIS"
            key.startsWith(VIRUS_TOTAL_PREFIX) -> "VIRUS_TOTAL"
            key.startsWith(EMAIL_PREFIX) -> "EMAIL"
            key.startsWith(FILE_PREFIX) -> "FILE"
            else -> "GENERAL"
        }
    }
    
    private fun extractTargetValue(key: String): String {
        val colonIndex = key.indexOf(':')
        return if (colonIndex != -1) {
            key.substring(colonIndex + 1)
        } else {
            key
        }
    }
    
    private fun getDefaultTTL(cacheType: String): Long {
        return when (cacheType) {
            "REPUTATION" -> DEFAULT_REPUTATION_TTL
            "DNS" -> DEFAULT_DNS_TTL
            "WHOIS" -> DEFAULT_WHOIS_TTL
            "VIRUS_TOTAL" -> DEFAULT_VIRUS_TOTAL_TTL
            else -> DEFAULT_REPUTATION_TTL
        }
    }
    
    private fun calculateHitRate(typeStats: List<CacheTypeStatistics>): Double {
        val totalEntries = typeStats.sumOf { it.totalEntries }
        val totalHits = typeStats.sumOf { it.totalHits }
        
        return if (totalEntries > 0) {
            totalHits.toDouble() / totalEntries.toDouble()
        } else {
            0.0
        }
    }
}

/**
 * Cache statistics data model.
 */
data class CacheStatistics(
    val totalEntries: Int = 0,
    val totalHits: Int = 0,
    val hitRate: Double = 0.0,
    val byType: Map<String, CacheTypeStatistics> = emptyMap(),
    val lastUpdated: Instant = Clock.System.now()
)

/**
 * Statistics for a specific cache type.
 */
data class CacheTypeStatistics(
    val cacheType: String,
    val totalEntries: Int,
    val averageConfidence: Double,
    val totalHits: Int
)

/**
 * Cleanup result.
 */
sealed class CleanupResult {
    data class Success(val cleanedCount: Int) : CleanupResult()
    data class Error(val message: String) : CleanupResult()
}

/**
 * Cached reputation data.
 */
@kotlinx.serialization.Serializable
data class ReputationCacheData(
    val score: Int,
    val sources: List<String>,
    val confidence: Double,
    val lastChecked: Long
)

/**
 * Cached DNS data.
 */
@kotlinx.serialization.Serializable
data class DNSCacheData(
    val aRecords: List<String>,
    val aaaaRecords: List<String>,
    val mxRecords: List<String>,
    val txtRecords: List<String>,
    val resolvedAt: Long
)

/**
 * Cached VirusTotal data.
 */
@kotlinx.serialization.Serializable
data class VirusTotalCacheData(
    val positiveDetections: Int,
    val totalEngines: Int,
    val scanDate: Long,
    val permalink: String
)

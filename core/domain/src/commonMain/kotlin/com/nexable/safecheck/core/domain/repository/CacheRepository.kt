package com.nexable.safecheck.core.domain.repository

import kotlinx.coroutines.flow.Flow

/**
 * Repository interface for managing cached data with TTL (Time To Live) support.
 * Used for caching external API responses and other temporary data.
 */
interface CacheRepository {
    
    /**
     * Stores a value in the cache with the specified TTL.
     * 
     * @param key Unique cache key
     * @param value The value to cache (as JSON string)
     * @param ttlMs Time to live in milliseconds
     */
    suspend fun put(key: String, value: String, ttlMs: Long)
    
    /**
     * Retrieves a value from the cache if it exists and hasn't expired.
     * 
     * @param key The cache key
     * @return The cached value if found and valid, null otherwise
     */
    suspend fun get(key: String): String?
    
    /**
     * Checks if a cache entry exists and is still valid.
     * 
     * @param key The cache key
     * @return true if the entry exists and hasn't expired
     */
    suspend fun exists(key: String): Boolean
    
    /**
     * Removes a specific cache entry.
     * 
     * @param key The cache key to remove
     * @return true if the entry was removed, false if it didn't exist
     */
    suspend fun remove(key: String): Boolean
    
    /**
     * Removes all cache entries matching the key pattern.
     * 
     * @param keyPattern Pattern to match (supports wildcards)
     * @return Number of entries removed
     */
    suspend fun removeByPattern(keyPattern: String): Int
    
    /**
     * Clears all expired cache entries.
     * 
     * @return Number of expired entries removed
     */
    suspend fun clearExpired(): Int
    
    /**
     * Clears all cache entries.
     * 
     * @return Number of entries removed
     */
    suspend fun clearAll(): Int
    
    /**
     * Gets the total size of the cache.
     * 
     * @return Number of cache entries
     */
    suspend fun size(): Int
    
    /**
     * Gets cache statistics as a flow.
     * 
     * @return Flow of cache statistics
     */
    fun getCacheStats(): Flow<CacheStats>
    
    /**
     * Updates the TTL for an existing cache entry.
     * 
     * @param key The cache key
     * @param newTtlMs New TTL in milliseconds
     * @return true if updated, false if key doesn't exist
     */
    suspend fun updateTtl(key: String, newTtlMs: Long): Boolean
    
    /**
     * Gets the remaining TTL for a cache entry.
     * 
     * @param key The cache key
     * @return Remaining TTL in milliseconds, null if key doesn't exist or has expired
     */
    suspend fun getRemainingTtl(key: String): Long?
}

/**
 * Data class representing cache statistics.
 */
data class CacheStats(
    val totalEntries: Int,
    val expiredEntries: Int,
    val hitCount: Long,
    val missCount: Long,
    val evictionCount: Long
) {
    val hitRate: Double
        get() = if (hitCount + missCount > 0) {
            hitCount.toDouble() / (hitCount + missCount)
        } else 0.0
}

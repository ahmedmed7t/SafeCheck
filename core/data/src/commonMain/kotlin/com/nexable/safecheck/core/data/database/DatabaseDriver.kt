package com.nexable.safecheck.core.data.database

import app.cash.sqldelight.db.SqlDriver

/**
 * Cross-platform database driver interface for SafeCheck database.
 */
expect class DatabaseDriverFactory {
    fun createDriver(): SqlDriver
}

/**
 * Database configuration for SafeCheck.
 */
data class DatabaseConfig(
    val databaseName: String = "safecheck.db",
    val enableEncryption: Boolean = true,
    val encryptionKey: String? = null,
    val enableWAL: Boolean = true,
    val busyTimeout: Long = 30_000L,
    val pageSize: Int = 4096,
    val cacheSize: Int = 2000,
    val enableForeignKeys: Boolean = true,
    val enableAutoVacuum: Boolean = true
)

/**
 * Database encryption utilities.
 */
object DatabaseEncryption {
    
    /**
     * Generates a secure encryption key for the database.
     */
    fun generateEncryptionKey(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..64)
            .map { chars.random() }
            .joinToString("")
    }
    
    /**
     * Encrypts sensitive data before storing in database.
     */
    fun encryptData(data: String, key: String): String {
        // Simple XOR encryption for demonstration
        // In production, use proper encryption like AES
        val keyBytes = key.toByteArray()
        val dataBytes = data.toByteArray()
        val encrypted = ByteArray(dataBytes.size)
        
        for (i in dataBytes.indices) {
            encrypted[i] = (dataBytes[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
        }
        
        return encrypted.joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Decrypts sensitive data from database.
     */
    fun decryptData(encryptedData: String, key: String): String {
        try {
            val keyBytes = key.toByteArray()
            val encryptedBytes = encryptedData.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
            
            val decrypted = ByteArray(encryptedBytes.size)
            
            for (i in encryptedBytes.indices) {
                decrypted[i] = (encryptedBytes[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            
            return String(decrypted)
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to decrypt data", e)
        }
    }
    
    /**
     * Validates encryption key format.
     */
    fun isValidEncryptionKey(key: String): Boolean {
        return key.length >= 32 && key.all { it.isLetterOrDigit() }
    }
}

/**
 * Database performance monitoring.
 */
class DatabasePerformanceMonitor {
    private val queryTimes = mutableMapOf<String, MutableList<Long>>()
    
    fun recordQueryTime(queryName: String, timeMs: Long) {
        queryTimes.getOrPut(queryName) { mutableListOf() }.add(timeMs)
        
        // Keep only last 100 measurements per query
        val times = queryTimes[queryName]!!
        if (times.size > 100) {
            times.removeFirst()
        }
    }
    
    fun getAverageQueryTime(queryName: String): Double? {
        val times = queryTimes[queryName]
        return times?.takeIf { it.isNotEmpty() }?.average()
    }
    
    fun getSlowQueries(thresholdMs: Long = 100): Map<String, Double> {
        return queryTimes.mapNotNull { (query, times) ->
            val avg = times.average()
            if (avg > thresholdMs) query to avg else null
        }.toMap()
    }
    
    fun reset() {
        queryTimes.clear()
    }
}

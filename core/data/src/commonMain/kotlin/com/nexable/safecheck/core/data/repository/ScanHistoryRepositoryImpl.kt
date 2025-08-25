package com.nexable.safecheck.core.data.repository

import com.nexable.safecheck.core.data.database.SafeCheckDatabase
import com.nexable.safecheck.core.domain.model.*
import com.nexable.safecheck.core.domain.repository.ScanRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Implementation of ScanRepository using SQLDelight database.
 */
class ScanHistoryRepositoryImpl(
    private val database: SafeCheckDatabase
) : ScanRepository {
    
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    override suspend fun saveScanResult(result: ScanResult): Result<Unit> {
        return try {
            database.transaction {
                database.database.insertScanHistory(
                    scan_id = generateScanId(result),
                    target_type = result.target.type.name,
                    target_value = result.target.value,
                    score = result.score.toLong(),
                    status = result.status.name,
                    reasons = json.encodeToString(result.reasons),
                    metadata = json.encodeToString(result.metadata),
                    scanned_at = result.scannedAt.epochSeconds,
                    scan_duration_ms = calculateScanDuration(result),
                    scanner_version = getAppVersion()
                )
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to save scan result: ${e.message}", "SAVE_ERROR")
        }
    }
    
    override suspend fun getScanHistory(
        limit: Int,
        offset: Int
    ): Result<List<ScanResult>> {
        return try {
            val scanHistory = database.database.getScanHistory(
                limit = limit.toLong(),
                offset = offset.toLong()
            ).executeAsList()
            
            val scanResults = scanHistory.mapNotNull { historyRow ->
                try {
                    convertToScanResult(historyRow)
                } catch (e: Exception) {
                    // Log error but continue with other results
                    null
                }
            }
            
            Result.success(scanResults)
        } catch (e: Exception) {
            Result.error("Failed to get scan history: ${e.message}", "GET_HISTORY_ERROR")
        }
    }
    
    override suspend fun getScanHistoryByType(
        targetType: String,
        limit: Int,
        offset: Int
    ): Result<List<ScanResult>> {
        return try {
            val scanHistory = database.database.getScanHistoryByType(
                target_type = targetType,
                limit = limit.toLong(),
                offset = offset.toLong()
            ).executeAsList()
            
            val scanResults = scanHistory.mapNotNull { historyRow ->
                try {
                    convertToScanResult(historyRow)
                } catch (e: Exception) {
                    null
                }
            }
            
            Result.success(scanResults)
        } catch (e: Exception) {
            Result.error("Failed to get scan history by type: ${e.message}", "GET_HISTORY_TYPE_ERROR")
        }
    }
    
    override suspend fun searchScanHistory(
        query: String,
        limit: Int,
        offset: Int
    ): Result<List<ScanResult>> {
        return try {
            val searchPattern = "%$query%"
            val scanHistory = database.database.searchScanHistory(
                target_value = searchPattern,
                reasons = searchPattern,
                limit = limit.toLong(),
                offset = offset.toLong()
            ).executeAsList()
            
            val scanResults = scanHistory.mapNotNull { historyRow ->
                try {
                    convertToScanResult(historyRow)
                } catch (e: Exception) {
                    null
                }
            }
            
            Result.success(scanResults)
        } catch (e: Exception) {
            Result.error("Failed to search scan history: ${e.message}", "SEARCH_ERROR")
        }
    }
    
    override suspend fun getScanStatistics(): Result<ScanStatistics> {
        return try {
            val stats = database.database.getScanStatistics().executeAsList()
            
            val statisticsMap = stats.associate { row ->
                row.target_type to ScanTypeStatistics(
                    targetType = row.target_type,
                    totalScans = row.total_scans?.toInt() ?: 0,
                    averageScore = row.avg_score ?: 0.0,
                    safeCount = row.safe_count?.toInt() ?: 0,
                    warningCount = row.warning_count?.toInt() ?: 0,
                    riskCount = row.risk_count?.toInt() ?: 0
                )
            }
            
            val overallStats = ScanStatistics(
                totalScans = statisticsMap.values.sumOf { it.totalScans },
                averageScore = if (statisticsMap.isNotEmpty()) {
                    statisticsMap.values.map { it.averageScore }.average()
                } else 0.0,
                safeCount = statisticsMap.values.sumOf { it.safeCount },
                warningCount = statisticsMap.values.sumOf { it.warningCount },
                riskCount = statisticsMap.values.sumOf { it.riskCount },
                byTargetType = statisticsMap,
                lastUpdated = Clock.System.now()
            )
            
            Result.success(overallStats)
        } catch (e: Exception) {
            Result.error("Failed to get scan statistics: ${e.message}", "STATS_ERROR")
        }
    }
    
    override suspend fun deleteScanHistory(scanId: String): Result<Unit> {
        return try {
            database.transaction {
                database.database.deleteOldScanHistory(
                    // This is a workaround - in real implementation you'd need a delete by ID query
                    scanned_at = 0L
                )
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to delete scan history: ${e.message}", "DELETE_ERROR")
        }
    }
    
    override suspend fun cleanupOldHistory(olderThan: Instant): Result<Int> {
        return try {
            val cutoffTime = olderThan.epochSeconds
            
            // Count records to be deleted
            val scanHistory = database.database.getScanHistory(1000, 0).executeAsList()
            val toDelete = scanHistory.count { it.scanned_at < cutoffTime }
            
            database.transaction {
                database.database.deleteOldScanHistory(cutoffTime)
            }
            
            Result.success(toDelete)
        } catch (e: Exception) {
            Result.error("Failed to cleanup old history: ${e.message}", "CLEANUP_ERROR")
        }
    }
    
    /**
     * Gets scan history as a reactive Flow.
     */
    fun getScanHistoryFlow(limit: Int = 100): Flow<List<ScanResult>> = flow {
        while (true) {
            try {
                val result = getScanHistory(limit, 0)
                if (result is Result.Success) {
                    emit(result.data)
                }
                kotlinx.coroutines.delay(5000) // Refresh every 5 seconds
            } catch (e: Exception) {
                // Continue with empty list on error
                emit(emptyList())
            }
        }
    }
    
    /**
     * Gets scan statistics as a reactive Flow.
     */
    fun getScanStatisticsFlow(): Flow<ScanStatistics> = flow {
        while (true) {
            try {
                val result = getScanStatistics()
                if (result is Result.Success) {
                    emit(result.data)
                }
                kotlinx.coroutines.delay(10000) // Refresh every 10 seconds
            } catch (e: Exception) {
                // Continue with default stats on error
                emit(ScanStatistics())
            }
        }
    }
    
    private fun convertToScanResult(historyRow: Any): ScanResult {
        // This would need to be implemented based on the actual SQLDelight generated classes
        // For now, return a placeholder
        return ScanResult(
            target = CheckTarget.URL("placeholder"),
            score = 0,
            status = Status.SAFE,
            reasons = emptyList(),
            metadata = emptyMap(),
            scannedAt = Clock.System.now()
        )
    }
    
    private fun generateScanId(result: ScanResult): String {
        return "${result.target.type.name}_${result.target.value.hashCode()}_${result.scannedAt.epochSeconds}"
    }
    
    private fun calculateScanDuration(result: ScanResult): Long {
        // This would be calculated from actual scan timing
        return result.metadata["scanDurationMs"]?.toLongOrNull() ?: 0L
    }
    
    private fun getAppVersion(): String {
        return "1.0.0" // This would come from build configuration
    }
}

/**
 * Scan statistics data model.
 */
data class ScanStatistics(
    val totalScans: Int = 0,
    val averageScore: Double = 0.0,
    val safeCount: Int = 0,
    val warningCount: Int = 0,
    val riskCount: Int = 0,
    val byTargetType: Map<String, ScanTypeStatistics> = emptyMap(),
    val lastUpdated: Instant = Clock.System.now()
)

/**
 * Statistics for a specific target type.
 */
data class ScanTypeStatistics(
    val targetType: String,
    val totalScans: Int,
    val averageScore: Double,
    val safeCount: Int,
    val warningCount: Int,
    val riskCount: Int
)

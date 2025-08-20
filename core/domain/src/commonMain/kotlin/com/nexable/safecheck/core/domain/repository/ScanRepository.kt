package com.nexable.safecheck.core.domain.repository

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.ScanResult
import kotlinx.coroutines.flow.Flow

/**
 * Repository interface for managing scan results and history.
 * Provides data access methods for storing, retrieving, and managing scan results.
 */
interface ScanRepository {
    
    /**
     * Saves a scan result to persistent storage.
     * 
     * @param result The scan result to save
     */
    suspend fun saveScanResult(result: ScanResult)
    
    /**
     * Retrieves a scan result by its unique ID.
     * 
     * @param scanId The unique scan ID
     * @return The scan result if found, null otherwise
     */
    suspend fun getScanResultById(scanId: String): ScanResult?
    
    /**
     * Retrieves the most recent scan result for a specific target.
     * 
     * @param target The target that was scanned
     * @return The most recent scan result for the target, null if none found
     */
    suspend fun getLatestScanForTarget(target: CheckTarget): ScanResult?
    
    /**
     * Gets all scan results as a flow, ordered by timestamp (newest first).
     * 
     * @return Flow of all scan results
     */
    fun getAllScanResults(): Flow<List<ScanResult>>
    
    /**
     * Gets scan results with pagination support.
     * 
     * @param limit Maximum number of results to return
     * @param offset Number of results to skip
     * @return List of scan results
     */
    suspend fun getScanResults(limit: Int, offset: Int): List<ScanResult>
    
    /**
     * Searches scan results by target value (supports partial matching).
     * 
     * @param query Search query string
     * @return Flow of matching scan results
     */
    fun searchScanResults(query: String): Flow<List<ScanResult>>
    
    /**
     * Gets scan results filtered by status.
     * 
     * @param status The status to filter by
     * @return Flow of scan results with the specified status
     */
    fun getScanResultsByStatus(status: com.nexable.safecheck.core.domain.model.Status): Flow<List<ScanResult>>
    
    /**
     * Gets scan results for a specific target type.
     * 
     * @param targetType The type of target ("URL", "EMAIL", "FILE_HASH")
     * @return Flow of scan results for the specified target type
     */
    fun getScanResultsByTargetType(targetType: String): Flow<List<ScanResult>>
    
    /**
     * Deletes a scan result by its ID.
     * 
     * @param scanId The unique scan ID to delete
     * @return true if deleted, false if not found
     */
    suspend fun deleteScanResult(scanId: String): Boolean
    
    /**
     * Deletes all scan results for a specific target.
     * 
     * @param target The target whose scan results should be deleted
     * @return Number of scan results deleted
     */
    suspend fun deleteScanResultsForTarget(target: CheckTarget): Int
    
    /**
     * Deletes all scan results.
     * 
     * @return Number of scan results deleted
     */
    suspend fun deleteAllScanResults(): Int
    
    /**
     * Deletes scan results older than the specified timestamp.
     * 
     * @param olderThanMs Timestamp in milliseconds (epoch time)
     * @return Number of scan results deleted
     */
    suspend fun deleteOldScanResults(olderThanMs: Long): Int
    
    /**
     * Gets the total count of scan results.
     * 
     * @return Total number of scan results stored
     */
    suspend fun getScanResultCount(): Int
    
    /**
     * Checks if a recent scan exists for the target (within specified time).
     * 
     * @param target The target to check
     * @param withinMs Time window in milliseconds
     * @return true if a recent scan exists
     */
    suspend fun hasRecentScan(target: CheckTarget, withinMs: Long): Boolean
}

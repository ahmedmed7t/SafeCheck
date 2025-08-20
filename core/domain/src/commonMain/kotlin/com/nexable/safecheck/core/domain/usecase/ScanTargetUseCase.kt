package com.nexable.safecheck.core.domain.usecase

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.ScanResult
import com.nexable.safecheck.core.domain.model.isRecent
import com.nexable.safecheck.core.domain.model.isSafe
import com.nexable.safecheck.core.domain.model.isRisky
import com.nexable.safecheck.core.domain.repository.ScanRepository
import com.nexable.safecheck.core.domain.util.InputValidator

/**
 * Use case for scanning a target and managing scan results.
 * Coordinates validation, scanning, and persistence operations.
 */
class ScanTargetUseCase(
    private val scanRepository: ScanRepository
) {
    
    /**
     * Result of target validation and preparation for scanning.
     */
    sealed class ValidationResult {
        data class Valid(val target: CheckTarget) : ValidationResult()
        data class Invalid(val error: String) : ValidationResult()
    }
    
    /**
     * Result of the scan operation.
     */
    sealed class ScanResult {
        data class Success(val result: com.nexable.safecheck.core.domain.model.ScanResult) : ScanResult()
        data class Error(val message: String, val cause: Throwable? = null) : ScanResult()
        data class Cached(val result: com.nexable.safecheck.core.domain.model.ScanResult) : ScanResult()
    }
    
    /**
     * Validates the input string and converts it to a CheckTarget.
     * 
     * @param input Raw input string from user
     * @return ValidationResult indicating success or failure
     */
    fun validateInput(input: String): ValidationResult {
        if (input.isBlank()) {
            return ValidationResult.Invalid("Input cannot be empty")
        }
        
        val target = InputValidator.createNormalizedTarget(input)
            ?: return ValidationResult.Invalid(
                "Invalid input format. ${InputValidator.supportedInputsDescription}"
            )
        
        return ValidationResult.Valid(target)
    }
    
    /**
     * Checks if a recent scan exists for the given target.
     * 
     * @param target The target to check
     * @param maxAgeMs Maximum age in milliseconds to consider "recent"
     * @return The recent scan result if found, null otherwise
     */
    suspend fun getRecentScan(target: CheckTarget, maxAgeMs: Long = 300_000): com.nexable.safecheck.core.domain.model.ScanResult? {
        val latest = scanRepository.getLatestScanForTarget(target)
        return if (latest?.isRecent(maxAgeMs) == true) latest else null
    }
    
    /**
     * Saves a scan result to the repository.
     * 
     * @param scanResult The scan result to save
     */
    suspend fun saveScanResult(scanResult: com.nexable.safecheck.core.domain.model.ScanResult) {
        scanRepository.saveScanResult(scanResult)
    }
    
    /**
     * Gets the scan history for a specific target.
     * 
     * @param target The target to get history for
     * @return List of scan results for the target (newest first)
     */
    suspend fun getScanHistory(target: CheckTarget): List<com.nexable.safecheck.core.domain.model.ScanResult> {
        // This would typically involve filtering by target
        // For now, we'll get all results and filter
        return scanRepository.getScanResults(limit = 100, offset = 0)
            .filter { it.target == target }
    }
    
    /**
     * Deletes scan results for a specific target.
     * 
     * @param target The target whose scan results should be deleted
     * @return Number of scan results deleted
     */
    suspend fun deleteScanHistory(target: CheckTarget): Int {
        return scanRepository.deleteScanResultsForTarget(target)
    }
    
    /**
     * Gets summary statistics for all scans.
     * 
     * @return ScanSummary with statistics
     */
    suspend fun getScanSummary(): ScanSummary {
        val allResults = scanRepository.getScanResults(limit = Int.MAX_VALUE, offset = 0)
        
        return ScanSummary(
            totalScans = allResults.size,
            safeCount = allResults.count { it.isSafe },
            cautionCount = allResults.count { it.status == com.nexable.safecheck.core.domain.model.Status.CAUTION },
            riskCount = allResults.count { it.isRisky },
            urlScans = allResults.count { it.target is CheckTarget.Url },
            emailScans = allResults.count { it.target is CheckTarget.Email },
            fileScans = allResults.count { it.target is CheckTarget.FileHash },
            averageScore = if (allResults.isNotEmpty()) allResults.map { it.score }.average() else 0.0
        )
    }
}

/**
 * Summary statistics for scan operations.
 */
data class ScanSummary(
    val totalScans: Int,
    val safeCount: Int,
    val cautionCount: Int,
    val riskCount: Int,
    val urlScans: Int,
    val emailScans: Int,
    val fileScans: Int,
    val averageScore: Double
)

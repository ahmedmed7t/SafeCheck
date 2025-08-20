package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.model.ScanResult

/**
 * Generic scanner interface for different types of security targets.
 * Each scanner implementation handles specific target types and their unique security checks.
 */
interface Scanner<T : CheckTarget> {
    
    /**
     * Scans the given target and returns a detailed security result.
     * 
     * @param target The target to scan (URL, Email, or FileHash)
     * @return Result containing ScanResult on success or error details on failure
     */
    suspend fun scan(target: T): Result<ScanResult>
    
    /**
     * Performs a quick validation check without full scanning.
     * Useful for input validation before expensive scan operations.
     * 
     * @param target The target to validate
     * @return Result indicating if the target is valid for scanning
     */
    suspend fun validate(target: T): Result<Boolean>
    
    /**
     * Gets the scanner configuration and capabilities.
     * 
     * @return ScannerInfo with details about this scanner
     */
    fun getInfo(): ScannerInfo
    
    /**
     * Checks if the scanner supports the given target type.
     * 
     * @param target The target to check
     * @return true if this scanner can handle the target
     */
    fun supports(target: CheckTarget): Boolean
}

/**
 * Information about a scanner's capabilities and configuration.
 */
data class ScannerInfo(
    val name: String,
    val version: String,
    val supportedTargetTypes: List<String>,
    val description: String,
    val requiresNetwork: Boolean = false,
    val averageScanTimeMs: Long = 1000,
    val maxConcurrentScans: Int = 5
)

/**
 * Base class for scanner implementations with common functionality.
 */
abstract class BaseScanner<T : CheckTarget> : Scanner<T> {
    
    protected abstract val scannerInfo: ScannerInfo
    
    override fun getInfo(): ScannerInfo = scannerInfo
    
    /**
     * Template method for scan operation with error handling.
     */
    override suspend fun scan(target: T): Result<ScanResult> {
        return try {
            // Validate first
            when (val validationResult = validate(target)) {
                is Result.Error -> return validationResult
                is Result.Loading -> return Result.loading()
                is Result.Success -> {
                    if (!validationResult.data) {
                        return Result.error("Target validation failed")
                    }
                }
            }
            
            // Perform the actual scan
            performScan(target)
        } catch (e: Exception) {
            Result.error(
                message = "Scan failed: ${e.message}",
                code = "SCAN_ERROR",
                details = mapOf(
                    "scanner" to scannerInfo.name,
                    "target" to target.toString(),
                    "exception" to e::class.simpleName.orEmpty()
                )
            )
        }
    }
    
    /**
     * Abstract method for actual scan implementation.
     * Subclasses implement their specific scanning logic here.
     */
    protected abstract suspend fun performScan(target: T): Result<ScanResult>
    
    /**
     * Default validation implementation - can be overridden by subclasses.
     */
    override suspend fun validate(target: T): Result<Boolean> {
        return Result.success(supports(target))
    }
}

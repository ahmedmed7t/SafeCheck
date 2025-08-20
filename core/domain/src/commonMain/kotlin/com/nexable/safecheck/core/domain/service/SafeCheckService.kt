package com.nexable.safecheck.core.domain.service

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.model.ScanResult
import com.nexable.safecheck.core.domain.model.isRecent
import com.nexable.safecheck.core.domain.repository.ScanRepository
import com.nexable.safecheck.core.domain.scanner.Scanner
import com.nexable.safecheck.core.domain.util.InputValidator
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.datetime.Clock

/**
 * Main orchestrator service for SafeCheck operations.
 * Coordinates input detection, scanner selection, scanning, and result persistence.
 */
class SafeCheckService(
    private val urlScanner: Scanner<CheckTarget.Url>,
    private val emailScanner: Scanner<CheckTarget.Email>,
    private val fileHashScanner: Scanner<CheckTarget.FileHash>,
    private val scanRepository: ScanRepository
) {
    
    /**
     * Comprehensive scan result including detection and scan phases.
     */
    data class ScanResponse(
        val detectedTarget: CheckTarget?,
        val scanResult: ScanResult?,
        val error: String? = null,
        val processingTimeMs: Long = 0
    )
    
    /**
     * Scans raw input by auto-detecting type and routing to appropriate scanner.
     * 
     * @param rawInput The raw string input from user
     * @param saveResult Whether to save the result to repository (default: true)
     * @param useCache Whether to check for recent cached results (default: true)
     * @return Flow of ScanResponse with progress updates
     */
    fun scanInput(
        rawInput: String,
        saveResult: Boolean = true,
        useCache: Boolean = true
    ): Flow<Result<ScanResponse>> = flow {
        val startTime = Clock.System.now().toEpochMilliseconds()
        
        emit(Result.loading())
        
        try {
            // Step 1: Input validation and type detection
            val target = InputValidator.createNormalizedTarget(rawInput)
            if (target == null) {
                emit(Result.error(
                    message = "Invalid input format",
                    code = "INVALID_INPUT",
                    details = mapOf(
                        "input" to rawInput,
                        "supported" to InputValidator.supportedInputsDescription
                    )
                ))
                return@flow
            }
            
            // Step 2: Check for recent cached result if requested
            if (useCache) {
                val recentResult = scanRepository.getLatestScanForTarget(target)
                if (recentResult?.isRecent(300_000) == true) { // 5 minutes cache
                    val processingTime = Clock.System.now().toEpochMilliseconds() - startTime
                    emit(Result.success(
                        ScanResponse(
                            detectedTarget = target,
                            scanResult = recentResult,
                            processingTimeMs = processingTime
                        )
                    ))
                    return@flow
                }
            }
            
            // Step 3: Select appropriate scanner and perform scan
            val scanResult = when (target) {
                is CheckTarget.Url -> urlScanner.scan(target)
                is CheckTarget.Email -> emailScanner.scan(target)
                is CheckTarget.FileHash -> fileHashScanner.scan(target)
            }
            
            when (scanResult) {
                is Result.Success -> {
                    // Step 4: Save result if requested
                    if (saveResult) {
                        scanRepository.saveScanResult(scanResult.data)
                    }
                    
                    val processingTime = Clock.System.now().toEpochMilliseconds() - startTime
                    emit(Result.success(
                        ScanResponse(
                            detectedTarget = target,
                            scanResult = scanResult.data,
                            processingTimeMs = processingTime
                        )
                    ))
                }
                
                is Result.Error -> {
                    emit(Result.error(
                        message = "Scan failed: ${scanResult.message}",
                        code = scanResult.code ?: "SCAN_FAILED",
                        details = scanResult.details + mapOf("target" to target.toString())
                    ))
                }
                
                is Result.Loading -> {
                    emit(Result.loading())
                }
            }
            
        } catch (e: Exception) {
            emit(Result.error(
                message = "Service error: ${e.message}",
                code = "SERVICE_ERROR",
                details = mapOf(
                    "input" to rawInput,
                    "exception" to e::class.simpleName.orEmpty()
                )
            ))
        }
    }
    
    /**
     * Rescans a previously scanned target with the latest scanning logic.
     * 
     * @param target The target to rescan
     * @param saveResult Whether to save the new result
     * @return Flow of scan progress and result
     */
    fun rescanTarget(
        target: CheckTarget,
        saveResult: Boolean = true
    ): Flow<Result<ScanResponse>> = flow {
        emit(Result.loading())
        
        val startTime = Clock.System.now().toEpochMilliseconds()
        
        try {
            val scanResult = when (target) {
                is CheckTarget.Url -> urlScanner.scan(target)
                is CheckTarget.Email -> emailScanner.scan(target)
                is CheckTarget.FileHash -> fileHashScanner.scan(target)
            }
            
            when (scanResult) {
                is Result.Success -> {
                    if (saveResult) {
                        scanRepository.saveScanResult(scanResult.data)
                    }
                    
                    val processingTime = Clock.System.now().toEpochMilliseconds() - startTime
                    emit(Result.success(
                        ScanResponse(
                            detectedTarget = target,
                            scanResult = scanResult.data,
                            processingTimeMs = processingTime
                        )
                    ))
                }
                
                is Result.Error -> {
                    emit(Result.error(
                        message = "Rescan failed: ${scanResult.message}",
                        code = scanResult.code ?: "RESCAN_FAILED",
                        details = scanResult.details
                    ))
                }
                
                is Result.Loading -> {
                    emit(Result.loading())
                }
            }
            
        } catch (e: Exception) {
            emit(Result.error(
                message = "Rescan error: ${e.message}",
                code = "RESCAN_ERROR",
                details = mapOf(
                    "target" to target.toString(),
                    "exception" to e::class.simpleName.orEmpty()
                )
            ))
        }
    }
    
    /**
     * Validates input without performing a full scan.
     * 
     * @param rawInput The input to validate
     * @return ValidationResult with target type or error
     */
    suspend fun validateInput(rawInput: String): ValidationResult {
        return try {
            val target = InputValidator.createNormalizedTarget(rawInput)
            if (target != null) {
                ValidationResult.Valid(target)
            } else {
                ValidationResult.Invalid("Unsupported input format. ${InputValidator.supportedInputsDescription}")
            }
        } catch (e: Exception) {
            ValidationResult.Invalid("Validation error: ${e.message}")
        }
    }
    
    /**
     * Gets scan history for a specific target.
     * 
     * @param target The target to get history for
     * @return Flow of scan results for the target
     */
    fun getScanHistory(target: CheckTarget): Flow<List<ScanResult>> {
        return scanRepository.getAllScanResults()
    }
    
    /**
     * Gets all scan results with optional filtering.
     * 
     * @return Flow of all scan results
     */
    fun getAllScanResults(): Flow<List<ScanResult>> {
        return scanRepository.getAllScanResults()
    }
    
    /**
     * Deletes scan history for a specific target.
     * 
     * @param target The target whose history should be deleted
     * @return Number of deleted scan results
     */
    suspend fun deleteScanHistory(target: CheckTarget): Int {
        return scanRepository.deleteScanResultsForTarget(target)
    }
    
    /**
     * Clears all scan history.
     * 
     * @return Number of deleted scan results
     */
    suspend fun clearAllHistory(): Int {
        return scanRepository.deleteAllScanResults()
    }
    
    /**
     * Gets service status and scanner information.
     * 
     * @return ServiceStatus with current state
     */
    suspend fun getServiceStatus(): ServiceStatus {
        val totalScans = scanRepository.getScanResultCount()
        
        return ServiceStatus(
            isHealthy = true,
            totalScans = totalScans,
            availableScanners = listOf(
                urlScanner.getInfo(),
                emailScanner.getInfo(),
                fileHashScanner.getInfo()
            ),
            supportedInputTypes = listOf("URL", "EMAIL", "FILE_HASH")
        )
    }
}

/**
 * Result of input validation.
 */
sealed class ValidationResult {
    data class Valid(val target: CheckTarget) : ValidationResult()
    data class Invalid(val reason: String) : ValidationResult()
}

/**
 * Service status information.
 */
data class ServiceStatus(
    val isHealthy: Boolean,
    val totalScans: Int,
    val availableScanners: List<com.nexable.safecheck.core.domain.scanner.ScannerInfo>,
    val supportedInputTypes: List<String>,
    val lastError: String? = null
)

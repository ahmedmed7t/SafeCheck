package com.nexable.safecheck.core.domain.model

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

/**
 * Represents the complete result of a security scan operation.
 * Contains the target, calculated score, status, reasons, and metadata.
 */
@Serializable
data class ScanResult(
    /**
     * The target that was scanned (URL, Email, or FileHash)
     */
    val target: CheckTarget,
    
    /**
     * The calculated security score (0-100)
     * Higher scores indicate better security
     */
    val score: Int,
    
    /**
     * The status classification based on the score
     */
    val status: Status,
    
    /**
     * List of reasons explaining the score calculation
     * Ordered by impact (most significant first)
     */
    val reasons: List<Reason>,
    
    /**
     * Additional metadata collected during scanning
     * Examples: finalUrl, host, domainAgeDays, certExpiryDays, IPs, etc.
     */
    val metadata: Map<String, String> = emptyMap(),
    
    /**
     * UTC timestamp when the scan was performed
     */
    val timestampUtc: Instant = Clock.System.now(),
    
    /**
     * Unique identifier for this scan result
     */
    val scanId: String = generateScanId()
) {
    init {
        require(score in 0..100) { "Score must be between 0 and 100, got $score" }
        require(reasons.isNotEmpty()) { "At least one reason must be provided" }
        require(status == Status.fromScore(score)) { 
            "Status $status does not match score $score" 
        }
    }
    
    companion object {
        /**
         * Generates a unique scan ID
         */
        private fun generateScanId(): String {
            return "scan_${Clock.System.now().toEpochMilliseconds()}_${(1000..9999).random()}"
        }
    }
}

/**
 * Extension property to get the top 3 most significant reasons
 */
val ScanResult.topReasons: List<Reason>
    get() = reasons.sortedBy { kotlin.math.abs(it.delta) }.reversed().take(3)

/**
 * Extension property to check if this scan result indicates a safe target
 */
val ScanResult.isSafe: Boolean
    get() = status == Status.SAFE

/**
 * Extension property to check if this scan result indicates a risky target
 */
val ScanResult.isRisky: Boolean
    get() = status == Status.RISK

/**
 * Extension property to get the scan age in milliseconds
 */
val ScanResult.ageMs: Long
    get() = Clock.System.now().toEpochMilliseconds() - timestampUtc.toEpochMilliseconds()

/**
 * Extension function to check if the scan result is recent (within specified milliseconds)
 */
fun ScanResult.isRecent(withinMs: Long): Boolean = ageMs <= withinMs

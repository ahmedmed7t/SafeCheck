package com.nexable.safecheck.core.domain.model

/**
 * Core scoring engine that calculates security scores and determines status classifications.
 * Applies reasons to a base score and ensures the result stays within valid bounds.
 */
class ScoreEngine {
    
    companion object {
        private const val MIN_SCORE = 0
        private const val MAX_SCORE = 100
        private const val DEFAULT_BASE_SCORE = 100
        
        // Status thresholds as defined in the specification
        private const val SAFE_THRESHOLD = 85
        private const val CAUTION_THRESHOLD = 60
    }
    
    /**
     * Applies a list of reasons to a base score and returns the final calculated score.
     * The score is clamped between 0 and 100.
     * 
     * @param base The starting score (default 100)
     * @param reasons List of reasons with score deltas
     * @return The final calculated score (0-100)
     */
    fun apply(base: Int = DEFAULT_BASE_SCORE, reasons: List<Reason>): Int {
        require(base in MIN_SCORE..MAX_SCORE) { 
            "Base score must be between $MIN_SCORE and $MAX_SCORE, got $base" 
        }
        
        val totalDelta = reasons.sumOf { it.delta }
        val finalScore = base + totalDelta
        
        return finalScore.coerceIn(MIN_SCORE, MAX_SCORE)
    }
    
    /**
     * Classifies a score into a security status.
     * 
     * @param score The security score (0-100)
     * @return The corresponding Status (SAFE, CAUTION, or RISK)
     */
    fun classify(score: Int): Status {
        require(score in MIN_SCORE..MAX_SCORE) { 
            "Score must be between $MIN_SCORE and $MAX_SCORE, got $score" 
        }
        
        return when {
            score >= SAFE_THRESHOLD -> Status.SAFE
            score >= CAUTION_THRESHOLD -> Status.CAUTION
            else -> Status.RISK
        }
    }
    
    /**
     * Calculates score and status from a base score and reasons in one operation.
     * 
     * @param base The starting score (default 100)
     * @param reasons List of reasons with score deltas
     * @return Pair of (finalScore, status)
     */
    fun calculateScoreAndStatus(base: Int = DEFAULT_BASE_SCORE, reasons: List<Reason>): Pair<Int, Status> {
        val score = apply(base, reasons)
        val status = classify(score)
        return score to status
    }
    
    /**
     * Validates that a list of reasons is suitable for scoring.
     * 
     * @param reasons List of reasons to validate
     * @throws IllegalArgumentException if validation fails
     */
    fun validateReasons(reasons: List<Reason>) {
        require(reasons.isNotEmpty()) { "At least one reason must be provided" }
        
        val totalDelta = reasons.sumOf { it.delta }
        require(totalDelta >= -MAX_SCORE) { 
            "Total negative delta cannot exceed $MAX_SCORE (got ${-totalDelta})" 
        }
        
        // Check for duplicate reason codes
        val duplicateCodes = reasons.groupBy { it.code }.filter { it.value.size > 1 }.keys
        require(duplicateCodes.isEmpty()) { 
            "Duplicate reason codes found: $duplicateCodes" 
        }
    }
    
    /**
     * Creates a complete scan result from target, base score, and reasons.
     * 
     * @param target The scan target
     * @param base The base score (default 100)
     * @param reasons List of reasons
     * @param metadata Optional metadata map
     * @return Complete ScanResult
     */
    fun createScanResult(
        target: CheckTarget,
        base: Int = DEFAULT_BASE_SCORE,
        reasons: List<Reason>,
        metadata: Map<String, String> = emptyMap()
    ): ScanResult {
        validateReasons(reasons)
        
        val (score, status) = calculateScoreAndStatus(base, reasons)
        
        return ScanResult(
            target = target,
            score = score,
            status = status,
            reasons = reasons.sortedByDescending { kotlin.math.abs(it.delta) }, // Most significant first
            metadata = metadata
        )
    }
}

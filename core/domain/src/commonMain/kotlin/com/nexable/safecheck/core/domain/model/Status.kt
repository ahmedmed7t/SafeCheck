package com.nexable.safecheck.core.domain.model

import kotlinx.serialization.Serializable

/**
 * Enum representing the security status based on the calculated score.
 * Status thresholds: SAFE ≥85, CAUTION 60-84, RISK <60
 */
@Serializable
enum class Status {
    /**
     * Safe status - score 85 or higher
     * Indicates the target is likely safe to trust
     */
    SAFE,
    
    /**
     * Caution status - score 60-84
     * Indicates the target should be approached with caution
     */
    CAUTION,
    
    /**
     * Risk status - score below 60
     * Indicates the target poses potential security risks
     */
    RISK;
    
    companion object {
        /**
         * Determines the status based on the security score
         * @param score The security score (0-100)
         * @return The corresponding Status
         */
        fun fromScore(score: Int): Status = when {
            score >= 85 -> SAFE
            score >= 60 -> CAUTION
            else -> RISK
        }
        
        /**
         * Gets the minimum score threshold for this status
         */
        val Status.minScore: Int
            get() = when (this) {
                SAFE -> 85
                CAUTION -> 60
                RISK -> 0
            }
        
        /**
         * Gets the maximum score threshold for this status
         */
        val Status.maxScore: Int
            get() = when (this) {
                SAFE -> 100
                CAUTION -> 84
                RISK -> 59
            }
    }
}

/**
 * Extension property to get a human-readable description of the status
 */
val Status.description: String
    get() = when (this) {
        Status.SAFE -> "Safe to trust"
        Status.CAUTION -> "Approach with caution"
        Status.RISK -> "Potential security risk"
    }

/**
 * Extension property to get the color representation for UI
 */
val Status.colorName: String
    get() = when (this) {
        Status.SAFE -> "GREEN"
        Status.CAUTION -> "YELLOW"
        Status.RISK -> "RED"
    }

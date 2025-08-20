package com.nexable.safecheck.core.domain.model

import kotlinx.serialization.Serializable

/**
 * Represents a reason for the security score adjustment with a specific code, message, and score delta.
 * Reasons explain why the score was increased or decreased during scanning.
 */
@Serializable
data class Reason(
    /**
     * Unique code identifying the type of reason (e.g., "DOMAIN_AGE", "NO_HTTPS", "MALICIOUS_HASH")
     */
    val code: String,
    
    /**
     * Human-readable message explaining the reason (e.g., "Domain age 4 days", "No HTTPS connection")
     */
    val message: String,
    
    /**
     * Score delta applied to the base score (-100 to +100)
     * Negative values decrease security score, positive values increase it
     */
    val delta: Int
) {
    init {
        require(code.isNotBlank()) { "Reason code cannot be blank" }
        require(message.isNotBlank()) { "Reason message cannot be blank" }
        require(delta in -100..100) { "Reason delta must be between -100 and +100" }
    }
}

/**
 * Extension property to check if this reason has a negative impact on security
 */
val Reason.isNegative: Boolean
    get() = delta < 0

/**
 * Extension property to check if this reason has a positive impact on security
 */
val Reason.isPositive: Boolean
    get() = delta > 0

/**
 * Extension property to check if this reason is neutral (no score impact)
 */
val Reason.isNeutral: Boolean
    get() = delta == 0

package com.nexable.safecheck.core.domain.model

import kotlinx.serialization.Serializable

/**
 * Sealed interface representing the different types of targets that can be scanned for safety.
 * Each target type has specific validation and scanning requirements.
 */
@Serializable
sealed interface CheckTarget {
    
    /**
     * URL target for scanning web links
     * @param value The URL string to be validated and scanned
     */
    @Serializable
    data class Url(val value: String) : CheckTarget
    
    /**
     * Email target for scanning email addresses
     * @param value The email address string to be validated and scanned
     */
    @Serializable
    data class Email(val value: String) : CheckTarget
    
    /**
     * File hash target for scanning file SHA-256 hashes
     * @param sha256 The SHA-256 hash string (64 hex characters)
     */
    @Serializable
    data class FileHash(val sha256: String) : CheckTarget
}

/**
 * Extension property to get the raw string value from any CheckTarget
 */
val CheckTarget.rawValue: String
    get() = when (this) {
        is CheckTarget.Url -> value
        is CheckTarget.Email -> value
        is CheckTarget.FileHash -> sha256
    }

/**
 * Extension property to get the target type as a string
 */
val CheckTarget.type: String
    get() = when (this) {
        is CheckTarget.Url -> "URL"
        is CheckTarget.Email -> "EMAIL"
        is CheckTarget.FileHash -> "FILE_HASH"
    }

package com.nexable.safecheck.core.platform.clipboard

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.datetime.Clock

/**
 * Platform-specific clipboard access interface.
 * Provides clipboard reading and writing capabilities.
 */
expect class ClipboardManager() {
    
    /**
     * Reads text content from the clipboard.
     * 
     * @return Result containing clipboard text or null if empty
     */
    suspend fun readText(): Result<String?>
    
    /**
     * Writes text content to the clipboard.
     * 
     * @param text The text to write to clipboard
     * @return Result indicating success or failure
     */
    suspend fun writeText(text: String): Result<Unit>
    
    /**
     * Checks if the clipboard contains text content.
     * 
     * @return Result indicating if clipboard has text
     */
    suspend fun hasText(): Result<Boolean>
    
    /**
     * Clears the clipboard content.
     * 
     * @return Result indicating success or failure
     */
    suspend fun clear(): Result<Unit>
}

/**
 * Clipboard content information.
 */
data class ClipboardContent(
    val text: String?,
    val hasText: Boolean,
    val contentType: ClipboardContentType,
    val timestamp: Long = Clock.System.now().toEpochMilliseconds()
)

/**
 * Types of clipboard content.
 */
enum class ClipboardContentType {
    TEXT,
    URL,
    EMAIL,
    EMPTY,
    UNSUPPORTED
}

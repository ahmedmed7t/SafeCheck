package com.nexable.safecheck.core.platform.clipboard

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import platform.Foundation.*
import platform.UIKit.*

/**
 * iOS implementation of clipboard manager using UIPasteboard.
 * Includes proper privacy handling for iOS clipboard access.
 */
actual class ClipboardManager {
    
    private val pasteboard = UIPasteboard.generalPasteboard
    
    actual suspend fun readText(): Result<String?> {
        return withContext(Dispatchers.Main) {
            try {
                // Check if pasteboard has string content
                if (!pasteboard.hasStrings) {
                    return@withContext Result.success(null)
                }
                
                // Read string from pasteboard
                val text = pasteboard.string
                
                Result.success(text)
            } catch (e: Exception) {
                Result.error("Failed to read clipboard: ${e.message}", "CLIPBOARD_READ_FAILED")
            }
        }
    }
    
    actual suspend fun writeText(text: String): Result<Unit> {
        return withContext(Dispatchers.Main) {
            try {
                // Write string to pasteboard
                pasteboard.string = text
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to write to clipboard: ${e.message}", "CLIPBOARD_WRITE_FAILED")
            }
        }
    }
    
    actual suspend fun hasText(): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                val hasText = pasteboard.hasStrings
                Result.success(hasText)
            } catch (e: Exception) {
                Result.error("Failed to check clipboard: ${e.message}", "CLIPBOARD_CHECK_FAILED")
            }
        }
    }
    
    actual suspend fun clear(): Result<Unit> {
        return withContext(Dispatchers.Main) {
            try {
                // Clear the pasteboard by setting empty items
                pasteboard.items = emptyList<Map<Any?, *>>()
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to clear clipboard: ${e.message}", "CLIPBOARD_CLEAR_FAILED")
            }
        }
    }
    
    /**
     * Gets clipboard content with type detection and privacy consideration.
     * iOS automatically shows privacy indicators when apps access the clipboard.
     */
    suspend fun getClipboardContent(): Result<ClipboardContent> {
        return withContext(Dispatchers.Main) {
            try {
                val hasTextResult = hasText()
                val textResult = readText()
                
                val hasText = when (hasTextResult) {
                    is Result.Success -> hasTextResult.data
                    else -> false
                }
                val text = when (textResult) {
                    is Result.Success -> textResult.data
                    else -> null
                }
                
                val contentType = when {
                    text == null -> ClipboardContentType.EMPTY
                    text.startsWith("http://") || text.startsWith("https://") -> ClipboardContentType.URL
                    text.contains("@") && text.contains(".") -> ClipboardContentType.EMAIL
                    hasText -> ClipboardContentType.TEXT
                    else -> ClipboardContentType.UNSUPPORTED
                }
                
                val content = ClipboardContent(
                    text = text,
                    hasText = hasText,
                    contentType = contentType
                )
                
                Result.success(content)
            } catch (e: Exception) {
                Result.error("Failed to get clipboard content: ${e.message}", "CLIPBOARD_CONTENT_FAILED")
            }
        }
    }
    
    /**
     * Checks if clipboard access permission is granted.
     * iOS 14+ automatically grants clipboard access but shows privacy indicators.
     */
    suspend fun hasClipboardPermission(): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                // iOS doesn't require explicit permission for clipboard access
                // but apps must declare usage in Info.plist for App Store submission
                Result.success(true)
            } catch (e: Exception) {
                Result.error("Failed to check clipboard permission: ${e.message}", "CLIPBOARD_PERMISSION_CHECK_FAILED")
            }
        }
    }
    
    /**
     * Shows privacy-conscious clipboard access prompt to user.
     * This is a best practice to inform users before accessing clipboard.
     */
    suspend fun requestClipboardAccess(reason: String): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                // In a real app, you might show an alert explaining why you need clipboard access
                // iOS will automatically show privacy indicators when clipboard is accessed
                
                // For now, we'll just return true as iOS doesn't require explicit permission
                Result.success(true)
            } catch (e: Exception) {
                Result.error("Failed to request clipboard access: ${e.message}", "CLIPBOARD_PERMISSION_REQUEST_FAILED")
            }
        }
    }
    
    /**
     * Monitors clipboard changes (iOS 14+).
     * Note: This should be used sparingly due to privacy implications.
     */
    fun addClipboardChangeObserver(callback: (ClipboardContent?) -> Unit) {
        // Set up notification observer for pasteboard changes
        NSNotificationCenter.defaultCenter.addObserverForName(
            UIPasteboardChangedNotification,
            null,
            NSOperationQueue.mainQueue
        ) { notification ->
            // Get updated clipboard content
            kotlinx.coroutines.GlobalScope.launch {
                val contentResult = getClipboardContent()
                val content = when (contentResult) {
                    is Result.Success -> contentResult.data
                    else -> null
                }
                callback(content)
            }
        }
    }
    
    /**
     * Removes clipboard change observer.
     */
    fun removeClipboardChangeObserver() {
        NSNotificationCenter.defaultCenter.removeObserver(
            null,
            UIPasteboardChangedNotification,
            null
        )
    }
    
    /**
     * Checks if the app is authorized to access sensitive clipboard content.
     * iOS may restrict access to certain types of clipboard content.
     */
    suspend fun canAccessSensitiveContent(): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                // Check if we can access clipboard content
                // iOS may block access if the app is not in foreground
                val canAccess = UIApplication.sharedApplication.applicationState == UIApplicationState.UIApplicationStateActive
                
                Result.success(canAccess)
            } catch (e: Exception) {
                Result.error("Failed to check sensitive content access: ${e.message}", "CLIPBOARD_SENSITIVE_ACCESS_FAILED")
            }
        }
    }
    
    /**
     * Gets the number of items in the clipboard.
     */
    suspend fun getClipboardItemCount(): Result<Int> {
        return withContext(Dispatchers.Main) {
            try {
                val itemCount = pasteboard.numberOfItems.toInt()
                Result.success(itemCount)
            } catch (e: Exception) {
                Result.error("Failed to get clipboard item count: ${e.message}", "CLIPBOARD_ITEM_COUNT_FAILED")
            }
        }
    }
    
    /**
     * Checks if clipboard contains URLs.
     */
    suspend fun hasUrls(): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                val hasUrls = pasteboard.hasURLs
                Result.success(hasUrls)
            } catch (e: Exception) {
                Result.error("Failed to check URLs in clipboard: ${e.message}", "CLIPBOARD_URL_CHECK_FAILED")
            }
        }
    }
    
    /**
     * Gets URLs from clipboard if available.
     */
    suspend fun getUrls(): Result<List<String>> {
        return withContext(Dispatchers.Main) {
            try {
                val urls = pasteboard.URLs?.mapNotNull { url ->
                    (url as? NSURL)?.absoluteString
                } ?: emptyList()
                
                Result.success(urls)
            } catch (e: Exception) {
                Result.error("Failed to get URLs from clipboard: ${e.message}", "CLIPBOARD_URL_GET_FAILED")
            }
        }
    }
    
    companion object {
        /**
         * Create clipboard manager instance.
         * No initialization needed for iOS implementation.
         */
        fun create(): ClipboardManager {
            return ClipboardManager()
        }
        
        /**
         * Privacy description that should be added to Info.plist:
         * NSClipboardUsageDescription = "SafeCheck accesses the clipboard to quickly scan URLs, emails, and other content for security threats. This helps protect you from malicious links and suspicious content."
         */
        const val CLIPBOARD_USAGE_DESCRIPTION = "SafeCheck accesses the clipboard to quickly scan URLs, emails, and other content for security threats. This helps protect you from malicious links and suspicious content."
    }
}

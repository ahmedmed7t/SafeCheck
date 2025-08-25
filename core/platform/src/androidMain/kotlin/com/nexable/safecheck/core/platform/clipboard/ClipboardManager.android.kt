package com.nexable.safecheck.core.platform.clipboard

import android.content.ClipData
import android.content.ClipboardManager as AndroidClipboardManager
import android.content.Context
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Android implementation of clipboard manager using Android ClipboardManager.
 */
actual class ClipboardManager {
    private var androidClipboardManager: AndroidClipboardManager? = null
    
    /**
     * Initialize the clipboard manager with Android context.
     * This should be called before using other methods.
     */
    fun initialize(context: Context) {
        androidClipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as AndroidClipboardManager
    }
    
    actual suspend fun readText(): Result<String?> {
        return withContext(Dispatchers.Main) {
            try {
                val clipboardManager = androidClipboardManager
                    ?: return@withContext Result.error("Clipboard not initialized", "CLIPBOARD_NOT_INITIALIZED")
                
                val clip = clipboardManager.primaryClip
                val text = if (clip != null && clip.itemCount > 0) {
                    val item = clip.getItemAt(0)
                    item?.text?.toString()
                } else {
                    null
                }
                
                Result.success(text)
            } catch (e: SecurityException) {
                Result.error("Permission denied to access clipboard", "CLIPBOARD_PERMISSION_DENIED")
            } catch (e: Exception) {
                Result.error("Failed to read clipboard: ${e.message}", "CLIPBOARD_READ_FAILED")
            }
        }
    }
    
    actual suspend fun writeText(text: String): Result<Unit> {
        return withContext(Dispatchers.Main) {
            try {
                val clipboardManager = androidClipboardManager
                    ?: return@withContext Result.error("Clipboard not initialized", "CLIPBOARD_NOT_INITIALIZED")
                
                val clip = ClipData.newPlainText("SafeCheck", text)
                clipboardManager.setPrimaryClip(clip)
                
                Result.success(Unit)
            } catch (e: SecurityException) {
                Result.error("Permission denied to write to clipboard", "CLIPBOARD_PERMISSION_DENIED")
            } catch (e: Exception) {
                Result.error("Failed to write to clipboard: ${e.message}", "CLIPBOARD_WRITE_FAILED")
            }
        }
    }
    
    actual suspend fun hasText(): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                val clipboardManager = androidClipboardManager
                    ?: return@withContext Result.error("Clipboard not initialized", "CLIPBOARD_NOT_INITIALIZED")
                
                val hasText = clipboardManager.hasPrimaryClip() && 
                        clipboardManager.primaryClipDescription?.hasMimeType("text/plain") == true
                
                Result.success(hasText)
            } catch (e: Exception) {
                Result.error("Failed to check clipboard: ${e.message}", "CLIPBOARD_CHECK_FAILED")
            }
        }
    }
    
    actual suspend fun clear(): Result<Unit> {
        return withContext(Dispatchers.Main) {
            try {
                val clipboardManager = androidClipboardManager
                    ?: return@withContext Result.error("Clipboard not initialized", "CLIPBOARD_NOT_INITIALIZED")
                
                val clip = ClipData.newPlainText("", "")
                clipboardManager.setPrimaryClip(clip)
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to clear clipboard: ${e.message}", "CLIPBOARD_CLEAR_FAILED")
            }
        }
    }
    
    /**
     * Gets clipboard content with type detection.
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
     * Adds a clipboard change listener (Android 10+).
     */
    fun addClipboardListener(listener: (ClipboardContent?) -> Unit) {
        try {
            val clipboardManager = androidClipboardManager ?: return
            
            clipboardManager.addPrimaryClipChangedListener {
                // Note: This runs on main thread
                CoroutineScope(Dispatchers.Main).launch {
                    val contentResult = getClipboardContent()
                    val content = when (contentResult) {
                        is Result.Success -> contentResult.data
                        else -> null
                    }
                    listener(content)
                }
            }
        } catch (e: Exception) {
            // Silently ignore listener registration failures
        }
    }
    
    companion object {
        /**
         * Create and initialize clipboard manager with context.
         */
        fun create(context: Context): ClipboardManager {
            val manager = ClipboardManager()
            manager.initialize(context)
            return manager
        }
    }
}

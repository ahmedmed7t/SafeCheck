package com.nexable.safecheck.core.platform.share

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import platform.Foundation.*
import platform.UIKit.*

/**
 * iOS implementation for handling Share Extension and share functionality.
 * This handles incoming shared content from other apps and system share sheet.
 */
class ShareExtensionHandler {
    
    /**
     * Handles shared content from iOS Share Extension.
     * This should be called from the Share Extension's view controller.
     */
    suspend fun handleSharedContent(extensionContext: NSExtensionContext): Result<SharedContent> {
        return withContext(Dispatchers.Main) {
            try {
                val inputItems = extensionContext.inputItems
                
                for (inputItem in inputItems) {
                    val item = inputItem as? NSExtensionItem ?: continue
                    val attachments = item.attachments ?: continue
                    
                    for (attachment in attachments) {
                        val provider = attachment as? NSItemProvider ?: continue
                        
                        // Check for URL content
                        if (provider.hasItemConformingToTypeIdentifier(kUTTypeURL as String)) {
                            val url = extractUrlFromProvider(provider)
                            if (url != null) {
                                return@withContext Result.success(
                                    SharedContent(
                                        content = url,
                                        type = SharedContentType.URL,
                                        sourceApp = item.sourceURL?.absoluteString
                                    )
                                )
                            }
                        }
                        
                        // Check for text content
                        if (provider.hasItemConformingToTypeIdentifier(kUTTypeText as String)) {
                            val text = extractTextFromProvider(provider)
                            if (text != null) {
                                val contentType = detectContentType(text)
                                return@withContext Result.success(
                                    SharedContent(
                                        content = text,
                                        type = contentType,
                                        sourceApp = item.sourceURL?.absoluteString
                                    )
                                )
                            }
                        }
                        
                        // Check for plain text
                        if (provider.hasItemConformingToTypeIdentifier(kUTTypePlainText as String)) {
                            val text = extractPlainTextFromProvider(provider)
                            if (text != null) {
                                val contentType = detectContentType(text)
                                return@withContext Result.success(
                                    SharedContent(
                                        content = text,
                                        type = contentType,
                                        sourceApp = item.sourceURL?.absoluteString
                                    )
                                )
                            }
                        }
                    }
                }
                
                Result.error("No supported content found", "NO_SUPPORTED_CONTENT")
            } catch (e: Exception) {
                Result.error("Failed to handle shared content: ${e.message}", "SHARE_HANDLING_FAILED")
            }
        }
    }
    
    /**
     * Configures the main app to handle returning from Share Extension.
     * This should be called in the main app's AppDelegate.
     */
    fun configureMainAppForSharedContent() {
        // Set up URL scheme handling for returning from Share Extension
        // The Share Extension will open the main app with a custom URL scheme
    }
    
    /**
     * Handles URL schemes when the main app is opened from Share Extension.
     */
    suspend fun handleUrlScheme(url: NSURL): Result<SharedContent?> {
        return withContext(Dispatchers.Main) {
            try {
                val urlString = url.absoluteString ?: ""
                
                // Parse custom URL scheme from Share Extension
                // Format: safecheck://scan?content=<encoded_content>&type=<type>
                if (urlString.startsWith("safecheck://scan")) {
                    val components = NSURLComponents.componentsWithString(urlString)
                    val queryItems = components?.queryItems
                    
                    var content: String? = null
                    var type: String? = null
                    
                    queryItems?.forEach { queryItem ->
                        val item = queryItem as NSURLQueryItem
                        when (item.name) {
                            "content" -> content = item.value?.removingPercentEncoding
                            "type" -> type = item.value
                        }
                    }
                    
                    if (content != null) {
                        val contentType = when (type) {
                            "url" -> SharedContentType.URL
                            "email" -> SharedContentType.EMAIL
                            "text" -> SharedContentType.TEXT
                            else -> detectContentType(content!!)
                        }
                        
                        return@withContext Result.success(
                            SharedContent(
                                content = content!!,
                                type = contentType,
                                sourceApp = "ShareExtension"
                            )
                        )
                    }
                }
                
                Result.success(null)
            } catch (e: Exception) {
                Result.error("Failed to handle URL scheme: ${e.message}", "URL_SCHEME_HANDLING_FAILED")
            }
        }
    }
    
    /**
     * Creates share sheet for sharing scan results.
     */
    fun createShareSheet(
        content: String,
        viewController: UIViewController,
        sourceView: UIView? = null,
        sourceRect: CGRect? = null
    ): Result<Unit> {
        return try {
            val itemsToShare = listOf(content)
            val activityViewController = UIActivityViewController(
                activityItems = itemsToShare,
                applicationActivities = null
            )
            
            // Configure for iPad
            if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiom.UIUserInterfaceIdiomPad) {
                val popover = activityViewController.popoverPresentationController
                if (sourceView != null) {
                    popover?.sourceView = sourceView
                    if (sourceRect != null) {
                        popover?.sourceRect = sourceRect
                    }
                } else {
                    // Fallback to center of screen
                    popover?.sourceView = viewController.view
                    popover?.sourceRect = CGRectMake(
                        viewController.view.bounds.size.width / 2,
                        viewController.view.bounds.size.height / 2,
                        0.0,
                        0.0
                    )
                }
            }
            
            viewController.presentViewController(activityViewController, true, null)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to create share sheet: ${e.message}", "SHARE_SHEET_FAILED")
        }
    }
    
    private suspend fun extractUrlFromProvider(provider: NSItemProvider): String? {
        // This would need to be implemented with proper async handling
        // For now, return null as it requires complex NSItemProvider handling
        return null
    }
    
    private suspend fun extractTextFromProvider(provider: NSItemProvider): String? {
        // This would need to be implemented with proper async handling
        // For now, return null as it requires complex NSItemProvider handling
        return null
    }
    
    private suspend fun extractPlainTextFromProvider(provider: NSItemProvider): String? {
        // This would need to be implemented with proper async handling
        // For now, return null as it requires complex NSItemProvider handling
        return null
    }
    
    private fun detectContentType(content: String): SharedContentType {
        return when {
            content.startsWith("http://") || content.startsWith("https://") -> SharedContentType.URL
            content.contains("@") && content.contains(".") -> SharedContentType.EMAIL
            else -> SharedContentType.TEXT
        }
    }
    
    companion object {
        /**
         * URL scheme for the main app.
         */
        const val URL_SCHEME = "safecheck"
        
        /**
         * Creates a URL to open the main app from Share Extension.
         */
        fun createMainAppUrl(content: String, type: SharedContentType): NSURL? {
            val encodedContent = content.addingPercentEncoding(withAllowedCharacters = NSCharacterSet.URLQueryAllowedCharacterSet())
            val typeString = when (type) {
                SharedContentType.URL -> "url"
                SharedContentType.EMAIL -> "email"
                SharedContentType.TEXT -> "text"
                SharedContentType.FILE -> "file"
                SharedContentType.UNKNOWN -> "unknown"
            }
            
            val urlString = "$URL_SCHEME://scan?content=$encodedContent&type=$typeString"
            return NSURL.URLWithString(urlString)
        }
    }
}

/**
 * Represents shared content from other apps.
 */
data class SharedContent(
    val content: String,
    val type: SharedContentType,
    val sourceApp: String? = null,
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Types of shared content.
 */
enum class SharedContentType {
    URL,
    EMAIL,
    TEXT,
    FILE,
    UNKNOWN
}

/**
 * Share Extension configuration and Info.plist requirements.
 * 
 * To implement the Share Extension, you need to:
 * 
 * 1. Create a Share Extension target in Xcode
 * 2. Add the following to the Share Extension's Info.plist:
 * 
 * <key>NSExtension</key>
 * <dict>
 *     <key>NSExtensionPointIdentifier</key>
 *     <string>com.apple.share-services</string>
 *     <key>NSExtensionAttributes</key>
 *     <dict>
 *         <key>NSExtensionActivationRule</key>
 *         <dict>
 *             <key>NSExtensionActivationSupportsText</key>
 *             <true/>
 *             <key>NSExtensionActivationSupportsWebURLWithMaxCount</key>
 *             <integer>1</integer>
 *         </dict>
 *     </dict>
 *     <key>NSExtensionMainStoryboard</key>
 *     <string>MainInterface</string>
 * </dict>
 * 
 * 3. Add URL scheme to main app's Info.plist:
 * 
 * <key>CFBundleURLTypes</key>
 * <array>
 *     <dict>
 *         <key>CFBundleURLName</key>
 *         <string>com.nexable.safecheck</string>
 *         <key>CFBundleURLSchemes</key>
 *         <array>
 *             <string>safecheck</string>
 *         </array>
 *     </dict>
 * </array>
 * 
 * 4. Add app group for sharing data between main app and extension:
 * 
 * <key>com.apple.security.application-groups</key>
 * <array>
 *     <string>group.com.nexable.safecheck</string>
 * </array>
 */

package com.nexable.safecheck.core.platform.permissions

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.AVFoundation.*
import platform.Foundation.*
import platform.UIKit.*
import kotlin.coroutines.resume

/**
 * iOS implementation of permission manager using iOS permission APIs.
 */
actual class PermissionManager {
    
    actual suspend fun isPermissionGranted(permission: Permission): Result<Boolean> {
        return try {
            val isGranted = when (permission) {
                Permission.CAMERA -> {
                    val status = AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeVideo)
                    status == AVAuthorizationStatus.AVAuthorizationStatusAuthorized
                }
                Permission.MICROPHONE -> {
                    val status = AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeAudio)
                    status == AVAuthorizationStatus.AVAuthorizationStatusAuthorized
                }
                Permission.LOCATION -> {
                    // iOS location permissions need CLLocationManager
                    // For now, return false as it requires more complex setup
                    false
                }
                Permission.STORAGE,
                Permission.INTERNET,
                Permission.NETWORK_STATE,
                Permission.WRITE_EXTERNAL_STORAGE,
                Permission.READ_EXTERNAL_STORAGE -> {
                    // These permissions are automatically granted on iOS
                    true
                }
            }
            
            Result.success(isGranted)
        } catch (e: Exception) {
            Result.error("Failed to check permission: ${e.message}", "PERMISSION_CHECK_FAILED")
        }
    }
    
    actual suspend fun requestPermission(permission: Permission): Result<Boolean> {
        return try {
            when (permission) {
                Permission.CAMERA -> requestCameraPermission()
                Permission.MICROPHONE -> requestMicrophonePermission()
                Permission.LOCATION -> requestLocationPermission()
                Permission.STORAGE,
                Permission.INTERNET,
                Permission.NETWORK_STATE,
                Permission.WRITE_EXTERNAL_STORAGE,
                Permission.READ_EXTERNAL_STORAGE -> {
                    // These permissions are automatically granted on iOS
                    Result.success(true)
                }
            }
        } catch (e: Exception) {
            Result.error("Failed to request permission: ${e.message}", "PERMISSION_REQUEST_FAILED")
        }
    }
    
    actual suspend fun requestPermissions(permissions: List<Permission>): Result<Map<Permission, Boolean>> {
        return try {
            val results = mutableMapOf<Permission, Boolean>()
            
            for (permission in permissions) {
                val result = requestPermission(permission)
                when (result) {
                    is Result.Success -> results[permission] = result.data
                    is Result.Error -> results[permission] = false
                    is Result.Loading -> results[permission] = false
                }
            }
            
            Result.success(results)
        } catch (e: Exception) {
            Result.error("Failed to request permissions: ${e.message}", "PERMISSIONS_REQUEST_FAILED")
        }
    }
    
    actual suspend fun shouldShowRationale(permission: Permission): Result<Boolean> {
        return try {
            // iOS doesn't have a direct equivalent to Android's shouldShowRequestPermissionRationale
            // We can determine this based on the permission status
            val shouldShow = when (permission) {
                Permission.CAMERA -> {
                    val status = AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeVideo)
                    status == AVAuthorizationStatus.AVAuthorizationStatusDenied
                }
                Permission.MICROPHONE -> {
                    val status = AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeAudio)
                    status == AVAuthorizationStatus.AVAuthorizationStatusDenied
                }
                Permission.LOCATION -> {
                    // Would need CLLocationManager to check status
                    false
                }
                Permission.STORAGE,
                Permission.INTERNET,
                Permission.NETWORK_STATE,
                Permission.WRITE_EXTERNAL_STORAGE,
                Permission.READ_EXTERNAL_STORAGE -> {
                    // These permissions don't require rationale on iOS
                    false
                }
            }
            
            Result.success(shouldShow)
        } catch (e: Exception) {
            Result.error("Failed to check rationale: ${e.message}", "RATIONALE_CHECK_FAILED")
        }
    }
    
    actual suspend fun openAppSettings(): Result<Unit> {
        return try {
            val settingsUrl = NSURL.URLWithString(UIApplicationOpenSettingsURLString)
            
            if (settingsUrl != null && UIApplication.sharedApplication.canOpenURL(settingsUrl)) {
                UIApplication.sharedApplication.openURL(settingsUrl)
                Result.success(Unit)
            } else {
                Result.error("Cannot open app settings", "SETTINGS_OPEN_FAILED")
            }
        } catch (e: Exception) {
            Result.error("Failed to open app settings: ${e.message}", "SETTINGS_OPEN_FAILED")
        }
    }
    
    private suspend fun requestCameraPermission(): Result<Boolean> {
        return suspendCancellableCoroutine { continuation ->
            try {
                AVCaptureDevice.requestAccessForMediaType(AVMediaTypeVideo) { granted ->
                    continuation.resume(Result.success(granted))
                }
            } catch (e: Exception) {
                continuation.resume(Result.error("Camera permission request failed: ${e.message}", "CAMERA_PERMISSION_FAILED"))
            }
        }
    }
    
    private suspend fun requestMicrophonePermission(): Result<Boolean> {
        return suspendCancellableCoroutine { continuation ->
            try {
                AVCaptureDevice.requestAccessForMediaType(AVMediaTypeAudio) { granted ->
                    continuation.resume(Result.success(granted))
                }
            } catch (e: Exception) {
                continuation.resume(Result.error("Microphone permission request failed: ${e.message}", "MICROPHONE_PERMISSION_FAILED"))
            }
        }
    }
    
    private suspend fun requestLocationPermission(): Result<Boolean> {
        return try {
            // Location permission requires CLLocationManager setup
            // For now, return an error indicating this needs more implementation
            Result.error("Location permission not yet implemented", "LOCATION_PERMISSION_NOT_IMPLEMENTED")
        } catch (e: Exception) {
            Result.error("Location permission request failed: ${e.message}", "LOCATION_PERMISSION_FAILED")
        }
    }
    
    /**
     * Gets permission status with additional information.
     */
    suspend fun getPermissionStatus(permission: Permission): Result<PermissionStatus> {
        val isGrantedResult = isPermissionGranted(permission)
        val shouldShowRationaleResult = shouldShowRationale(permission)
        
        return when {
            isGrantedResult is Result.Success && shouldShowRationaleResult is Result.Success -> {
                val isGranted = isGrantedResult.data
                val shouldShowRationale = shouldShowRationaleResult.data
                
                // On iOS, if permission is denied and no rationale needed, it might be permanently denied
                val isPermanentlyDenied = !isGranted && !shouldShowRationale && hasBeenRequestedBefore(permission)
                
                val status = PermissionStatus(
                    permission = permission,
                    isGranted = isGranted,
                    shouldShowRationale = shouldShowRationale,
                    isPermanentlyDenied = isPermanentlyDenied
                )
                
                Result.success(status)
            }
            isGrantedResult is Result.Error -> isGrantedResult
            shouldShowRationaleResult is Result.Error -> shouldShowRationaleResult
            else -> Result.error("Unknown error checking permission status", "PERMISSION_STATUS_ERROR")
        }
    }
    
    /**
     * Checks if a permission has been requested before.
     */
    private fun hasBeenRequestedBefore(permission: Permission): Boolean {
        return when (permission) {
            Permission.CAMERA -> {
                val status = AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeVideo)
                status != AVAuthorizationStatus.AVAuthorizationStatusNotDetermined
            }
            Permission.MICROPHONE -> {
                val status = AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeAudio)
                status != AVAuthorizationStatus.AVAuthorizationStatusNotDetermined
            }
            Permission.LOCATION -> {
                // Would need CLLocationManager to check
                false
            }
            Permission.STORAGE,
            Permission.INTERNET,
            Permission.NETWORK_STATE,
            Permission.WRITE_EXTERNAL_STORAGE,
            Permission.READ_EXTERNAL_STORAGE -> {
                // These are automatically granted
                true
            }
        }
    }
    
    /**
     * Processes batch permission results.
     */
    suspend fun processPermissionResults(permissions: List<Permission>): Result<PermissionResult> {
        val granted = mutableListOf<Permission>()
        val denied = mutableListOf<Permission>()
        val permanentlyDenied = mutableListOf<Permission>()
        
        for (permission in permissions) {
            when (val statusResult = getPermissionStatus(permission)) {
                is Result.Success -> {
                    val status = statusResult.data
                    when {
                        status.isGranted -> granted.add(permission)
                        status.isPermanentlyDenied -> permanentlyDenied.add(permission)
                        else -> denied.add(permission)
                    }
                }
                is Result.Error -> {
                    // Treat error as denied
                    denied.add(permission)
                }
                is Result.Loading -> {
                    // Treat loading as denied
                    denied.add(permission)
                }
            }
        }
        
        val result = PermissionResult(
            granted = granted,
            denied = denied,
            permanentlyDenied = permanentlyDenied
        )
        
        return Result.success(result)
    }
    
    companion object {
        /**
         * Create permission manager instance.
         * No initialization needed for iOS implementation.
         */
        fun create(): PermissionManager {
            return PermissionManager()
        }
        
        /**
         * Privacy descriptions that should be added to Info.plist:
         */
        const val CAMERA_USAGE_DESCRIPTION = "SafeCheck uses the camera to scan QR codes that may contain URLs, emails, or other content for security analysis. This helps protect you from malicious QR codes."
        const val MICROPHONE_USAGE_DESCRIPTION = "SafeCheck may use the microphone for enhanced scanning features or voice-based interactions."
        const val LOCATION_USAGE_DESCRIPTION = "SafeCheck may use location data to provide region-specific security insights and warnings."
        const val CLIPBOARD_USAGE_DESCRIPTION = "SafeCheck accesses the clipboard to quickly scan URLs, emails, and other content for security threats. This helps protect you from malicious links and suspicious content."
    }
}

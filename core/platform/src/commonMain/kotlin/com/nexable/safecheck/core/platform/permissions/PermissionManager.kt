package com.nexable.safecheck.core.platform.permissions

import com.nexable.safecheck.core.domain.model.Result

/**
 * Platform-specific permission management interface.
 * Provides runtime permission checking and requesting capabilities.
 */
expect class PermissionManager() {
    
    /**
     * Checks if a specific permission is granted.
     * 
     * @param permission The permission to check
     * @return Result indicating if permission is granted
     */
    suspend fun isPermissionGranted(permission: Permission): Result<Boolean>
    
    /**
     * Requests a specific permission.
     * 
     * @param permission The permission to request
     * @return Result indicating if permission was granted
     */
    suspend fun requestPermission(permission: Permission): Result<Boolean>
    
    /**
     * Requests multiple permissions.
     * 
     * @param permissions The permissions to request
     * @return Result containing map of permission to granted status
     */
    suspend fun requestPermissions(permissions: List<Permission>): Result<Map<Permission, Boolean>>
    
    /**
     * Checks if permission rationale should be shown.
     * 
     * @param permission The permission to check
     * @return Result indicating if rationale should be shown
     */
    suspend fun shouldShowRationale(permission: Permission): Result<Boolean>
    
    /**
     * Opens app settings for manual permission configuration.
     * 
     * @return Result indicating if settings were opened successfully
     */
    suspend fun openAppSettings(): Result<Unit>
}

/**
 * Supported permissions across platforms.
 */
enum class Permission {
    CAMERA,
    MICROPHONE,
    LOCATION,
    STORAGE,
    INTERNET,
    NETWORK_STATE,
    WRITE_EXTERNAL_STORAGE,
    READ_EXTERNAL_STORAGE
}

/**
 * Permission status with additional information.
 */
data class PermissionStatus(
    val permission: Permission,
    val isGranted: Boolean,
    val shouldShowRationale: Boolean = false,
    val isPermanentlyDenied: Boolean = false
)

/**
 * Permission result for batch operations.
 */
data class PermissionResult(
    val granted: List<Permission>,
    val denied: List<Permission>,
    val permanentlyDenied: List<Permission>
) {
    val allGranted: Boolean = denied.isEmpty() && permanentlyDenied.isEmpty()
    val hasGranted: Boolean = granted.isNotEmpty()
    val hasDenied: Boolean = denied.isNotEmpty()
    val hasPermanentlyDenied: Boolean = permanentlyDenied.isNotEmpty()
}

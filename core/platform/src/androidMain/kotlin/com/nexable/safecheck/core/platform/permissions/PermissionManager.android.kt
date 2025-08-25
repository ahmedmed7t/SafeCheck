package com.nexable.safecheck.core.platform.permissions

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Android implementation of permission manager using Android permissions API.
 */
actual class PermissionManager {
    
    private var context: Context? = null
    private var activity: ComponentActivity? = null
    private var singlePermissionLauncher: ActivityResultLauncher<String>? = null
    private var multiplePermissionsLauncher: ActivityResultLauncher<Array<String>>? = null
    
    /**
     * Initialize the permission manager with Android context and activity.
     * This should be called before using other methods.
     */
    fun initialize(context: Context, activity: ComponentActivity? = null) {
        this.context = context
        this.activity = activity
        
        // Set up permission launchers if activity is provided
        activity?.let { act ->
            singlePermissionLauncher = act.registerForActivityResult(
                ActivityResultContracts.RequestPermission()
            ) { /* Result handled in suspend function */ }
            
            multiplePermissionsLauncher = act.registerForActivityResult(
                ActivityResultContracts.RequestMultiplePermissions()
            ) { /* Result handled in suspend function */ }
        }
    }
    
    actual suspend fun isPermissionGranted(permission: Permission): Result<Boolean> {
        val ctx = context ?: return Result.error("PermissionManager not initialized", "PERMISSION_MANAGER_NOT_INITIALIZED")
        
        return try {
            val androidPermission = permission.toAndroidPermission()
            val isGranted = ContextCompat.checkSelfPermission(ctx, androidPermission) == PackageManager.PERMISSION_GRANTED
            Result.success(isGranted)
        } catch (e: Exception) {
            Result.error("Failed to check permission: ${e.message}", "PERMISSION_CHECK_FAILED")
        }
    }
    
    actual suspend fun requestPermission(permission: Permission): Result<Boolean> {
        val act = activity ?: return Result.error("Activity not available for permission request", "ACTIVITY_NOT_AVAILABLE")
        val launcher = singlePermissionLauncher ?: return Result.error("Permission launcher not initialized", "LAUNCHER_NOT_INITIALIZED")
        
        return try {
            val androidPermission = permission.toAndroidPermission()
            
            // Check if permission is already granted
            val currentStatus = isPermissionGranted(permission)
            if (currentStatus is Result.Success && currentStatus.data) {
                return Result.success(true)
            }
            
            // Request permission using suspendCancellableCoroutine
            suspendCancellableCoroutine { continuation ->
                launcher.launch(androidPermission)
                
                // Note: In a production app, you would need to properly handle the result
                // This is a simplified implementation. You would typically use a callback
                // or state management to handle the async result.
                continuation.resume(Result.success(false)) // Placeholder
            }
        } catch (e: Exception) {
            Result.error("Failed to request permission: ${e.message}", "PERMISSION_REQUEST_FAILED")
        }
    }
    
    actual suspend fun requestPermissions(permissions: List<Permission>): Result<Map<Permission, Boolean>> {
        val act = activity ?: return Result.error("Activity not available for permission request", "ACTIVITY_NOT_AVAILABLE")
        val launcher = multiplePermissionsLauncher ?: return Result.error("Permission launcher not initialized", "LAUNCHER_NOT_INITIALIZED")
        
        return try {
            val androidPermissions = permissions.map { it.toAndroidPermission() }.toTypedArray()
            
            // Check if all permissions are already granted
            val currentStatuses = mutableMapOf<Permission, Boolean>()
            for (permission in permissions) {
                val status = isPermissionGranted(permission)
                if (status is Result.Success) {
                    currentStatuses[permission] = status.data
                }
            }
            
            val allGranted = currentStatuses.values.all { it }
            if (allGranted) {
                return Result.success(currentStatuses)
            }
            
            // Request permissions using suspendCancellableCoroutine
            suspendCancellableCoroutine { continuation ->
                launcher.launch(androidPermissions)
                
                // Note: In a production app, you would need to properly handle the result
                // This is a simplified implementation
                continuation.resume(Result.success(currentStatuses))
            }
        } catch (e: Exception) {
            Result.error("Failed to request permissions: ${e.message}", "PERMISSIONS_REQUEST_FAILED")
        }
    }
    
    actual suspend fun shouldShowRationale(permission: Permission): Result<Boolean> {
        val act = activity ?: return Result.error("Activity not available", "ACTIVITY_NOT_AVAILABLE")
        
        return try {
            val androidPermission = permission.toAndroidPermission()
            val shouldShow = ActivityCompat.shouldShowRequestPermissionRationale(act, androidPermission)
            Result.success(shouldShow)
        } catch (e: Exception) {
            Result.error("Failed to check rationale: ${e.message}", "RATIONALE_CHECK_FAILED")
        }
    }
    
    actual suspend fun openAppSettings(): Result<Unit> {
        val ctx = context ?: return Result.error("Context not available", "CONTEXT_NOT_AVAILABLE")
        
        return try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.fromParts("package", ctx.packageName, null)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            ctx.startActivity(intent)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to open app settings: ${e.message}", "SETTINGS_OPEN_FAILED")
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
                
                // If permission is denied and rationale is false, it might be permanently denied
                val isPermanentlyDenied = !isGranted && !shouldShowRationale
                
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
         * Create and initialize permission manager with context.
         */
        fun create(context: Context, activity: ComponentActivity? = null): PermissionManager {
            val manager = PermissionManager()
            manager.initialize(context, activity)
            return manager
        }
    }
}

/**
 * Extension function to convert Platform Permission to Android permission string.
 */
private fun Permission.toAndroidPermission(): String {
    return when (this) {
        Permission.CAMERA -> Manifest.permission.CAMERA
        Permission.MICROPHONE -> Manifest.permission.RECORD_AUDIO
        Permission.LOCATION -> Manifest.permission.ACCESS_FINE_LOCATION
        Permission.STORAGE -> Manifest.permission.READ_EXTERNAL_STORAGE
        Permission.INTERNET -> Manifest.permission.INTERNET
        Permission.NETWORK_STATE -> Manifest.permission.ACCESS_NETWORK_STATE
        Permission.WRITE_EXTERNAL_STORAGE -> Manifest.permission.WRITE_EXTERNAL_STORAGE
        Permission.READ_EXTERNAL_STORAGE -> Manifest.permission.READ_EXTERNAL_STORAGE
    }
}

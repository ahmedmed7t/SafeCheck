package com.nexable.safecheck.core.platform.background

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import platform.BackgroundTasks.*
import platform.Foundation.*
import platform.UIKit.*

/**
 * iOS implementation of background task scheduler using BackgroundTasks framework.
 * Requires iOS 13+ for BGTaskScheduler API.
 */
actual class BackgroundTaskScheduler {
    
    private var isInitialized = false
    
    companion object {
        // Background task identifiers - these must be registered in Info.plist
        private const val BACKGROUND_SCAN_TASK_ID = "com.nexable.safecheck.background-scan"
        private const val BACKGROUND_REFRESH_TASK_ID = "com.nexable.safecheck.background-refresh"
    }
    
    /**
     * Initialize the background task scheduler.
     * This should be called during app launch.
     */
    fun initialize(): Result<Unit> {
        return try {
            if (isInitialized) {
                return Result.success(Unit)
            }
            
            // Register background task handlers
            registerBackgroundTasks()
            isInitialized = true
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to initialize background scheduler: ${e.message}", "INIT_FAILED")
        }
    }
    
    actual suspend fun scheduleOneTimeScan(request: BackgroundScanRequest): Result<String> {
        return withContext(Dispatchers.Main) {
            try {
                if (!isInitialized) {
                    return@withContext Result.error("Scheduler not initialized", "SCHEDULER_NOT_INITIALIZED")
                }
                
                // Create background task request
                val taskRequest = BGProcessingTaskRequest(BACKGROUND_SCAN_TASK_ID)
                taskRequest.requiresNetworkConnectivity = request.requiresNetwork
                taskRequest.requiresExternalPower = request.requiresCharging
                
                // Set earliest begin date if scheduled time is provided
                request.scheduledTime?.let { scheduledTime ->
                    val now = Clock.System.now()
                    if (scheduledTime > now) {
                        val timeInterval = (scheduledTime.toEpochMilliseconds() - now.toEpochMilliseconds()) / 1000.0
                        taskRequest.earliestBeginDate = NSDate.dateWithTimeIntervalSinceNow(timeInterval)
                    }
                }
                
                // Submit the request
                val scheduler = BGTaskScheduler.sharedScheduler
                val error = scheduler.submitTaskRequest(taskRequest, null)
                
                if (error != null) {
                    return@withContext Result.error("Failed to schedule task: ${error.localizedDescription}", "SCHEDULE_FAILED")
                }
                
                Result.success(taskRequest.identifier)
            } catch (e: Exception) {
                Result.error("Failed to schedule one-time scan: ${e.message}", "SCHEDULE_ONE_TIME_FAILED")
            }
        }
    }
    
    actual suspend fun schedulePeriodicScan(request: PeriodicScanRequest): Result<String> {
        return withContext(Dispatchers.Main) {
            try {
                if (!isInitialized) {
                    return@withContext Result.error("Scheduler not initialized", "SCHEDULER_NOT_INITIALIZED")
                }
                
                // Create background app refresh request
                val taskRequest = BGAppRefreshTaskRequest(BACKGROUND_REFRESH_TASK_ID)
                taskRequest.earliestBeginDate = NSDate.dateWithTimeIntervalSinceNow(request.intervalMinutes * 60.0)
                
                // Submit the request
                val scheduler = BGTaskScheduler.sharedScheduler
                val error = scheduler.submitTaskRequest(taskRequest, null)
                
                if (error != null) {
                    return@withContext Result.error("Failed to schedule task: ${error.localizedDescription}", "SCHEDULE_FAILED")
                }
                
                Result.success(taskRequest.identifier)
            } catch (e: Exception) {
                Result.error("Failed to schedule periodic scan: ${e.message}", "SCHEDULE_PERIODIC_FAILED")
            }
        }
    }
    
    actual suspend fun cancelTask(taskId: String): Result<Unit> {
        return withContext(Dispatchers.Main) {
            try {
                val scheduler = BGTaskScheduler.sharedScheduler
                scheduler.cancelTaskRequestWithIdentifier(taskId)
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to cancel task: ${e.message}", "CANCEL_FAILED")
            }
        }
    }
    
    actual suspend fun cancelAllTasks(): Result<Unit> {
        return withContext(Dispatchers.Main) {
            try {
                val scheduler = BGTaskScheduler.sharedScheduler
                scheduler.cancelAllTaskRequests()
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to cancel all tasks: ${e.message}", "CANCEL_ALL_FAILED")
            }
        }
    }
    
    actual suspend fun getTaskStatus(taskId: String): Result<TaskStatus> {
        return withContext(Dispatchers.Main) {
            try {
                // iOS doesn't provide a direct way to query task status
                // We can only check if it's pending by trying to get pending requests
                val scheduler = BGTaskScheduler.sharedScheduler
                val pendingRequests = scheduler.pendingTaskRequests()
                
                val hasPendingTask = pendingRequests.any { request ->
                    request.identifier == taskId
                }
                
                val status = if (hasPendingTask) TaskStatus.ENQUEUED else TaskStatus.SUCCEEDED
                Result.success(status)
            } catch (e: Exception) {
                Result.error("Failed to get task status: ${e.message}", "STATUS_CHECK_FAILED")
            }
        }
    }
    
    actual suspend fun getAllTasks(): Result<List<TaskInfo>> {
        return withContext(Dispatchers.Main) {
            try {
                val scheduler = BGTaskScheduler.sharedScheduler
                val pendingRequests = scheduler.pendingTaskRequests()
                
                val taskInfos = pendingRequests.map { request ->
                    val taskType = when (request.identifier) {
                        BACKGROUND_SCAN_TASK_ID -> TaskType.ONE_TIME_SCAN
                        BACKGROUND_REFRESH_TASK_ID -> TaskType.PERIODIC_SCAN
                        else -> TaskType.ONE_TIME_SCAN
                    }
                    
                    val scheduledAt = request.earliestBeginDate?.let { date ->
                        Instant.fromEpochMilliseconds((date.timeIntervalSince1970 * 1000).toLong())
                    }
                    
                    TaskInfo(
                        id = request.identifier,
                        type = taskType,
                        status = TaskStatus.ENQUEUED,
                        createdAt = Clock.System.now(), // Not available from iOS API
                        scheduledAt = scheduledAt,
                        runAttemptCount = 0, // Not available from iOS API
                        metadata = emptyMap()
                    )
                }
                
                Result.success(taskInfos)
            } catch (e: Exception) {
                Result.error("Failed to get all tasks: ${e.message}", "GET_ALL_TASKS_FAILED")
            }
        }
    }
    
    /**
     * Checks if background app refresh is enabled in device settings.
     */
    suspend fun isBackgroundAppRefreshEnabled(): Result<Boolean> {
        return withContext(Dispatchers.Main) {
            try {
                val status = UIApplication.sharedApplication.backgroundRefreshStatus
                val isEnabled = status == UIBackgroundRefreshStatus.UIBackgroundRefreshStatusAvailable
                
                Result.success(isEnabled)
            } catch (e: Exception) {
                Result.error("Failed to check background refresh status: ${e.message}", "BACKGROUND_REFRESH_CHECK_FAILED")
            }
        }
    }
    
    /**
     * Gets the current background refresh status.
     */
    suspend fun getBackgroundRefreshStatus(): Result<String> {
        return withContext(Dispatchers.Main) {
            try {
                val status = when (UIApplication.sharedApplication.backgroundRefreshStatus) {
                    UIBackgroundRefreshStatus.UIBackgroundRefreshStatusAvailable -> "Available"
                    UIBackgroundRefreshStatus.UIBackgroundRefreshStatusDenied -> "Denied"
                    UIBackgroundRefreshStatus.UIBackgroundRefreshStatusRestricted -> "Restricted"
                    else -> "Unknown"
                }
                
                Result.success(status)
            } catch (e: Exception) {
                Result.error("Failed to get background refresh status: ${e.message}", "BACKGROUND_REFRESH_STATUS_FAILED")
            }
        }
    }
    
    private fun registerBackgroundTasks() {
        val scheduler = BGTaskScheduler.sharedScheduler
        
        // Register background processing task
        scheduler.registerForTaskWithIdentifier(
            BACKGROUND_SCAN_TASK_ID,
            null // Using null for queue - will use main queue
        ) { task ->
            handleBackgroundScanTask(task as BGProcessingTask)
        }
        
        // Register background app refresh task
        scheduler.registerForTaskWithIdentifier(
            BACKGROUND_REFRESH_TASK_ID,
            null // Using null for queue - will use main queue
        ) { task ->
            handleBackgroundRefreshTask(task as BGAppRefreshTask)
        }
    }
    
    private fun handleBackgroundScanTask(task: BGProcessingTask) {
        // Set expiration handler
        task.expirationHandler = {
            // Clean up and mark task as failed
            task.setTaskCompletedWithSuccess(false)
        }
        
        // Perform the background scan
        // This would integrate with the actual scanning logic
        performBackgroundScan { success ->
            task.setTaskCompletedWithSuccess(success)
            
            // Schedule next background scan if needed
            if (success) {
                scheduleNextBackgroundScan()
            }
        }
    }
    
    private fun handleBackgroundRefreshTask(task: BGAppRefreshTask) {
        // Set expiration handler
        task.expirationHandler = {
            // Clean up and mark task as failed
            task.setTaskCompletedWithSuccess(false)
        }
        
        // Perform background refresh (e.g., update threat databases)
        performBackgroundRefresh { success ->
            task.setTaskCompletedWithSuccess(success)
            
            // Schedule next refresh
            if (success) {
                scheduleNextBackgroundRefresh()
            }
        }
    }
    
    private fun performBackgroundScan(completion: (Boolean) -> Unit) {
        // TODO: Implement actual background scan logic
        // This would use the scanning engines to process any queued scans
        
        // For now, simulate success
        completion(true)
    }
    
    private fun performBackgroundRefresh(completion: (Boolean) -> Unit) {
        // TODO: Implement background refresh logic
        // This could update threat databases, clean cache, etc.
        
        // For now, simulate success
        completion(true)
    }
    
    private fun scheduleNextBackgroundScan() {
        // Schedule next background processing task
        val taskRequest = BGProcessingTaskRequest(BACKGROUND_SCAN_TASK_ID)
        taskRequest.requiresNetworkConnectivity = true
        taskRequest.earliestBeginDate = NSDate.dateWithTimeIntervalSinceNow(3600.0) // 1 hour
        
        val scheduler = BGTaskScheduler.sharedScheduler
        scheduler.submitTaskRequest(taskRequest, null)
    }
    
    private fun scheduleNextBackgroundRefresh() {
        // Schedule next background refresh task
        val taskRequest = BGAppRefreshTaskRequest(BACKGROUND_REFRESH_TASK_ID)
        taskRequest.earliestBeginDate = NSDate.dateWithTimeIntervalSinceNow(86400.0) // 24 hours
        
        val scheduler = BGTaskScheduler.sharedScheduler
        scheduler.submitTaskRequest(taskRequest, null)
    }
    
    companion object {
        /**
         * Create and initialize background task scheduler.
         */
        fun create(): Result<BackgroundTaskScheduler> {
            val scheduler = BackgroundTaskScheduler()
            val initResult = scheduler.initialize()
            
            return when (initResult) {
                is Result.Success -> Result.success(scheduler)
                is Result.Error -> Result.error(initResult.message, initResult.code)
                is Result.Loading -> Result.error("Initialization in progress", "INIT_IN_PROGRESS")
            }
        }
        
        /**
         * Required Info.plist configuration for background tasks:
         * 
         * <key>BGTaskSchedulerPermittedIdentifiers</key>
         * <array>
         *     <string>com.nexable.safecheck.background-scan</string>
         *     <string>com.nexable.safecheck.background-refresh</string>
         * </array>
         * 
         * <key>UIBackgroundModes</key>
         * <array>
         *     <string>background-processing</string>
         *     <string>background-fetch</string>
         * </array>
         */
        
        /**
         * Background task identifiers that must be registered in Info.plist.
         */
        const val BACKGROUND_SCAN_IDENTIFIER = BACKGROUND_SCAN_TASK_ID
        const val BACKGROUND_REFRESH_IDENTIFIER = BACKGROUND_REFRESH_TASK_ID
    }
}

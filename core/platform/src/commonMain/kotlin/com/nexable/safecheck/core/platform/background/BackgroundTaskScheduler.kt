package com.nexable.safecheck.core.platform.background

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.datetime.Instant

/**
 * Platform-specific background task scheduling interface.
 * Provides capabilities to schedule and manage background tasks.
 */
expect class BackgroundTaskScheduler() {
    
    /**
     * Schedules a one-time background scan task.
     * 
     * @param request The scan request to schedule
     * @return Result containing the task ID
     */
    suspend fun scheduleOneTimeScan(request: BackgroundScanRequest): Result<String>
    
    /**
     * Schedules a periodic background scan task.
     * 
     * @param request The periodic scan request to schedule
     * @return Result containing the task ID
     */
    suspend fun schedulePeriodicScan(request: PeriodicScanRequest): Result<String>
    
    /**
     * Cancels a background task by ID.
     * 
     * @param taskId The ID of the task to cancel
     * @return Result indicating success or failure
     */
    suspend fun cancelTask(taskId: String): Result<Unit>
    
    /**
     * Cancels all background tasks.
     * 
     * @return Result indicating success or failure
     */
    suspend fun cancelAllTasks(): Result<Unit>
    
    /**
     * Gets the status of a background task.
     * 
     * @param taskId The ID of the task to check
     * @return Result containing the task status
     */
    suspend fun getTaskStatus(taskId: String): Result<TaskStatus>
    
    /**
     * Gets all scheduled background tasks.
     * 
     * @return Result containing list of task info
     */
    suspend fun getAllTasks(): Result<List<TaskInfo>>
}

/**
 * Background scan request for one-time execution.
 */
data class BackgroundScanRequest(
    val content: String,
    val scanType: ScanType,
    val scheduledTime: Instant? = null, // null for immediate execution
    val requiresNetwork: Boolean = true,
    val requiresCharging: Boolean = false,
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Periodic background scan request.
 */
data class PeriodicScanRequest(
    val content: String,
    val scanType: ScanType,
    val intervalMinutes: Long = 60, // Default 1 hour
    val flexIntervalMinutes: Long = 15, // Default 15 minutes flexibility
    val requiresNetwork: Boolean = true,
    val requiresCharging: Boolean = false,
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Types of scans that can be scheduled.
 */
enum class ScanType {
    URL,
    EMAIL,
    FILE_HASH,
    AUTO_DETECT
}

/**
 * Task execution status.
 */
enum class TaskStatus {
    ENQUEUED,
    RUNNING,
    SUCCEEDED,
    FAILED,
    BLOCKED,
    CANCELLED
}

/**
 * Background task information.
 */
data class TaskInfo(
    val id: String,
    val type: TaskType,
    val status: TaskStatus,
    val createdAt: Instant,
    val scheduledAt: Instant? = null,
    val completedAt: Instant? = null,
    val runAttemptCount: Int = 0,
    val lastFailureReason: String? = null,
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Background task types.
 */
enum class TaskType {
    ONE_TIME_SCAN,
    PERIODIC_SCAN,
    CACHE_CLEANUP,
    DATA_SYNC
}

/**
 * Task execution constraints.
 */
data class TaskConstraints(
    val requiresNetwork: Boolean = true,
    val requiresCharging: Boolean = false,
    val requiresDeviceIdle: Boolean = false,
    val requiresStorageNotLow: Boolean = false,
    val requiredNetworkType: NetworkType = NetworkType.CONNECTED
)

/**
 * Network type requirements for tasks.
 */
enum class NetworkType {
    NOT_REQUIRED,
    CONNECTED,
    UNMETERED,
    NOT_ROAMING,
    METERED
}

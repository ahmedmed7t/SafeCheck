package com.nexable.safecheck.core.platform.background

import android.content.Context
import androidx.work.*
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Android implementation of background task scheduler using WorkManager.
 */
actual class BackgroundTaskScheduler {
    
    private var context: Context? = null
    private var workManager: WorkManager? = null
    
    /**
     * Initialize the background task scheduler with Android context.
     */
    fun initialize(context: Context) {
        this.context = context
        this.workManager = WorkManager.getInstance(context)
    }
    
    actual suspend fun scheduleOneTimeScan(request: BackgroundScanRequest): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                val workManager = workManager ?: return@withContext Result.error(
                    "BackgroundTaskScheduler not initialized", 
                    "SCHEDULER_NOT_INITIALIZED"
                )
                
                val inputData = createInputData(request.content, request.scanType, request.metadata)
                val constraints = createConstraints(request.requiresNetwork, request.requiresCharging)
                
                val workRequestBuilder = OneTimeWorkRequestBuilder<ScanWorker>()
                    .setInputData(inputData)
                    .setConstraints(constraints)
                    .addTag("scan_task")
                    .addTag("one_time")
                
                // Add delay if scheduled time is provided
                request.scheduledTime?.let { scheduledTime ->
                    val currentTime = Clock.System.now()
                    val delayMs = (scheduledTime.toEpochMilliseconds() - currentTime.toEpochMilliseconds())
                    if (delayMs > 0) {
                        workRequestBuilder.setInitialDelay(delayMs, TimeUnit.MILLISECONDS)
                    }
                }
                
                val workRequest = workRequestBuilder.build()
                workManager.enqueue(workRequest)
                
                Result.success(workRequest.id.toString())
            } catch (e: Exception) {
                Result.error("Failed to schedule scan task: ${e.message}", "SCHEDULE_FAILED")
            }
        }
    }
    
    actual suspend fun schedulePeriodicScan(request: PeriodicScanRequest): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                val workManager = workManager ?: return@withContext Result.error(
                    "BackgroundTaskScheduler not initialized", 
                    "SCHEDULER_NOT_INITIALIZED"
                )
                
                val inputData = createInputData(request.content, request.scanType, request.metadata)
                val constraints = createConstraints(request.requiresNetwork, request.requiresCharging)
                
                val workRequest = PeriodicWorkRequestBuilder<ScanWorker>(
                    request.intervalMinutes, 
                    TimeUnit.MINUTES,
                    request.flexIntervalMinutes,
                    TimeUnit.MINUTES
                )
                    .setInputData(inputData)
                    .setConstraints(constraints)
                    .addTag("scan_task")
                    .addTag("periodic")
                    .build()
                
                workManager.enqueue(workRequest)
                
                Result.success(workRequest.id.toString())
            } catch (e: Exception) {
                Result.error("Failed to schedule periodic scan: ${e.message}", "SCHEDULE_PERIODIC_FAILED")
            }
        }
    }
    
    actual suspend fun cancelTask(taskId: String): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                val workManager = workManager ?: return@withContext Result.error(
                    "BackgroundTaskScheduler not initialized", 
                    "SCHEDULER_NOT_INITIALIZED"
                )
                
                val uuid = UUID.fromString(taskId)
                workManager.cancelWorkById(uuid)
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to cancel task: ${e.message}", "CANCEL_FAILED")
            }
        }
    }
    
    actual suspend fun cancelAllTasks(): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                val workManager = workManager ?: return@withContext Result.error(
                    "BackgroundTaskScheduler not initialized", 
                    "SCHEDULER_NOT_INITIALIZED"
                )
                
                workManager.cancelAllWorkByTag("scan_task")
                
                Result.success(Unit)
            } catch (e: Exception) {
                Result.error("Failed to cancel all tasks: ${e.message}", "CANCEL_ALL_FAILED")
            }
        }
    }
    
    actual suspend fun getTaskStatus(taskId: String): Result<TaskStatus> {
        return withContext(Dispatchers.IO) {
            try {
                val workManager = workManager ?: return@withContext Result.error(
                    "BackgroundTaskScheduler not initialized", 
                    "SCHEDULER_NOT_INITIALIZED"
                )
                
                val uuid = UUID.fromString(taskId)
                val workInfo = workManager.getWorkInfoById(uuid).get()
                
                val status = when (workInfo?.state) {
                    WorkInfo.State.ENQUEUED -> TaskStatus.ENQUEUED
                    WorkInfo.State.RUNNING -> TaskStatus.RUNNING
                    WorkInfo.State.SUCCEEDED -> TaskStatus.SUCCEEDED
                    WorkInfo.State.FAILED -> TaskStatus.FAILED
                    WorkInfo.State.BLOCKED -> TaskStatus.BLOCKED
                    WorkInfo.State.CANCELLED -> TaskStatus.CANCELLED
                    null -> TaskStatus.FAILED
                }
                
                Result.success(status)
            } catch (e: Exception) {
                Result.error("Failed to get task status: ${e.message}", "STATUS_CHECK_FAILED")
            }
        }
    }
    
    actual suspend fun getAllTasks(): Result<List<TaskInfo>> {
        return withContext(Dispatchers.IO) {
            try {
                val workManager = workManager ?: return@withContext Result.error(
                    "BackgroundTaskScheduler not initialized", 
                    "SCHEDULER_NOT_INITIALIZED"
                )
                
                val workInfos = workManager.getWorkInfosByTag("scan_task").get()
                
                val taskInfos = workInfos.map { workInfo ->
                    val status = when (workInfo.state) {
                        WorkInfo.State.ENQUEUED -> TaskStatus.ENQUEUED
                        WorkInfo.State.RUNNING -> TaskStatus.RUNNING
                        WorkInfo.State.SUCCEEDED -> TaskStatus.SUCCEEDED
                        WorkInfo.State.FAILED -> TaskStatus.FAILED
                        WorkInfo.State.BLOCKED -> TaskStatus.BLOCKED
                        WorkInfo.State.CANCELLED -> TaskStatus.CANCELLED
                    }
                    
                    val isPeriodicTask = workInfo.tags.contains("periodic")
                    val taskType = if (isPeriodicTask) TaskType.PERIODIC_SCAN else TaskType.ONE_TIME_SCAN
                    
                    TaskInfo(
                        id = workInfo.id.toString(),
                        type = taskType,
                        status = status,
                        createdAt = Clock.System.now(), // WorkManager doesn't provide creation time
                        runAttemptCount = workInfo.runAttemptCount,
                        metadata = emptyMap() // Could extract from input data if needed
                    )
                }
                
                Result.success(taskInfos)
            } catch (e: Exception) {
                Result.error("Failed to get all tasks: ${e.message}", "GET_ALL_TASKS_FAILED")
            }
        }
    }
    
    /**
     * Creates input data for WorkManager from scan parameters.
     */
    private fun createInputData(
        content: String,
        scanType: ScanType,
        metadata: Map<String, String>
    ): Data {
        val builder = Data.Builder()
            .putString(KEY_CONTENT, content)
            .putString(KEY_SCAN_TYPE, scanType.name)
        
        // Add metadata with prefix to avoid conflicts
        metadata.forEach { (key, value) ->
            builder.putString("meta_$key", value)
        }
        
        return builder.build()
    }
    
    /**
     * Creates WorkManager constraints from scan requirements.
     */
    private fun createConstraints(
        requiresNetwork: Boolean,
        requiresCharging: Boolean
    ): Constraints {
        return Constraints.Builder()
            .setRequiredNetworkType(
                if (requiresNetwork) androidx.work.NetworkType.CONNECTED else androidx.work.NetworkType.NOT_REQUIRED
            )
            .setRequiresCharging(requiresCharging)
            .build()
    }
    
    companion object {
        const val KEY_CONTENT = "scan_content"
        const val KEY_SCAN_TYPE = "scan_type"
        
        /**
         * Create and initialize background task scheduler with context.
         */
        fun create(context: Context): BackgroundTaskScheduler {
            val scheduler = BackgroundTaskScheduler()
            scheduler.initialize(context)
            return scheduler
        }
    }
}

/**
 * WorkManager Worker class for executing background scans.
 */
class ScanWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {
    
    override suspend fun doWork(): androidx.work.ListenableWorker.Result {
        return try {
            val content = inputData.getString(BackgroundTaskScheduler.KEY_CONTENT)
                ?: return androidx.work.ListenableWorker.Result.failure()
            
            val scanTypeStr = inputData.getString(BackgroundTaskScheduler.KEY_SCAN_TYPE)
                ?: return androidx.work.ListenableWorker.Result.failure()
            
            val scanType = ScanType.valueOf(scanTypeStr)
            
            // TODO: Implement actual scan logic here
            // This would integrate with the SafeCheckService from the domain layer
            // For now, we'll just simulate success
            
            androidx.work.ListenableWorker.Result.success()
        } catch (e: Exception) {
            androidx.work.ListenableWorker.Result.failure(
                Data.Builder()
                    .putString("error", e.message)
                    .build()
            )
        }
    }
}

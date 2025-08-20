package com.nexable.safecheck.core.domain.util

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.delay
import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Retry policy implementation with capped exponential backoff and jitter.
 * Provides configurable retry strategies for external service calls.
 */
class RetryPolicy(
    private val maxAttempts: Int = 3,
    private val baseDelay: Duration = 100.milliseconds,
    private val maxDelay: Duration = 1.seconds,
    private val multiplier: Double = 2.0,
    private val jitterFactor: Double = 0.1,
    private val retryableExceptions: Set<String> = defaultRetryableExceptions
) {
    
    companion object {
        private val defaultRetryableExceptions = setOf(
            "IOException",
            "SocketTimeoutException",
            "ConnectException",
            "UnknownHostException",
            "NetworkException",
            "TimeoutException"
        )
    }
    
    /**
     * Executes an operation with retry logic.
     * 
     * @param operation The operation to execute
     * @return Result of the operation after all retry attempts
     */
    suspend fun <T> execute(operation: suspend () -> Result<T>): Result<T> {
        var lastResult: Result<T>? = null
        var attempt = 1
        
        while (attempt <= maxAttempts) {
            try {
                val result = operation()
                
                when (result) {
                    is Result.Success -> return result
                    is Result.Error -> {
                        lastResult = result
                        
                        if (attempt >= maxAttempts || !shouldRetry(result)) {
                            return result
                        }
                        
                        val delayDuration = calculateDelay(attempt)
                        delay(delayDuration)
                        attempt++
                    }
                    is Result.Loading -> return result
                }
                
            } catch (e: Exception) {
                lastResult = Result.error(
                    message = "Operation failed: ${e.message}",
                    code = "OPERATION_FAILED",
                    details = mapOf(
                        "attempt" to attempt.toString(),
                        "exception" to e::class.simpleName.orEmpty()
                    )
                )
                
                if (attempt >= maxAttempts || !shouldRetryException(e)) {
                    return lastResult
                }
                
                val delayDuration = calculateDelay(attempt)
                delay(delayDuration)
                attempt++
            }
        }
        
        return lastResult ?: Result.error("All retry attempts failed", "RETRY_EXHAUSTED")
    }
    
    /**
     * Executes an operation with retry logic and progress callback.
     * 
     * @param operation The operation to execute
     * @param onRetry Callback invoked before each retry attempt
     * @return Result of the operation after all retry attempts
     */
    suspend fun <T> executeWithCallback(
        operation: suspend () -> Result<T>,
        onRetry: suspend (attempt: Int, delay: Duration, lastError: String?) -> Unit = { _, _, _ -> }
    ): Result<T> {
        var lastResult: Result<T>? = null
        var attempt = 1
        
        while (attempt <= maxAttempts) {
            try {
                if (attempt > 1) {
                    val delay = calculateDelay(attempt - 1)
                    val lastError = when (lastResult) {
                        is Result.Error -> lastResult.message
                        else -> null
                    }
                    onRetry(attempt, delay, lastError)
                    delay(delay)
                }
                
                val result = operation()
                
                when (result) {
                    is Result.Success -> return result
                    is Result.Error -> {
                        lastResult = result
                        
                        if (attempt >= maxAttempts || !shouldRetry(result)) {
                            return result
                        }
                        
                        attempt++
                    }
                    is Result.Loading -> return result
                }
                
            } catch (e: Exception) {
                lastResult = Result.error(
                    message = "Operation failed: ${e.message}",
                    code = "OPERATION_FAILED",
                    details = mapOf(
                        "attempt" to attempt.toString(),
                        "exception" to e::class.simpleName.orEmpty()
                    )
                )
                
                if (attempt >= maxAttempts || !shouldRetryException(e)) {
                    return lastResult
                }
                
                attempt++
            }
        }
        
        return lastResult ?: Result.error("All retry attempts failed", "RETRY_EXHAUSTED")
    }
    
    /**
     * Calculates the delay for a given attempt using exponential backoff with jitter.
     * 
     * @param attempt The current attempt number (1-based)
     * @return Duration to wait before the next attempt
     */
    private fun calculateDelay(attempt: Int): Duration {
        val exponentialDelay = baseDelay.inWholeMilliseconds * multiplier.pow(attempt - 1)
        val cappedDelay = min(exponentialDelay, maxDelay.inWholeMilliseconds.toDouble())
        
        // Add jitter to prevent thundering herd
        val jitter = cappedDelay * jitterFactor * (Random.nextDouble() * 2 - 1) // ±jitterFactor
        val finalDelay = cappedDelay + jitter
        
        return finalDelay.toLong().milliseconds
    }
    
    /**
     * Determines if a Result.Error should be retried.
     */
    private fun shouldRetry(result: Result.Error): Boolean {
        return when (result.code) {
            "NETWORK_ERROR", "TIMEOUT", "SERVICE_UNAVAILABLE", 
            "RATE_LIMITED", "TEMPORARY_FAILURE" -> true
            "INVALID_INPUT", "AUTHENTICATION_FAILED", 
            "PERMISSION_DENIED", "NOT_FOUND" -> false
            else -> retryableExceptions.any { exception ->
                result.message.contains(exception, ignoreCase = true) ||
                result.details.values.any { it.contains(exception, ignoreCase = true) }
            }
        }
    }
    
    /**
     * Determines if an exception should be retried.
     */
    private fun shouldRetryException(exception: Exception): Boolean {
        val exceptionName = exception::class.simpleName.orEmpty()
        return retryableExceptions.any { retryable ->
            exceptionName.contains(retryable, ignoreCase = true)
        }
    }
    
    /**
     * Gets retry information for the next attempt.
     * 
     * @param attempt Current attempt number
     * @return RetryInfo with delay and remaining attempts
     */
    fun getRetryInfo(attempt: Int): RetryInfo {
        return RetryInfo(
            attempt = attempt,
            maxAttempts = maxAttempts,
            nextDelay = if (attempt < maxAttempts) calculateDelay(attempt) else Duration.ZERO,
            remainingAttempts = maxOf(0, maxAttempts - attempt)
        )
    }
}

/**
 * Information about retry attempts.
 */
data class RetryInfo(
    val attempt: Int,
    val maxAttempts: Int,
    val nextDelay: Duration,
    val remainingAttempts: Int
) {
    val isLastAttempt: Boolean = attempt >= maxAttempts
    val hasRemainingAttempts: Boolean = remainingAttempts > 0
}

/**
 * Retry policy factory for common configurations.
 */
object RetryPolicies {
    /**
     * Default retry policy: 3 attempts, 100ms→1s exponential backoff.
     */
    fun default() = RetryPolicy(
        maxAttempts = 3,
        baseDelay = 100.milliseconds,
        maxDelay = 1.seconds,
        multiplier = 2.0,
        jitterFactor = 0.1
    )
    
    /**
     * Fast retry policy: 2 attempts, 50ms→200ms backoff.
     */
    fun fast() = RetryPolicy(
        maxAttempts = 2,
        baseDelay = 50.milliseconds,
        maxDelay = 200.milliseconds,
        multiplier = 2.0,
        jitterFactor = 0.05
    )
    
    /**
     * Conservative retry policy: 5 attempts, 200ms→5s backoff.
     */
    fun conservative() = RetryPolicy(
        maxAttempts = 5,
        baseDelay = 200.milliseconds,
        maxDelay = 5.seconds,
        multiplier = 2.0,
        jitterFactor = 0.2
    )
    
    /**
     * No retry policy: single attempt only.
     */
    fun none() = RetryPolicy(
        maxAttempts = 1,
        baseDelay = Duration.ZERO,
        maxDelay = Duration.ZERO
    )
    
    /**
     * Custom retry policy with specific parameters.
     */
    fun custom(
        maxAttempts: Int,
        baseDelay: Duration,
        maxDelay: Duration,
        multiplier: Double = 2.0,
        jitterFactor: Double = 0.1
    ) = RetryPolicy(
        maxAttempts = maxAttempts,
        baseDelay = baseDelay,
        maxDelay = maxDelay,
        multiplier = multiplier,
        jitterFactor = jitterFactor
    )
}

/**
 * Extension function to add retry capability to any suspend function.
 */
suspend fun <T> (() -> Result<T>).withRetry(
    policy: RetryPolicy = RetryPolicies.default()
): Result<T> = policy.execute { this() }

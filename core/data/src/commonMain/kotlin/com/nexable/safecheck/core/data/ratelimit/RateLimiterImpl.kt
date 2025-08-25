package com.nexable.safecheck.core.data.ratelimit

import com.nexable.safecheck.core.domain.util.RateLimiter
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Comprehensive rate limiting implementation for external API calls.
 */
class RateLimiterImpl : RateLimiter {
    
    private val limiters = mutableMapOf<String, ServiceRateLimiter>()
    private val mutex = Mutex()
    
    companion object {
        // Default rate limits for various services
        val DEFAULT_LIMITS = mapOf(
            "virustotal" to RateLimit(4, 60), // 4 requests per minute
            "virustotal_public" to RateLimit(500, 24 * 60 * 60), // 500 requests per day
            "dns" to RateLimit(100, 60), // 100 DNS queries per minute
            "whois" to RateLimit(10, 60), // 10 WHOIS queries per minute
            "reputation" to RateLimit(200, 60), // 200 reputation checks per minute
            "default" to RateLimit(60, 60) // 60 requests per minute default
        )
    }
    
    override suspend fun isAllowed(service: String): Boolean {
        return mutex.withLock {
            val limiter = getLimiter(service)
            limiter.isAllowed()
        }
    }
    
    override suspend fun recordRequest(service: String): Boolean {
        return mutex.withLock {
            val limiter = getLimiter(service)
            limiter.recordRequest()
        }
    }
    
    override suspend fun getRemainingRequests(service: String): Int {
        return mutex.withLock {
            val limiter = getLimiter(service)
            limiter.getRemainingRequests()
        }
    }
    
    override suspend fun getResetTime(service: String): Instant {
        return mutex.withLock {
            val limiter = getLimiter(service)
            limiter.getResetTime()
        }
    }
    
    override suspend fun waitForReset(service: String): Long {
        return mutex.withLock {
            val limiter = getLimiter(service)
            limiter.getWaitTimeMs()
        }
    }
    
    /**
     * Sets custom rate limit for a service.
     */
    suspend fun setRateLimit(service: String, limit: RateLimit) {
        mutex.withLock {
            limiters[service] = ServiceRateLimiter(limit)
        }
    }
    
    /**
     * Gets rate limit statistics for a service.
     */
    suspend fun getStatistics(service: String): RateLimitStatistics {
        return mutex.withLock {
            val limiter = getLimiter(service)
            limiter.getStatistics()
        }
    }
    
    /**
     * Gets statistics for all services.
     */
    suspend fun getAllStatistics(): Map<String, RateLimitStatistics> {
        return mutex.withLock {
            limiters.mapValues { (_, limiter) ->
                limiter.getStatistics()
            }
        }
    }
    
    /**
     * Resets rate limiter for a service.
     */
    suspend fun reset(service: String) {
        mutex.withLock {
            limiters.remove(service)
        }
    }
    
    /**
     * Resets all rate limiters.
     */
    suspend fun resetAll() {
        mutex.withLock {
            limiters.clear()
        }
    }
    
    private fun getLimiter(service: String): ServiceRateLimiter {
        return limiters.getOrPut(service) {
            val limit = DEFAULT_LIMITS[service] ?: DEFAULT_LIMITS["default"]!!
            ServiceRateLimiter(limit)
        }
    }
}

/**
 * Rate limiter for a specific service.
 */
private class ServiceRateLimiter(
    private val rateLimit: RateLimit
) {
    private val requests = mutableListOf<Instant>()
    private var totalRequests = 0L
    private var rejectedRequests = 0L
    private var createdAt = Clock.System.now()
    
    fun isAllowed(): Boolean {
        cleanupOldRequests()
        return requests.size < rateLimit.maxRequests
    }
    
    fun recordRequest(): Boolean {
        cleanupOldRequests()
        
        if (requests.size >= rateLimit.maxRequests) {
            rejectedRequests++
            return false
        }
        
        requests.add(Clock.System.now())
        totalRequests++
        return true
    }
    
    fun getRemainingRequests(): Int {
        cleanupOldRequests()
        return (rateLimit.maxRequests - requests.size).coerceAtLeast(0)
    }
    
    fun getResetTime(): Instant {
        cleanupOldRequests()
        
        return if (requests.isEmpty()) {
            Clock.System.now()
        } else {
            requests.first().plus(kotlinx.datetime.DateTimeUnit.SECOND, rateLimit.windowSeconds)
        }
    }
    
    fun getWaitTimeMs(): Long {
        if (isAllowed()) return 0L
        
        val resetTime = getResetTime()
        val now = Clock.System.now()
        
        return if (resetTime > now) {
            resetTime.toEpochMilliseconds() - now.toEpochMilliseconds()
        } else {
            0L
        }
    }
    
    fun getStatistics(): RateLimitStatistics {
        cleanupOldRequests()
        
        val now = Clock.System.now()
        val currentWindowStart = now.minus(kotlinx.datetime.DateTimeUnit.SECOND, rateLimit.windowSeconds)
        val requestsInCurrentWindow = requests.count { it >= currentWindowStart }
        
        return RateLimitStatistics(
            service = "", // Will be set by caller
            maxRequests = rateLimit.maxRequests,
            windowSeconds = rateLimit.windowSeconds,
            currentRequests = requests.size,
            remainingRequests = getRemainingRequests(),
            totalRequests = totalRequests,
            rejectedRequests = rejectedRequests,
            requestsInCurrentWindow = requestsInCurrentWindow,
            resetTime = getResetTime(),
            createdAt = createdAt,
            lastRequestAt = requests.lastOrNull(),
            averageRequestsPerWindow = if (createdAt < now) {
                val totalWindows = (now.epochSeconds - createdAt.epochSeconds) / rateLimit.windowSeconds
                if (totalWindows > 0) totalRequests / totalWindows else 0.0
            } else {
                0.0
            }
        )
    }
    
    private fun cleanupOldRequests() {
        val cutoff = Clock.System.now().minus(kotlinx.datetime.DateTimeUnit.SECOND, rateLimit.windowSeconds)
        requests.removeAll { it < cutoff }
    }
}

/**
 * Rate limit configuration.
 */
data class RateLimit(
    val maxRequests: Int,
    val windowSeconds: Int
)

/**
 * Rate limit statistics.
 */
data class RateLimitStatistics(
    val service: String,
    val maxRequests: Int,
    val windowSeconds: Int,
    val currentRequests: Int,
    val remainingRequests: Int,
    val totalRequests: Long,
    val rejectedRequests: Long,
    val requestsInCurrentWindow: Int,
    val resetTime: Instant,
    val createdAt: Instant,
    val lastRequestAt: Instant?,
    val averageRequestsPerWindow: Double
)

/**
 * Advanced rate limiter with burst handling and backoff strategies.
 */
class AdvancedRateLimiter {
    
    private val limiters = mutableMapOf<String, AdvancedServiceLimiter>()
    private val mutex = Mutex()
    
    /**
     * Rate limiter with burst capacity and exponential backoff.
     */
    suspend fun isAllowedWithBurst(
        service: String,
        burstCapacity: Int = 10,
        backoffMultiplier: Double = 2.0
    ): RateLimitResult {
        return mutex.withLock {
            val limiter = limiters.getOrPut(service) {
                val baseLimit = RateLimiterImpl.DEFAULT_LIMITS[service] 
                    ?: RateLimiterImpl.DEFAULT_LIMITS["default"]!!
                AdvancedServiceLimiter(baseLimit, burstCapacity, backoffMultiplier)
            }
            
            limiter.checkAndRecord()
        }
    }
    
    /**
     * Adaptive rate limiter that adjusts based on response times and errors.
     */
    suspend fun recordResponse(
        service: String,
        responseTimeMs: Long,
        isError: Boolean,
        errorType: String? = null
    ) {
        mutex.withLock {
            limiters[service]?.recordResponse(responseTimeMs, isError, errorType)
        }
    }
    
    /**
     * Gets adaptive rate limit recommendations.
     */
    suspend fun getAdaptiveRecommendations(service: String): AdaptiveRecommendations? {
        return mutex.withLock {
            limiters[service]?.getAdaptiveRecommendations()
        }
    }
}

/**
 * Advanced service limiter with burst and backoff capabilities.
 */
private class AdvancedServiceLimiter(
    private val baseLimit: RateLimit,
    private val burstCapacity: Int,
    private val backoffMultiplier: Double
) {
    private val requests = mutableListOf<RequestRecord>()
    private val responses = mutableListOf<ResponseRecord>()
    private var consecutiveErrors = 0
    private var lastErrorTime: Instant? = null
    
    fun checkAndRecord(): RateLimitResult {
        cleanupOldRecords()
        
        val now = Clock.System.now()
        val currentRequests = requests.size
        
        // Check base rate limit
        if (currentRequests >= baseLimit.maxRequests) {
            val backoffTime = calculateBackoffTime()
            return RateLimitResult.RateLimited(
                resetTime = getResetTime(),
                backoffTime = backoffTime,
                reason = "Base rate limit exceeded"
            )
        }
        
        // Check burst capacity
        val recentRequests = requests.count { 
            it.timestamp >= now.minus(kotlinx.datetime.DateTimeUnit.SECOND, 10) // Last 10 seconds
        }
        
        if (recentRequests >= burstCapacity) {
            return RateLimitResult.RateLimited(
                resetTime = now.plus(kotlinx.datetime.DateTimeUnit.SECOND, 10),
                backoffTime = 10000, // 10 seconds
                reason = "Burst capacity exceeded"
            )
        }
        
        // Check error-based backoff
        lastErrorTime?.let { errorTime ->
            val backoffDuration = calculateBackoffTime()
            if (now < errorTime.plus(kotlinx.datetime.DateTimeUnit.MILLISECOND, backoffDuration.toInt())) {
                return RateLimitResult.RateLimited(
                    resetTime = errorTime.plus(kotlinx.datetime.DateTimeUnit.MILLISECOND, backoffDuration.toInt()),
                    backoffTime = backoffDuration,
                    reason = "Error backoff active"
                )
            }
        }
        
        // Record the request
        requests.add(RequestRecord(now))
        
        return RateLimitResult.Allowed(
            remainingRequests = baseLimit.maxRequests - requests.size,
            remainingBurst = burstCapacity - recentRequests - 1,
            resetTime = getResetTime()
        )
    }
    
    fun recordResponse(responseTimeMs: Long, isError: Boolean, errorType: String?) {
        val now = Clock.System.now()
        
        responses.add(ResponseRecord(
            timestamp = now,
            responseTimeMs = responseTimeMs,
            isError = isError,
            errorType = errorType
        ))
        
        if (isError) {
            consecutiveErrors++
            lastErrorTime = now
        } else {
            consecutiveErrors = 0
            lastErrorTime = null
        }
        
        // Keep only recent responses for analysis
        val cutoff = now.minus(kotlinx.datetime.DateTimeUnit.MINUTE, 10)
        responses.removeAll { it.timestamp < cutoff }
    }
    
    fun getAdaptiveRecommendations(): AdaptiveRecommendations {
        val recentResponses = responses.filter { 
            it.timestamp >= Clock.System.now().minus(kotlinx.datetime.DateTimeUnit.MINUTE, 5)
        }
        
        val avgResponseTime = recentResponses.mapNotNull { 
            if (!it.isError) it.responseTimeMs else null 
        }.average()
        
        val errorRate = if (recentResponses.isNotEmpty()) {
            recentResponses.count { it.isError }.toDouble() / recentResponses.size
        } else 0.0
        
        return AdaptiveRecommendations(
            recommendedRequestsPerMinute = calculateAdaptiveRate(avgResponseTime, errorRate),
            averageResponseTime = avgResponseTime,
            errorRate = errorRate,
            consecutiveErrors = consecutiveErrors,
            shouldReduceRate = errorRate > 0.1 || avgResponseTime > 5000,
            shouldIncreaseRate = errorRate < 0.01 && avgResponseTime < 1000
        )
    }
    
    private fun calculateAdaptiveRate(avgResponseTime: Double, errorRate: Double): Int {
        var baseRate = baseLimit.maxRequests
        
        // Adjust based on response time
        when {
            avgResponseTime > 5000 -> baseRate = (baseRate * 0.5).toInt()
            avgResponseTime > 2000 -> baseRate = (baseRate * 0.7).toInt()
            avgResponseTime < 500 -> baseRate = (baseRate * 1.2).toInt()
        }
        
        // Adjust based on error rate
        when {
            errorRate > 0.2 -> baseRate = (baseRate * 0.3).toInt()
            errorRate > 0.1 -> baseRate = (baseRate * 0.6).toInt()
            errorRate < 0.01 -> baseRate = (baseRate * 1.1).toInt()
        }
        
        return baseRate.coerceIn(1, baseLimit.maxRequests * 2)
    }
    
    private fun calculateBackoffTime(): Long {
        if (consecutiveErrors == 0) return 0L
        
        val baseBackoff = 1000L // 1 second
        return (baseBackoff * kotlin.math.pow(backoffMultiplier, consecutiveErrors.toDouble())).toLong()
            .coerceAtMost(300000L) // Max 5 minutes
    }
    
    private fun getResetTime(): Instant {
        return if (requests.isEmpty()) {
            Clock.System.now()
        } else {
            requests.first().timestamp.plus(kotlinx.datetime.DateTimeUnit.SECOND, baseLimit.windowSeconds)
        }
    }
    
    private fun cleanupOldRecords() {
        val cutoff = Clock.System.now().minus(kotlinx.datetime.DateTimeUnit.SECOND, baseLimit.windowSeconds)
        requests.removeAll { it.timestamp < cutoff }
    }
}

/**
 * Request record for tracking.
 */
private data class RequestRecord(
    val timestamp: Instant
)

/**
 * Response record for adaptive rate limiting.
 */
private data class ResponseRecord(
    val timestamp: Instant,
    val responseTimeMs: Long,
    val isError: Boolean,
    val errorType: String?
)

/**
 * Rate limit check result.
 */
sealed class RateLimitResult {
    data class Allowed(
        val remainingRequests: Int,
        val remainingBurst: Int,
        val resetTime: Instant
    ) : RateLimitResult()
    
    data class RateLimited(
        val resetTime: Instant,
        val backoffTime: Long,
        val reason: String
    ) : RateLimitResult()
}

/**
 * Adaptive rate limit recommendations.
 */
data class AdaptiveRecommendations(
    val recommendedRequestsPerMinute: Int,
    val averageResponseTime: Double,
    val errorRate: Double,
    val consecutiveErrors: Int,
    val shouldReduceRate: Boolean,
    val shouldIncreaseRate: Boolean
)

package com.nexable.safecheck.core.domain.util

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Token bucket rate limiter implementation for controlling request rates to external services.
 * Supports per-source rate limiting with configurable token replenishment.
 */
class RateLimiter(
    private val maxTokens: Int = 10,
    private val refillRate: Duration = 1.minutes,
    private val burstSize: Int = maxTokens
) {
    private val buckets = mutableMapOf<String, TokenBucket>()
    private val mutex = Mutex()
    
    /**
     * Attempts to acquire a token for the specified source.
     * 
     * @param source The source identifier (e.g., "virustotal", "urlvoid")
     * @param tokens Number of tokens to acquire (default: 1)
     * @return RateLimitResult indicating success or failure with retry info
     */
    suspend fun tryAcquire(source: String, tokens: Int = 1): RateLimitResult {
        mutex.withLock {
            val bucket = buckets.getOrPut(source) { 
                TokenBucket(maxTokens, refillRate, burstSize) 
            }
            
            bucket.refill()
            
            return if (bucket.tryConsume(tokens)) {
                RateLimitResult.Allowed(
                    remainingTokens = bucket.availableTokens,
                    resetTime = bucket.nextRefillTime
                )
            } else {
                RateLimitResult.RateLimited(
                    retryAfter = bucket.timeUntilNextToken(),
                    resetTime = bucket.nextRefillTime,
                    availableTokens = bucket.availableTokens
                )
            }
        }
    }
    
    /**
     * Gets the current status for a source without consuming tokens.
     * 
     * @param source The source identifier
     * @return RateLimitStatus with current token availability
     */
    suspend fun getStatus(source: String): RateLimitStatus {
        mutex.withLock {
            val bucket = buckets[source] ?: return RateLimitStatus(
                availableTokens = maxTokens,
                maxTokens = maxTokens,
                nextRefillTime = Clock.System.now().plus(refillRate)
            )
            
            bucket.refill()
            
            return RateLimitStatus(
                availableTokens = bucket.availableTokens,
                maxTokens = maxTokens,
                nextRefillTime = bucket.nextRefillTime
            )
        }
    }
    
    /**
     * Clears all rate limit state for a specific source.
     * 
     * @param source The source to reset
     */
    suspend fun reset(source: String) {
        mutex.withLock {
            buckets.remove(source)
        }
    }
    
    /**
     * Clears all rate limit state.
     */
    suspend fun resetAll() {
        mutex.withLock {
            buckets.clear()
        }
    }
}

/**
 * Result of a rate limit check.
 */
sealed class RateLimitResult {
    /**
     * Request is allowed to proceed.
     */
    data class Allowed(
        val remainingTokens: Int,
        val resetTime: Instant
    ) : RateLimitResult()
    
    /**
     * Request is rate limited.
     */
    data class RateLimited(
        val retryAfter: Duration,
        val resetTime: Instant,
        val availableTokens: Int
    ) : RateLimitResult()
}

/**
 * Current rate limit status for a source.
 */
data class RateLimitStatus(
    val availableTokens: Int,
    val maxTokens: Int,
    val nextRefillTime: Instant
) {
    val isAtLimit: Boolean = availableTokens == 0
    val utilizationPercent: Double = (maxTokens - availableTokens) / maxTokens.toDouble() * 100
}

/**
 * Token bucket implementation for rate limiting.
 */
private class TokenBucket(
    private val capacity: Int,
    private val refillPeriod: Duration,
    private val burstSize: Int = capacity
) {
    var availableTokens: Int = capacity
        private set
    
    private var lastRefillTime: Instant = Clock.System.now()
    
    val nextRefillTime: Instant
        get() = lastRefillTime.plus(refillPeriod)
    
    /**
     * Refills tokens based on elapsed time.
     */
    fun refill() {
        val now = Clock.System.now()
        val timeSinceLastRefill = now - lastRefillTime
        
        if (timeSinceLastRefill >= refillPeriod) {
            val periodsElapsed = (timeSinceLastRefill.inWholeMilliseconds / refillPeriod.inWholeMilliseconds).toInt()
            val tokensToAdd = minOf(periodsElapsed, capacity - availableTokens)
            
            availableTokens = minOf(capacity, availableTokens + tokensToAdd)
            lastRefillTime = now
        }
    }
    
    /**
     * Attempts to consume the specified number of tokens.
     * 
     * @param tokens Number of tokens to consume
     * @return true if tokens were consumed, false if insufficient tokens
     */
    fun tryConsume(tokens: Int): Boolean {
        return if (availableTokens >= tokens) {
            availableTokens -= tokens
            true
        } else {
            false
        }
    }
    
    /**
     * Calculates time until the next token becomes available.
     */
    fun timeUntilNextToken(): Duration {
        val now = Clock.System.now()
        val nextRefill = lastRefillTime.plus(refillPeriod)
        
        return if (nextRefill > now) {
            nextRefill - now
        } else {
            Duration.ZERO
        }
    }
}

/**
 * Rate limiter factory for common configurations.
 */
object RateLimiters {
    /**
     * Default rate limiter: 10 requests per minute with burst of 10.
     */
    fun default() = RateLimiter(
        maxTokens = 10,
        refillRate = 1.minutes,
        burstSize = 10
    )
    
    /**
     * Conservative rate limiter: 5 requests per minute with burst of 3.
     */
    fun conservative() = RateLimiter(
        maxTokens = 5,
        refillRate = 1.minutes,
        burstSize = 3
    )
    
    /**
     * Aggressive rate limiter: 30 requests per minute with burst of 15.
     */
    fun aggressive() = RateLimiter(
        maxTokens = 30,
        refillRate = 1.minutes,
        burstSize = 15
    )
    
    /**
     * Per-second rate limiter: 1 request per second with burst of 5.
     */
    fun perSecond(requestsPerSecond: Int = 1, burstSize: Int = 5) = RateLimiter(
        maxTokens = requestsPerSecond,
        refillRate = 1.seconds,
        burstSize = burstSize
    )
}

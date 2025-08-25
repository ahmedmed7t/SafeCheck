package com.nexable.safecheck.core.data.repository

import com.nexable.safecheck.core.data.database.SafeCheckDatabase
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Implementation of Brand List Repository with periodic updates and domain management.
 */
class BrandListRepositoryImpl(
    private val database: SafeCheckDatabase
) {
    
    companion object {
        // Update intervals
        const val BRAND_UPDATE_INTERVAL_HOURS = 24L
        const val DISPOSABLE_UPDATE_INTERVAL_HOURS = 12L
        
        // Domain categories
        const val BANKING = "BANKING"
        const val SOCIAL_MEDIA = "SOCIAL_MEDIA"
        const val ECOMMERCE = "ECOMMERCE"
        const val TECHNOLOGY = "TECHNOLOGY"
        const val GOVERNMENT = "GOVERNMENT"
        const val EDUCATION = "EDUCATION"
        const val HEALTHCARE = "HEALTHCARE"
        const val ENTERTAINMENT = "ENTERTAINMENT"
        
        // Disposable provider types
        const val TEMPORARY = "TEMPORARY"
        const val GUERRILLA = "GUERRILLA"
        const val FORWARDING = "FORWARDING"
        const val ALIAS = "ALIAS"
    }
    
    /**
     * Adds or updates a brand domain.
     */
    suspend fun addBrandDomain(
        domain: String,
        brandName: String,
        category: String,
        trustLevel: Int = 75,
        isVerified: Boolean = false
    ): Result<Unit> {
        return try {
            val now = Clock.System.now().epochSeconds
            
            database.transaction {
                database.database.insertBrandDomain(
                    domain = domain.lowercase(),
                    brand_name = brandName,
                    category = category,
                    trust_level = trustLevel.toLong(),
                    is_verified = isVerified,
                    last_verified = if (isVerified) now else null
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to add brand domain: ${e.message}", "ADD_BRAND_ERROR")
        }
    }
    
    /**
     * Gets a brand domain by domain name.
     */
    suspend fun getBrandDomain(domain: String): Result<BrandDomainInfo?> {
        return try {
            val brandDomain = database.database.getBrandDomain(domain.lowercase()).executeAsOneOrNull()
            
            val result = brandDomain?.let {
                BrandDomainInfo(
                    domain = it.domain,
                    brandName = it.brand_name,
                    category = it.category,
                    trustLevel = it.trust_level.toInt(),
                    isVerified = it.is_verified,
                    lastVerified = it.last_verified?.let { ts -> Instant.fromEpochSeconds(ts) },
                    createdAt = Instant.fromEpochSeconds(it.created_at),
                    updatedAt = Instant.fromEpochSeconds(it.updated_at)
                )
            }
            
            Result.success(result)
        } catch (e: Exception) {
            Result.error("Failed to get brand domain: ${e.message}", "GET_BRAND_ERROR")
        }
    }
    
    /**
     * Gets brand domains by category.
     */
    suspend fun getBrandDomainsByCategory(category: String): Result<List<BrandDomainInfo>> {
        return try {
            val brandDomains = database.database.getBrandDomainsByCategory(category).executeAsList()
            
            val results = brandDomains.map { domain ->
                BrandDomainInfo(
                    domain = domain.domain,
                    brandName = domain.brand_name,
                    category = domain.category,
                    trustLevel = domain.trust_level.toInt(),
                    isVerified = domain.is_verified,
                    lastVerified = domain.last_verified?.let { Instant.fromEpochSeconds(it) },
                    createdAt = Instant.fromEpochSeconds(domain.created_at),
                    updatedAt = Instant.fromEpochSeconds(domain.updated_at)
                )
            }
            
            Result.success(results)
        } catch (e: Exception) {
            Result.error("Failed to get brand domains by category: ${e.message}", "GET_BRANDS_CATEGORY_ERROR")
        }
    }
    
    /**
     * Searches brand domains.
     */
    suspend fun searchBrandDomains(query: String): Result<List<BrandDomainInfo>> {
        return try {
            val searchPattern = "%$query%"
            val brandDomains = database.database.searchBrandDomains(
                domain = searchPattern,
                brand_name = searchPattern
            ).executeAsList()
            
            val results = brandDomains.map { domain ->
                BrandDomainInfo(
                    domain = domain.domain,
                    brandName = domain.brand_name,
                    category = domain.category,
                    trustLevel = domain.trust_level.toInt(),
                    isVerified = domain.is_verified,
                    lastVerified = domain.last_verified?.let { Instant.fromEpochSeconds(it) },
                    createdAt = Instant.fromEpochSeconds(domain.created_at),
                    updatedAt = Instant.fromEpochSeconds(domain.updated_at)
                )
            }
            
            Result.success(results)
        } catch (e: Exception) {
            Result.error("Failed to search brand domains: ${e.message}", "SEARCH_BRANDS_ERROR")
        }
    }
    
    /**
     * Adds or updates a disposable domain.
     */
    suspend fun addDisposableDomain(
        domain: String,
        providerType: String,
        confidence: Double = 1.0,
        isActive: Boolean = true
    ): Result<Unit> {
        return try {
            val now = Clock.System.now().epochSeconds
            
            database.transaction {
                database.database.insertDisposableDomain(
                    domain = domain.lowercase(),
                    provider_type = providerType,
                    confidence = confidence,
                    is_active = isActive,
                    first_seen = now,
                    last_seen = now,
                    report_count = 1
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to add disposable domain: ${e.message}", "ADD_DISPOSABLE_ERROR")
        }
    }
    
    /**
     * Checks if a domain is disposable.
     */
    suspend fun isDisposableDomain(domain: String): Result<Boolean> {
        return try {
            val disposableDomain = database.database.isDisposableDomain(domain.lowercase()).executeAsOneOrNull()
            Result.success(disposableDomain != null)
        } catch (e: Exception) {
            Result.error("Failed to check disposable domain: ${e.message}", "CHECK_DISPOSABLE_ERROR")
        }
    }
    
    /**
     * Gets disposable domains by provider type.
     */
    suspend fun getDisposableDomainsByType(providerType: String): Result<List<DisposableDomainInfo>> {
        return try {
            val disposableDomains = database.database.getDisposableDomainsByType(providerType).executeAsList()
            
            val results = disposableDomains.map { domain ->
                DisposableDomainInfo(
                    domain = domain.domain,
                    providerType = domain.provider_type,
                    confidence = domain.confidence,
                    isActive = domain.is_active,
                    firstSeen = Instant.fromEpochSeconds(domain.first_seen),
                    lastSeen = Instant.fromEpochSeconds(domain.last_seen),
                    reportCount = domain.report_count.toInt(),
                    createdAt = Instant.fromEpochSeconds(domain.created_at)
                )
            }
            
            Result.success(results)
        } catch (e: Exception) {
            Result.error("Failed to get disposable domains by type: ${e.message}", "GET_DISPOSABLE_TYPE_ERROR")
        }
    }
    
    /**
     * Updates disposable domain activity.
     */
    suspend fun updateDisposableDomainActivity(
        domain: String,
        isActive: Boolean
    ): Result<Unit> {
        return try {
            val now = Clock.System.now().epochSeconds
            
            database.transaction {
                database.database.updateDisposableDomainActivity(
                    is_active = isActive,
                    last_seen = now,
                    domain = domain.lowercase()
                )
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to update disposable domain activity: ${e.message}", "UPDATE_DISPOSABLE_ERROR")
        }
    }
    
    /**
     * Initializes default brand domains.
     */
    suspend fun initializeDefaultBrandDomains(): Result<Int> {
        return try {
            val defaultBrands = getDefaultBrandDomains()
            var addedCount = 0
            
            database.transaction {
                for (brand in defaultBrands) {
                    try {
                        // Check if domain already exists
                        val existing = database.database.getBrandDomain(brand.domain).executeAsOneOrNull()
                        if (existing == null) {
                            database.database.insertBrandDomain(
                                domain = brand.domain,
                                brand_name = brand.brandName,
                                category = brand.category,
                                trust_level = brand.trustLevel.toLong(),
                                is_verified = brand.isVerified,
                                last_verified = if (brand.isVerified) Clock.System.now().epochSeconds else null
                            )
                            addedCount++
                        }
                    } catch (e: Exception) {
                        // Continue with other domains
                    }
                }
            }
            
            Result.success(addedCount)
        } catch (e: Exception) {
            Result.error("Failed to initialize default brand domains: ${e.message}", "INIT_BRANDS_ERROR")
        }
    }
    
    /**
     * Initializes default disposable domains.
     */
    suspend fun initializeDefaultDisposableDomains(): Result<Int> {
        return try {
            val defaultDisposable = getDefaultDisposableDomains()
            var addedCount = 0
            
            database.transaction {
                for (disposable in defaultDisposable) {
                    try {
                        // Check if domain already exists
                        val existing = database.database.isDisposableDomain(disposable.domain).executeAsOneOrNull()
                        if (existing == null) {
                            val now = Clock.System.now().epochSeconds
                            database.database.insertDisposableDomain(
                                domain = disposable.domain,
                                provider_type = disposable.providerType,
                                confidence = disposable.confidence,
                                is_active = true,
                                first_seen = now,
                                last_seen = now,
                                report_count = 1
                            )
                            addedCount++
                        }
                    } catch (e: Exception) {
                        // Continue with other domains
                    }
                }
            }
            
            Result.success(addedCount)
        } catch (e: Exception) {
            Result.error("Failed to initialize default disposable domains: ${e.message}", "INIT_DISPOSABLE_ERROR")
        }
    }
    
    /**
     * Periodic update service for brand and disposable domains.
     */
    fun startPeriodicUpdates(): Flow<UpdateResult> = flow {
        while (true) {
            try {
                // Update brand domains
                val brandUpdateResult = updateBrandDomains()
                emit(UpdateResult.BrandUpdate(brandUpdateResult))
                
                kotlinx.coroutines.delay(1000) // Small delay between updates
                
                // Update disposable domains
                val disposableUpdateResult = updateDisposableDomains()
                emit(UpdateResult.DisposableUpdate(disposableUpdateResult))
                
                // Wait for next update cycle
                kotlinx.coroutines.delay(BRAND_UPDATE_INTERVAL_HOURS * 60 * 60 * 1000)
                
            } catch (e: Exception) {
                emit(UpdateResult.Error("Update failed: ${e.message}"))
                kotlinx.coroutines.delay(60000) // Wait 1 minute on error
            }
        }
    }
    
    private suspend fun updateBrandDomains(): Result<Int> {
        return try {
            // In a real implementation, this would fetch from external sources
            // For now, just verify existing domains
            var updatedCount = 0
            
            val allSettings = database.database.getAllSettings().executeAsList()
            // This is a placeholder - real implementation would fetch from external API
            
            Result.success(updatedCount)
        } catch (e: Exception) {
            Result.error("Failed to update brand domains: ${e.message}", "UPDATE_BRANDS_ERROR")
        }
    }
    
    private suspend fun updateDisposableDomains(): Result<Int> {
        return try {
            // In a real implementation, this would fetch from external sources
            // For now, just cleanup inactive domains
            var updatedCount = 0
            
            val cutoffTime = Clock.System.now().epochSeconds - (30 * 24 * 60 * 60) // 30 days
            
            database.transaction {
                // Mark old domains as inactive
                database.database.updateDisposableDomainActivity(
                    is_active = false,
                    last_seen = cutoffTime,
                    domain = ""
                )
            }
            
            Result.success(updatedCount)
        } catch (e: Exception) {
            Result.error("Failed to update disposable domains: ${e.message}", "UPDATE_DISPOSABLE_ERROR")
        }
    }
    
    private fun getDefaultBrandDomains(): List<BrandDomainInfo> {
        return listOf(
            // Banking
            BrandDomainInfo("chase.com", "JPMorgan Chase", BANKING, 95, true),
            BrandDomainInfo("bankofamerica.com", "Bank of America", BANKING, 95, true),
            BrandDomainInfo("wellsfargo.com", "Wells Fargo", BANKING, 95, true),
            BrandDomainInfo("citibank.com", "Citibank", BANKING, 95, true),
            BrandDomainInfo("paypal.com", "PayPal", BANKING, 90, true),
            
            // Social Media
            BrandDomainInfo("facebook.com", "Facebook", SOCIAL_MEDIA, 90, true),
            BrandDomainInfo("instagram.com", "Instagram", SOCIAL_MEDIA, 90, true),
            BrandDomainInfo("twitter.com", "Twitter", SOCIAL_MEDIA, 90, true),
            BrandDomainInfo("linkedin.com", "LinkedIn", SOCIAL_MEDIA, 90, true),
            BrandDomainInfo("youtube.com", "YouTube", SOCIAL_MEDIA, 90, true),
            
            // E-commerce
            BrandDomainInfo("amazon.com", "Amazon", ECOMMERCE, 95, true),
            BrandDomainInfo("ebay.com", "eBay", ECOMMERCE, 90, true),
            BrandDomainInfo("walmart.com", "Walmart", ECOMMERCE, 90, true),
            BrandDomainInfo("target.com", "Target", ECOMMERCE, 90, true),
            BrandDomainInfo("shopify.com", "Shopify", ECOMMERCE, 85, true),
            
            // Technology
            BrandDomainInfo("google.com", "Google", TECHNOLOGY, 95, true),
            BrandDomainInfo("microsoft.com", "Microsoft", TECHNOLOGY, 95, true),
            BrandDomainInfo("apple.com", "Apple", TECHNOLOGY, 95, true),
            BrandDomainInfo("github.com", "GitHub", TECHNOLOGY, 90, true),
            BrandDomainInfo("stackoverflow.com", "Stack Overflow", TECHNOLOGY, 85, true)
        )
    }
    
    private fun getDefaultDisposableDomains(): List<DisposableDomainInfo> {
        return listOf(
            DisposableDomainInfo("10minutemail.com", TEMPORARY, 1.0, true),
            DisposableDomainInfo("guerrillamail.com", GUERRILLA, 1.0, true),
            DisposableDomainInfo("mailinator.com", TEMPORARY, 1.0, true),
            DisposableDomainInfo("temp-mail.org", TEMPORARY, 1.0, true),
            DisposableDomainInfo("yopmail.com", TEMPORARY, 1.0, true),
            DisposableDomainInfo("33mail.com", ALIAS, 0.9, true),
            DisposableDomainInfo("anonaddy.com", FORWARDING, 0.9, true),
            DisposableDomainInfo("simplelogin.io", FORWARDING, 0.9, true)
        )
    }
}

/**
 * Brand domain information.
 */
data class BrandDomainInfo(
    val domain: String,
    val brandName: String,
    val category: String,
    val trustLevel: Int,
    val isVerified: Boolean,
    val lastVerified: Instant? = null,
    val createdAt: Instant = Clock.System.now(),
    val updatedAt: Instant = Clock.System.now()
)

/**
 * Disposable domain information.
 */
data class DisposableDomainInfo(
    val domain: String,
    val providerType: String,
    val confidence: Double,
    val isActive: Boolean,
    val firstSeen: Instant = Clock.System.now(),
    val lastSeen: Instant = Clock.System.now(),
    val reportCount: Int = 1,
    val createdAt: Instant = Clock.System.now()
)

/**
 * Update result for periodic updates.
 */
sealed class UpdateResult {
    data class BrandUpdate(val result: Result<Int>) : UpdateResult()
    data class DisposableUpdate(val result: Result<Int>) : UpdateResult()
    data class Error(val message: String) : UpdateResult()
}

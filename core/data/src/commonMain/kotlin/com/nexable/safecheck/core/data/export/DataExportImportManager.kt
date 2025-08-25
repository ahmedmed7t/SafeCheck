package com.nexable.safecheck.core.data.export

import com.nexable.safecheck.core.data.database.SafeCheckDatabase
import com.nexable.safecheck.core.data.repository.SettingsRepositoryImpl
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Comprehensive data export and import manager for SafeCheck.
 * Handles backup, restore, and data migration functionality.
 */
class DataExportImportManager(
    private val database: SafeCheckDatabase,
    private val settingsRepository: SettingsRepositoryImpl
) {
    
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    companion object {
        const val EXPORT_VERSION = "1.0.0"
        const val MAX_EXPORT_SIZE_MB = 100
        const val MAX_SCAN_HISTORY_EXPORT = 10000
        
        // Export formats
        const val FORMAT_JSON = "json"
        const val FORMAT_CSV = "csv"
        
        // Export types
        const val TYPE_FULL_BACKUP = "full_backup"
        const val TYPE_SETTINGS_ONLY = "settings_only"
        const val TYPE_SCAN_HISTORY_ONLY = "scan_history_only"
        const val TYPE_CUSTOM = "custom"
    }
    
    /**
     * Exports data based on the specified configuration.
     */
    suspend fun exportData(config: ExportConfig): Result<DataExport> {
        return try {
            val exportData = DataExport(
                version = EXPORT_VERSION,
                exportType = config.exportType,
                createdAt = Clock.System.now(),
                metadata = ExportMetadata(
                    appVersion = getAppVersion(),
                    deviceInfo = getDeviceInfo(),
                    exportSize = 0L,
                    itemCounts = mutableMapOf()
                )
            )
            
            // Export settings if requested
            if (config.includeSettings) {
                val settingsResult = exportSettings(config.includeEncryptedSettings)
                if (settingsResult is Result.Success) {
                    exportData.settings = settingsResult.data
                    exportData.metadata.itemCounts["settings"] = settingsResult.data?.settings?.size ?: 0
                }
            }
            
            // Export scan history if requested
            if (config.includeScanHistory) {
                val scanHistoryResult = exportScanHistory(config.scanHistoryLimit ?: MAX_SCAN_HISTORY_EXPORT)
                if (scanHistoryResult is Result.Success) {
                    exportData.scanHistory = scanHistoryResult.data
                    exportData.metadata.itemCounts["scanHistory"] = scanHistoryResult.data.size
                }
            }
            
            // Export brand domains if requested
            if (config.includeBrandDomains) {
                val brandDomainsResult = exportBrandDomains()
                if (brandDomainsResult is Result.Success) {
                    exportData.brandDomains = brandDomainsResult.data
                    exportData.metadata.itemCounts["brandDomains"] = brandDomainsResult.data.size
                }
            }
            
            // Export disposable domains if requested
            if (config.includeDisposableDomains) {
                val disposableDomainsResult = exportDisposableDomains()
                if (disposableDomainsResult is Result.Success) {
                    exportData.disposableDomains = disposableDomainsResult.data
                    exportData.metadata.itemCounts["disposableDomains"] = disposableDomainsResult.data.size
                }
            }
            
            // Export cache data if requested
            if (config.includeCacheData) {
                val cacheDataResult = exportCacheData(config.includeExpiredCache)
                if (cacheDataResult is Result.Success) {
                    exportData.cacheData = cacheDataResult.data
                    exportData.metadata.itemCounts["cacheData"] = cacheDataResult.data.size
                }
            }
            
            // Calculate export size
            val exportJson = json.encodeToString(exportData)
            exportData.metadata.exportSize = exportJson.length.toLong()
            
            // Validate export size
            val exportSizeMB = exportData.metadata.exportSize / (1024 * 1024)
            if (exportSizeMB > MAX_EXPORT_SIZE_MB) {
                return Result.error("Export size ($exportSizeMB MB) exceeds maximum limit ($MAX_EXPORT_SIZE_MB MB)", "EXPORT_TOO_LARGE")
            }
            
            Result.success(exportData)
        } catch (e: Exception) {
            Result.error("Export failed: ${e.message}", "EXPORT_ERROR")
        }
    }
    
    /**
     * Imports data from an export file.
     */
    suspend fun importData(
        dataExport: DataExport,
        config: ImportConfig
    ): Result<ImportResult> {
        return try {
            val importResult = ImportResult(
                importType = dataExport.exportType,
                startedAt = Clock.System.now(),
                itemCounts = mutableMapOf(),
                errors = mutableListOf(),
                warnings = mutableListOf()
            )
            
            // Validate export version compatibility
            if (!isVersionCompatible(dataExport.version)) {
                return Result.error("Export version ${dataExport.version} is not compatible", "VERSION_INCOMPATIBLE")
            }
            
            // Import settings if available and requested
            if (config.importSettings && dataExport.settings != null) {
                val settingsResult = importSettings(dataExport.settings, config.overwriteExistingSettings)
                if (settingsResult is Result.Success) {
                    importResult.itemCounts["settings"] = settingsResult.data
                } else {
                    importResult.errors.add("Settings import failed: ${settingsResult.message}")
                }
            }
            
            // Import scan history if available and requested
            if (config.importScanHistory && dataExport.scanHistory != null) {
                val scanHistoryResult = importScanHistory(dataExport.scanHistory, config.overwriteExistingScanHistory)
                if (scanHistoryResult is Result.Success) {
                    importResult.itemCounts["scanHistory"] = scanHistoryResult.data
                } else {
                    importResult.errors.add("Scan history import failed: ${scanHistoryResult.message}")
                }
            }
            
            // Import brand domains if available and requested
            if (config.importBrandDomains && dataExport.brandDomains != null) {
                val brandDomainsResult = importBrandDomains(dataExport.brandDomains, config.overwriteExistingBrandDomains)
                if (brandDomainsResult is Result.Success) {
                    importResult.itemCounts["brandDomains"] = brandDomainsResult.data
                } else {
                    importResult.errors.add("Brand domains import failed: ${brandDomainsResult.message}")
                }
            }
            
            // Import disposable domains if available and requested
            if (config.importDisposableDomains && dataExport.disposableDomains != null) {
                val disposableDomainsResult = importDisposableDomains(dataExport.disposableDomains, config.overwriteExistingDisposableDomains)
                if (disposableDomainsResult is Result.Success) {
                    importResult.itemCounts["disposableDomains"] = disposableDomainsResult.data
                } else {
                    importResult.errors.add("Disposable domains import failed: ${disposableDomainsResult.message}")
                }
            }
            
            // Import cache data if available and requested
            if (config.importCacheData && dataExport.cacheData != null) {
                val cacheDataResult = importCacheData(dataExport.cacheData, config.overwriteExistingCacheData)
                if (cacheDataResult is Result.Success) {
                    importResult.itemCounts["cacheData"] = cacheDataResult.data
                } else {
                    importResult.errors.add("Cache data import failed: ${cacheDataResult.message}")
                }
            }
            
            importResult.completedAt = Clock.System.now()
            importResult.success = importResult.errors.isEmpty()
            
            Result.success(importResult)
        } catch (e: Exception) {
            Result.error("Import failed: ${e.message}", "IMPORT_ERROR")
        }
    }
    
    /**
     * Exports data to a specific format (JSON, CSV).
     */
    suspend fun exportToFormat(
        dataExport: DataExport,
        format: String
    ): Result<String> {
        return try {
            val exportString = when (format.lowercase()) {
                FORMAT_JSON -> json.encodeToString(dataExport)
                FORMAT_CSV -> convertToCSV(dataExport)
                else -> return Result.error("Unsupported format: $format", "UNSUPPORTED_FORMAT")
            }
            
            Result.success(exportString)
        } catch (e: Exception) {
            Result.error("Format conversion failed: ${e.message}", "FORMAT_ERROR")
        }
    }
    
    /**
     * Imports data from a formatted string.
     */
    suspend fun importFromFormat(
        data: String,
        format: String
    ): Result<DataExport> {
        return try {
            val dataExport = when (format.lowercase()) {
                FORMAT_JSON -> json.decodeFromString<DataExport>(data)
                FORMAT_CSV -> convertFromCSV(data)
                else -> return Result.error("Unsupported format: $format", "UNSUPPORTED_FORMAT")
            }
            
            Result.success(dataExport)
        } catch (e: Exception) {
            Result.error("Format parsing failed: ${e.message}", "PARSE_ERROR")
        }
    }
    
    /**
     * Creates a quick backup of essential data.
     */
    suspend fun createQuickBackup(): Result<DataExport> {
        val config = ExportConfig(
            exportType = TYPE_SETTINGS_ONLY,
            includeSettings = true,
            includeEncryptedSettings = false,
            includeScanHistory = false,
            includeBrandDomains = false,
            includeDisposableDomains = false,
            includeCacheData = false
        )
        
        return exportData(config)
    }
    
    /**
     * Creates a full backup of all data.
     */
    suspend fun createFullBackup(): Result<DataExport> {
        val config = ExportConfig(
            exportType = TYPE_FULL_BACKUP,
            includeSettings = true,
            includeEncryptedSettings = false, // Security: Don't export encrypted settings
            includeScanHistory = true,
            includeBrandDomains = true,
            includeDisposableDomains = true,
            includeCacheData = false, // Cache can be rebuilt
            scanHistoryLimit = MAX_SCAN_HISTORY_EXPORT
        )
        
        return exportData(config)
    }
    
    /**
     * Validates an export file before import.
     */
    suspend fun validateExport(dataExport: DataExport): Result<ValidationResult> {
        return try {
            val validation = ValidationResult()
            
            // Check version compatibility
            validation.isVersionCompatible = isVersionCompatible(dataExport.version)
            
            // Check data integrity
            validation.hasValidMetadata = dataExport.metadata != null
            validation.hasSettings = dataExport.settings != null
            validation.hasScanHistory = !dataExport.scanHistory.isNullOrEmpty()
            validation.hasBrandDomains = !dataExport.brandDomains.isNullOrEmpty()
            validation.hasDisposableDomains = !dataExport.disposableDomains.isNullOrEmpty()
            validation.hasCacheData = !dataExport.cacheData.isNullOrEmpty()
            
            // Check for potential issues
            if (dataExport.metadata?.exportSize ?: 0 > MAX_EXPORT_SIZE_MB * 1024 * 1024) {
                validation.warnings.add("Export file is very large")
            }
            
            if (dataExport.scanHistory?.size ?: 0 > MAX_SCAN_HISTORY_EXPORT) {
                validation.warnings.add("Scan history exceeds recommended limit")
            }
            
            validation.isValid = validation.isVersionCompatible && validation.hasValidMetadata
            
            Result.success(validation)
        } catch (e: Exception) {
            Result.error("Validation failed: ${e.message}", "VALIDATION_ERROR")
        }
    }
    
    private suspend fun exportSettings(includeEncrypted: Boolean): Result<SettingsExport?> {
        return try {
            val settingsResult = settingsRepository.getAllSettings()
            if (settingsResult is Result.Success) {
                val filteredSettings = if (includeEncrypted) {
                    settingsResult.data
                } else {
                    settingsResult.data.filterValues { !it.isEncrypted }
                }
                
                val settingsExport = SettingsExport(
                    version = "1.0",
                    exportedAt = Clock.System.now().epochSeconds,
                    settings = filteredSettings
                )
                
                Result.success(settingsExport)
            } else {
                Result.error("Failed to get settings", "SETTINGS_EXPORT_ERROR")
            }
        } catch (e: Exception) {
            Result.error("Settings export failed: ${e.message}", "SETTINGS_EXPORT_ERROR")
        }
    }
    
    private suspend fun exportScanHistory(limit: Int): Result<List<ScanHistoryExport>> {
        return try {
            val scanHistory = database.database.getScanHistory(limit.toLong(), 0).executeAsList()
            
            val exportData = scanHistory.map { scan ->
                ScanHistoryExport(
                    scanId = scan.scan_id,
                    targetType = scan.target_type,
                    targetValue = scan.target_value,
                    score = scan.score.toInt(),
                    status = scan.status,
                    reasons = scan.reasons,
                    metadata = scan.metadata,
                    scannedAt = scan.scanned_at,
                    scanDurationMs = scan.scan_duration_ms,
                    scannerVersion = scan.scanner_version
                )
            }
            
            Result.success(exportData)
        } catch (e: Exception) {
            Result.error("Scan history export failed: ${e.message}", "SCAN_HISTORY_EXPORT_ERROR")
        }
    }
    
    private suspend fun exportBrandDomains(): Result<List<BrandDomainExport>> {
        return try {
            // This would get all brand domains from the database
            val brandDomains = emptyList<BrandDomainExport>() // Placeholder
            Result.success(brandDomains)
        } catch (e: Exception) {
            Result.error("Brand domains export failed: ${e.message}", "BRAND_DOMAINS_EXPORT_ERROR")
        }
    }
    
    private suspend fun exportDisposableDomains(): Result<List<DisposableDomainExport>> {
        return try {
            // This would get all disposable domains from the database
            val disposableDomains = emptyList<DisposableDomainExport>() // Placeholder
            Result.success(disposableDomains)
        } catch (e: Exception) {
            Result.error("Disposable domains export failed: ${e.message}", "DISPOSABLE_DOMAINS_EXPORT_ERROR")
        }
    }
    
    private suspend fun exportCacheData(includeExpired: Boolean): Result<List<CacheDataExport>> {
        return try {
            // This would get cache data from the database
            val cacheData = emptyList<CacheDataExport>() // Placeholder
            Result.success(cacheData)
        } catch (e: Exception) {
            Result.error("Cache data export failed: ${e.message}", "CACHE_DATA_EXPORT_ERROR")
        }
    }
    
    private suspend fun importSettings(settingsExport: SettingsExport, overwrite: Boolean): Result<Int> {
        return try {
            var importedCount = 0
            
            for ((_, settingInfo) in settingsExport.settings) {
                if (!overwrite) {
                    // Check if setting already exists
                    val existing = settingsRepository.getString(settingInfo.key)
                    if (existing is Result.Success && existing.data.isNotEmpty()) {
                        continue // Skip existing settings
                    }
                }
                
                // Import the setting based on its type
                when (settingInfo.type) {
                    "STRING" -> settingsRepository.setString(settingInfo.key, settingInfo.value, description = settingInfo.description)
                    "INTEGER" -> settingsRepository.setInt(settingInfo.key, settingInfo.value.toInt(), description = settingInfo.description)
                    "BOOLEAN" -> settingsRepository.setBoolean(settingInfo.key, settingInfo.value.toBoolean(), description = settingInfo.description)
                    // Note: JSON and encrypted settings would need special handling
                }
                importedCount++
            }
            
            Result.success(importedCount)
        } catch (e: Exception) {
            Result.error("Settings import failed: ${e.message}", "SETTINGS_IMPORT_ERROR")
        }
    }
    
    private suspend fun importScanHistory(scanHistory: List<ScanHistoryExport>, overwrite: Boolean): Result<Int> {
        return try {
            var importedCount = 0
            
            database.transaction {
                for (scan in scanHistory) {
                    // Import scan history entry
                    database.database.insertScanHistory(
                        scan_id = scan.scanId,
                        target_type = scan.targetType,
                        target_value = scan.targetValue,
                        score = scan.score.toLong(),
                        status = scan.status,
                        reasons = scan.reasons,
                        metadata = scan.metadata,
                        scanned_at = scan.scannedAt,
                        scan_duration_ms = scan.scanDurationMs,
                        scanner_version = scan.scannerVersion
                    )
                    importedCount++
                }
            }
            
            Result.success(importedCount)
        } catch (e: Exception) {
            Result.error("Scan history import failed: ${e.message}", "SCAN_HISTORY_IMPORT_ERROR")
        }
    }
    
    private suspend fun importBrandDomains(brandDomains: List<BrandDomainExport>, overwrite: Boolean): Result<Int> {
        return try {
            var importedCount = 0
            
            // Implementation would import brand domains
            
            Result.success(importedCount)
        } catch (e: Exception) {
            Result.error("Brand domains import failed: ${e.message}", "BRAND_DOMAINS_IMPORT_ERROR")
        }
    }
    
    private suspend fun importDisposableDomains(disposableDomains: List<DisposableDomainExport>, overwrite: Boolean): Result<Int> {
        return try {
            var importedCount = 0
            
            // Implementation would import disposable domains
            
            Result.success(importedCount)
        } catch (e: Exception) {
            Result.error("Disposable domains import failed: ${e.message}", "DISPOSABLE_DOMAINS_IMPORT_ERROR")
        }
    }
    
    private suspend fun importCacheData(cacheData: List<CacheDataExport>, overwrite: Boolean): Result<Int> {
        return try {
            var importedCount = 0
            
            // Implementation would import cache data
            
            Result.success(importedCount)
        } catch (e: Exception) {
            Result.error("Cache data import failed: ${e.message}", "CACHE_DATA_IMPORT_ERROR")
        }
    }
    
    private fun convertToCSV(dataExport: DataExport): String {
        val csv = StringBuilder()
        
        // Add headers
        csv.appendLine("Type,Data")
        
        // Add metadata
        csv.appendLine("Metadata,${json.encodeToString(dataExport.metadata)}")
        
        // Add scan history if available
        dataExport.scanHistory?.forEach { scan ->
            csv.appendLine("ScanHistory,${json.encodeToString(scan)}")
        }
        
        return csv.toString()
    }
    
    private fun convertFromCSV(csv: String): DataExport {
        // Simplified CSV parsing - real implementation would be more robust
        val lines = csv.lines()
        val dataExport = DataExport(
            version = EXPORT_VERSION,
            exportType = TYPE_CUSTOM,
            createdAt = Clock.System.now(),
            metadata = ExportMetadata()
        )
        
        // Parse CSV lines and populate dataExport
        // This is a placeholder implementation
        
        return dataExport
    }
    
    private fun isVersionCompatible(version: String): Boolean {
        // Simple version compatibility check
        return version.startsWith("1.") // Compatible with version 1.x
    }
    
    private fun getAppVersion(): String {
        return "1.0.0" // This would come from build configuration
    }
    
    private fun getDeviceInfo(): String {
        return "Unknown Device" // This would come from platform-specific implementation
    }
}

/**
 * Export configuration.
 */
data class ExportConfig(
    val exportType: String,
    val includeSettings: Boolean = true,
    val includeEncryptedSettings: Boolean = false,
    val includeScanHistory: Boolean = true,
    val includeBrandDomains: Boolean = true,
    val includeDisposableDomains: Boolean = true,
    val includeCacheData: Boolean = false,
    val includeExpiredCache: Boolean = false,
    val scanHistoryLimit: Int? = null
)

/**
 * Import configuration.
 */
data class ImportConfig(
    val importSettings: Boolean = true,
    val importScanHistory: Boolean = true,
    val importBrandDomains: Boolean = true,
    val importDisposableDomains: Boolean = true,
    val importCacheData: Boolean = false,
    val overwriteExistingSettings: Boolean = false,
    val overwriteExistingScanHistory: Boolean = false,
    val overwriteExistingBrandDomains: Boolean = false,
    val overwriteExistingDisposableDomains: Boolean = false,
    val overwriteExistingCacheData: Boolean = false
)

/**
 * Main data export structure.
 */
@Serializable
data class DataExport(
    val version: String,
    val exportType: String,
    val createdAt: Instant,
    var metadata: ExportMetadata,
    var settings: SettingsExport? = null,
    var scanHistory: List<ScanHistoryExport>? = null,
    var brandDomains: List<BrandDomainExport>? = null,
    var disposableDomains: List<DisposableDomainExport>? = null,
    var cacheData: List<CacheDataExport>? = null
)

/**
 * Export metadata.
 */
@Serializable
data class ExportMetadata(
    val appVersion: String = "1.0.0",
    val deviceInfo: String = "Unknown",
    var exportSize: Long = 0L,
    var itemCounts: MutableMap<String, Int> = mutableMapOf()
)

/**
 * Settings export structure.
 */
@Serializable
data class SettingsExport(
    val version: String,
    val exportedAt: Long,
    val settings: Map<String, com.nexable.safecheck.core.data.repository.SettingInfo>
)

/**
 * Scan history export structure.
 */
@Serializable
data class ScanHistoryExport(
    val scanId: String,
    val targetType: String,
    val targetValue: String,
    val score: Int,
    val status: String,
    val reasons: String,
    val metadata: String,
    val scannedAt: Long,
    val scanDurationMs: Long,
    val scannerVersion: String
)

/**
 * Brand domain export structure.
 */
@Serializable
data class BrandDomainExport(
    val domain: String,
    val brandName: String,
    val category: String,
    val trustLevel: Int,
    val isVerified: Boolean
)

/**
 * Disposable domain export structure.
 */
@Serializable
data class DisposableDomainExport(
    val domain: String,
    val providerType: String,
    val confidence: Double,
    val isActive: Boolean
)

/**
 * Cache data export structure.
 */
@Serializable
data class CacheDataExport(
    val cacheKey: String,
    val cacheType: String,
    val targetValue: String,
    val cacheData: String,
    val confidence: Double,
    val expiresAt: Long
)

/**
 * Import result.
 */
data class ImportResult(
    val importType: String,
    val startedAt: Instant,
    var completedAt: Instant? = null,
    var success: Boolean = false,
    var itemCounts: MutableMap<String, Int> = mutableMapOf(),
    var errors: MutableList<String> = mutableListOf(),
    var warnings: MutableList<String> = mutableListOf()
)

/**
 * Validation result.
 */
data class ValidationResult(
    var isValid: Boolean = false,
    var isVersionCompatible: Boolean = false,
    var hasValidMetadata: Boolean = false,
    var hasSettings: Boolean = false,
    var hasScanHistory: Boolean = false,
    var hasBrandDomains: Boolean = false,
    var hasDisposableDomains: Boolean = false,
    var hasCacheData: Boolean = false,
    var warnings: MutableList<String> = mutableListOf(),
    var errors: MutableList<String> = mutableListOf()
)

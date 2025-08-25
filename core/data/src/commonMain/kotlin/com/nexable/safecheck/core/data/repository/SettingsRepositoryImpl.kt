package com.nexable.safecheck.core.data.repository

import com.nexable.safecheck.core.data.database.DatabaseEncryption
import com.nexable.safecheck.core.data.database.SafeCheckDatabase
import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Implementation of Settings Repository with reactive updates and encryption support.
 */
class SettingsRepositoryImpl(
    private val database: SafeCheckDatabase,
    private val encryptionKey: String? = null
) {
    
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    // Reactive updates
    private val _settingsUpdates = MutableSharedFlow<SettingUpdate>()
    val settingsUpdates = _settingsUpdates.asSharedFlow()
    
    companion object {
        // Setting keys
        const val SCAN_TIMEOUT = "scan_timeout"
        const val MAX_CONCURRENT_SCANS = "max_concurrent_scans"
        const val ENABLE_CACHING = "enable_caching"
        const val CACHE_TTL_HOURS = "cache_ttl_hours"
        const val AUTO_CLEANUP_ENABLED = "auto_cleanup_enabled"
        const val HISTORY_RETENTION_DAYS = "history_retention_days"
        const val VIRUS_TOTAL_API_KEY = "virus_total_api_key"
        const val ENABLE_NOTIFICATIONS = "enable_notifications"
        const val DARK_MODE = "dark_mode"
        const val LANGUAGE = "language"
        const val FIRST_LAUNCH = "first_launch"
        const val LAST_UPDATE_CHECK = "last_update_check"
        const val ANALYTICS_ENABLED = "analytics_enabled"
        const val CRASH_REPORTING_ENABLED = "crash_reporting_enabled"
        
        // Setting types
        const val TYPE_STRING = "STRING"
        const val TYPE_INTEGER = "INTEGER"
        const val TYPE_BOOLEAN = "BOOLEAN"
        const val TYPE_JSON = "JSON"
    }
    
    /**
     * Gets a string setting value.
     */
    suspend fun getString(key: String, defaultValue: String = ""): Result<String> {
        return try {
            val setting = database.database.getSetting(key).executeAsOneOrNull()
            
            if (setting == null) {
                Result.success(defaultValue)
            } else {
                val value = if (setting.is_encrypted) {
                    decryptValue(setting.setting_value)
                } else {
                    setting.setting_value
                }
                Result.success(value)
            }
        } catch (e: Exception) {
            Result.error("Failed to get string setting: ${e.message}", "GET_STRING_ERROR")
        }
    }
    
    /**
     * Sets a string setting value.
     */
    suspend fun setString(
        key: String, 
        value: String, 
        encrypted: Boolean = false,
        description: String? = null
    ): Result<Unit> {
        return try {
            val finalValue = if (encrypted) {
                encryptValue(value)
            } else {
                value
            }
            
            database.transaction {
                database.database.insertOrUpdateSetting(
                    setting_key = key,
                    setting_value = finalValue,
                    setting_type = TYPE_STRING,
                    is_encrypted = encrypted,
                    description = description
                )
            }
            
            _settingsUpdates.emit(SettingUpdate(key, value, TYPE_STRING))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to set string setting: ${e.message}", "SET_STRING_ERROR")
        }
    }
    
    /**
     * Gets an integer setting value.
     */
    suspend fun getInt(key: String, defaultValue: Int = 0): Result<Int> {
        return try {
            val setting = database.database.getSetting(key).executeAsOneOrNull()
            
            if (setting == null) {
                Result.success(defaultValue)
            } else {
                val value = setting.setting_value.toIntOrNull() ?: defaultValue
                Result.success(value)
            }
        } catch (e: Exception) {
            Result.error("Failed to get int setting: ${e.message}", "GET_INT_ERROR")
        }
    }
    
    /**
     * Sets an integer setting value.
     */
    suspend fun setInt(
        key: String, 
        value: Int,
        description: String? = null
    ): Result<Unit> {
        return try {
            database.transaction {
                database.database.insertOrUpdateSetting(
                    setting_key = key,
                    setting_value = value.toString(),
                    setting_type = TYPE_INTEGER,
                    is_encrypted = false,
                    description = description
                )
            }
            
            _settingsUpdates.emit(SettingUpdate(key, value.toString(), TYPE_INTEGER))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to set int setting: ${e.message}", "SET_INT_ERROR")
        }
    }
    
    /**
     * Gets a boolean setting value.
     */
    suspend fun getBoolean(key: String, defaultValue: Boolean = false): Result<Boolean> {
        return try {
            val setting = database.database.getSetting(key).executeAsOneOrNull()
            
            if (setting == null) {
                Result.success(defaultValue)
            } else {
                val value = setting.setting_value.toBooleanStrictOrNull() ?: defaultValue
                Result.success(value)
            }
        } catch (e: Exception) {
            Result.error("Failed to get boolean setting: ${e.message}", "GET_BOOLEAN_ERROR")
        }
    }
    
    /**
     * Sets a boolean setting value.
     */
    suspend fun setBoolean(
        key: String, 
        value: Boolean,
        description: String? = null
    ): Result<Unit> {
        return try {
            database.transaction {
                database.database.insertOrUpdateSetting(
                    setting_key = key,
                    setting_value = value.toString(),
                    setting_type = TYPE_BOOLEAN,
                    is_encrypted = false,
                    description = description
                )
            }
            
            _settingsUpdates.emit(SettingUpdate(key, value.toString(), TYPE_BOOLEAN))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to set boolean setting: ${e.message}", "SET_BOOLEAN_ERROR")
        }
    }
    
    /**
     * Gets a JSON object setting value.
     */
    suspend inline fun <reified T> getObject(
        key: String, 
        defaultValue: T? = null
    ): Result<T?> {
        return try {
            val setting = database.database.getSetting(key).executeAsOneOrNull()
            
            if (setting == null) {
                Result.success(defaultValue)
            } else {
                val jsonValue = if (setting.is_encrypted) {
                    decryptValue(setting.setting_value)
                } else {
                    setting.setting_value
                }
                val value = json.decodeFromString<T>(jsonValue)
                Result.success(value)
            }
        } catch (e: Exception) {
            Result.error("Failed to get object setting: ${e.message}", "GET_OBJECT_ERROR")
        }
    }
    
    /**
     * Sets a JSON object setting value.
     */
    suspend inline fun <reified T> setObject(
        key: String, 
        value: T,
        encrypted: Boolean = false,
        description: String? = null
    ): Result<Unit> {
        return try {
            val jsonValue = json.encodeToString(value)
            val finalValue = if (encrypted) {
                encryptValue(jsonValue)
            } else {
                jsonValue
            }
            
            database.transaction {
                database.database.insertOrUpdateSetting(
                    setting_key = key,
                    setting_value = finalValue,
                    setting_type = TYPE_JSON,
                    is_encrypted = encrypted,
                    description = description
                )
            }
            
            _settingsUpdates.emit(SettingUpdate(key, jsonValue, TYPE_JSON))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to set object setting: ${e.message}", "SET_OBJECT_ERROR")
        }
    }
    
    /**
     * Deletes a setting.
     */
    suspend fun deleteSetting(key: String): Result<Unit> {
        return try {
            database.transaction {
                database.database.deleteSetting(key)
            }
            
            _settingsUpdates.emit(SettingUpdate(key, null, "DELETED"))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to delete setting: ${e.message}", "DELETE_SETTING_ERROR")
        }
    }
    
    /**
     * Gets all settings.
     */
    suspend fun getAllSettings(): Result<Map<String, SettingInfo>> {
        return try {
            val settings = database.database.getAllSettings().executeAsList()
            
            val settingsMap = settings.associate { setting ->
                val value = if (setting.is_encrypted) {
                    "[ENCRYPTED]"
                } else {
                    setting.setting_value
                }
                
                setting.setting_key to SettingInfo(
                    key = setting.setting_key,
                    value = value,
                    type = setting.setting_type,
                    isEncrypted = setting.is_encrypted,
                    description = setting.description,
                    createdAt = setting.created_at,
                    updatedAt = setting.updated_at
                )
            }
            
            Result.success(settingsMap)
        } catch (e: Exception) {
            Result.error("Failed to get all settings: ${e.message}", "GET_ALL_SETTINGS_ERROR")
        }
    }
    
    /**
     * Observes changes to a specific setting.
     */
    fun observeSetting(key: String): Flow<String?> = flow {
        // Emit current value first
        val currentResult = getString(key)
        if (currentResult is Result.Success) {
            emit(currentResult.data)
        }
        
        // Then listen for updates
        settingsUpdates.collect { update ->
            if (update.key == key) {
                emit(update.value)
            }
        }
    }
    
    /**
     * Observes changes to a boolean setting.
     */
    fun observeBooleanSetting(key: String, defaultValue: Boolean = false): Flow<Boolean> = flow {
        // Emit current value first
        val currentResult = getBoolean(key, defaultValue)
        if (currentResult is Result.Success) {
            emit(currentResult.data)
        }
        
        // Then listen for updates
        settingsUpdates.collect { update ->
            if (update.key == key && update.type == TYPE_BOOLEAN) {
                emit(update.value?.toBooleanStrictOrNull() ?: defaultValue)
            }
        }
    }
    
    /**
     * Observes changes to an integer setting.
     */
    fun observeIntSetting(key: String, defaultValue: Int = 0): Flow<Int> = flow {
        // Emit current value first
        val currentResult = getInt(key, defaultValue)
        if (currentResult is Result.Success) {
            emit(currentResult.data)
        }
        
        // Then listen for updates
        settingsUpdates.collect { update ->
            if (update.key == key && update.type == TYPE_INTEGER) {
                emit(update.value?.toIntOrNull() ?: defaultValue)
            }
        }
    }
    
    /**
     * Initializes default settings if they don't exist.
     */
    suspend fun initializeDefaultSettings(): Result<Unit> {
        return try {
            val defaults = mapOf(
                SCAN_TIMEOUT to "30000", // 30 seconds
                MAX_CONCURRENT_SCANS to "3",
                ENABLE_CACHING to "true",
                CACHE_TTL_HOURS to "24",
                AUTO_CLEANUP_ENABLED to "true",
                HISTORY_RETENTION_DAYS to "90",
                ENABLE_NOTIFICATIONS to "true",
                DARK_MODE to "false",
                LANGUAGE to "en",
                FIRST_LAUNCH to "true",
                ANALYTICS_ENABLED to "false",
                CRASH_REPORTING_ENABLED to "true"
            )
            
            for ((key, value) in defaults) {
                val existing = database.database.getSetting(key).executeAsOneOrNull()
                if (existing == null) {
                    when (key) {
                        SCAN_TIMEOUT, MAX_CONCURRENT_SCANS, CACHE_TTL_HOURS, HISTORY_RETENTION_DAYS -> 
                            setInt(key, value.toInt(), "Default $key setting")
                        ENABLE_CACHING, AUTO_CLEANUP_ENABLED, ENABLE_NOTIFICATIONS, DARK_MODE, 
                        FIRST_LAUNCH, ANALYTICS_ENABLED, CRASH_REPORTING_ENABLED -> 
                            setBoolean(key, value.toBoolean(), "Default $key setting")
                        else -> 
                            setString(key, value, description = "Default $key setting")
                    }
                }
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.error("Failed to initialize default settings: ${e.message}", "INIT_DEFAULTS_ERROR")
        }
    }
    
    /**
     * Exports settings for backup.
     */
    suspend fun exportSettings(): Result<SettingsExport> {
        return try {
            val allSettings = getAllSettings()
            if (allSettings is Result.Success) {
                val export = SettingsExport(
                    version = "1.0",
                    exportedAt = Clock.System.now().epochSeconds,
                    settings = allSettings.data.filterValues { !it.isEncrypted } // Don't export encrypted settings
                )
                Result.success(export)
            } else {
                Result.error("Failed to get settings for export", "EXPORT_ERROR")
            }
        } catch (e: Exception) {
            Result.error("Failed to export settings: ${e.message}", "EXPORT_ERROR")
        }
    }
    
    /**
     * Imports settings from backup.
     */
    suspend fun importSettings(export: SettingsExport): Result<Int> {
        return try {
            var importedCount = 0
            
            database.transaction {
                for ((_, settingInfo) in export.settings) {
                    if (!settingInfo.isEncrypted) { // Only import non-encrypted settings
                        database.database.insertOrUpdateSetting(
                            setting_key = settingInfo.key,
                            setting_value = settingInfo.value,
                            setting_type = settingInfo.type,
                            is_encrypted = false,
                            description = settingInfo.description
                        )
                        importedCount++
                    }
                }
            }
            
            Result.success(importedCount)
        } catch (e: Exception) {
            Result.error("Failed to import settings: ${e.message}", "IMPORT_ERROR")
        }
    }
    
    private fun encryptValue(value: String): String {
        return if (encryptionKey != null) {
            DatabaseEncryption.encryptData(value, encryptionKey)
        } else {
            value // No encryption if key not available
        }
    }
    
    private fun decryptValue(encryptedValue: String): String {
        return if (encryptionKey != null) {
            DatabaseEncryption.decryptData(encryptedValue, encryptionKey)
        } else {
            encryptedValue // Return as-is if key not available
        }
    }
}

/**
 * Setting update event for reactive updates.
 */
data class SettingUpdate(
    val key: String,
    val value: String?,
    val type: String
)

/**
 * Setting information.
 */
data class SettingInfo(
    val key: String,
    val value: String,
    val type: String,
    val isEncrypted: Boolean,
    val description: String?,
    val createdAt: Long,
    val updatedAt: Long
)

/**
 * Settings export data.
 */
@kotlinx.serialization.Serializable
data class SettingsExport(
    val version: String,
    val exportedAt: Long,
    val settings: Map<String, SettingInfo>
)

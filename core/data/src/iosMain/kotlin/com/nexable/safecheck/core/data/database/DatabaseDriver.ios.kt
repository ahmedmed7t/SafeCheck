package com.nexable.safecheck.core.data.database

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.native.NativeSqliteDriver
import app.cash.sqldelight.driver.native.wrapConnection
import co.touchlab.sqliter.DatabaseConfiguration
import com.nexable.safecheck.core.data.SafeCheckDatabase
import platform.Foundation.*

/**
 * iOS implementation of the database driver factory.
 */
actual class DatabaseDriverFactory {
    
    actual fun createDriver(): SqlDriver {
        val databasePath = getDatabasePath("safecheck.db")
        
        return NativeSqliteDriver(
            schema = SafeCheckDatabase.Schema,
            name = databasePath,
            onConfiguration = { config ->
                config.copy(
                    extendedConfig = DatabaseConfiguration.Extended(
                        foreignKeyConstraints = true,
                        busyTimeout = 30_000,
                        journalMode = DatabaseConfiguration.JournalMode.WAL,
                        synchronousFlag = DatabaseConfiguration.SynchronousFlag.NORMAL
                    )
                )
            },
            onUpgrade = { driver, oldVersion, newVersion ->
                // Handle database upgrades
                println("Upgrading database from version $oldVersion to $newVersion")
            }
        )
    }
    
    /**
     * Creates an encrypted database driver.
     */
    fun createEncryptedDriver(encryptionKey: String): SqlDriver {
        val databasePath = getDatabasePath("safecheck_encrypted.db")
        
        // Note: For production, you would integrate with SQLCipher for iOS
        // This is a placeholder implementation
        println("Warning: Encrypted driver not fully implemented on iOS")
        
        return NativeSqliteDriver(
            schema = SafeCheckDatabase.Schema,
            name = databasePath,
            onConfiguration = { config ->
                config.copy(
                    extendedConfig = DatabaseConfiguration.Extended(
                        foreignKeyConstraints = true,
                        busyTimeout = 30_000,
                        journalMode = DatabaseConfiguration.JournalMode.WAL,
                        synchronousFlag = DatabaseConfiguration.SynchronousFlag.NORMAL,
                        // In a real implementation, you would add encryption configuration here
                    )
                )
            }
        )
    }
    
    private fun getDatabasePath(databaseName: String): String {
        val documentsPath = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask,
            true
        ).first() as String
        
        return "$documentsPath/$databaseName"
    }
}

/**
 * iOS-specific database utilities.
 */
object IosDatabaseUtils {
    
    /**
     * Gets the database file path on iOS.
     */
    fun getDatabasePath(databaseName: String = "safecheck.db"): String {
        val documentsPath = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask,
            true
        ).first() as String
        
        return "$documentsPath/$databaseName"
    }
    
    /**
     * Gets the database size in bytes.
     */
    fun getDatabaseSize(databaseName: String = "safecheck.db"): Long {
        val path = getDatabasePath(databaseName)
        val fileManager = NSFileManager.defaultManager
        
        return if (fileManager.fileExistsAtPath(path)) {
            val attributes = fileManager.attributesOfItemAtPath(path, null)
            (attributes?.get(NSFileSize) as? NSNumber)?.longValue ?: 0L
        } else {
            0L
        }
    }
    
    /**
     * Checks if database exists.
     */
    fun databaseExists(databaseName: String = "safecheck.db"): Boolean {
        val path = getDatabasePath(databaseName)
        return NSFileManager.defaultManager.fileExistsAtPath(path)
    }
    
    /**
     * Deletes the database file.
     */
    fun deleteDatabase(databaseName: String = "safecheck.db"): Boolean {
        val path = getDatabasePath(databaseName)
        val fileManager = NSFileManager.defaultManager
        
        return if (fileManager.fileExistsAtPath(path)) {
            fileManager.removeItemAtPath(path, null)
        } else {
            true // Already doesn't exist
        }
    }
    
    /**
     * Creates a backup of the database.
     */
    fun backupDatabase(
        sourceName: String = "safecheck.db",
        backupName: String = "safecheck_backup.db"
    ): Boolean {
        val sourcePath = getDatabasePath(sourceName)
        val backupPath = getDatabasePath(backupName)
        val fileManager = NSFileManager.defaultManager
        
        return try {
            if (fileManager.fileExistsAtPath(sourcePath)) {
                // Remove existing backup
                if (fileManager.fileExistsAtPath(backupPath)) {
                    fileManager.removeItemAtPath(backupPath, null)
                }
                
                // Copy source to backup
                fileManager.copyItemAtPath(sourcePath, backupPath, null)
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Restores database from backup.
     */
    fun restoreDatabase(
        backupName: String = "safecheck_backup.db",
        targetName: String = "safecheck.db"
    ): Boolean {
        val backupPath = getDatabasePath(backupName)
        val targetPath = getDatabasePath(targetName)
        val fileManager = NSFileManager.defaultManager
        
        return try {
            if (fileManager.fileExistsAtPath(backupPath)) {
                // Remove existing target
                if (fileManager.fileExistsAtPath(targetPath)) {
                    fileManager.removeItemAtPath(targetPath, null)
                }
                
                // Copy backup to target
                fileManager.copyItemAtPath(backupPath, targetPath, null)
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Gets available storage space in bytes.
     */
    fun getAvailableStorageSpace(): Long {
        val documentsPath = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask,
            true
        ).first() as String
        
        val fileManager = NSFileManager.defaultManager
        val attributes = fileManager.attributesOfFileSystemForPath(documentsPath, null)
        
        return (attributes?.get(NSFileSystemFreeSize) as? NSNumber)?.longValue ?: 0L
    }
    
    /**
     * Gets total storage space in bytes.
     */
    fun getTotalStorageSpace(): Long {
        val documentsPath = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask,
            true
        ).first() as String
        
        val fileManager = NSFileManager.defaultManager
        val attributes = fileManager.attributesOfFileSystemForPath(documentsPath, null)
        
        return (attributes?.get(NSFileSystemSize) as? NSNumber)?.longValue ?: 0L
    }
}

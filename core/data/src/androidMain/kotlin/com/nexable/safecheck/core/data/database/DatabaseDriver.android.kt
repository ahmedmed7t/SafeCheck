package com.nexable.safecheck.core.data.database

import android.content.Context
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.android.AndroidSqliteDriver
import com.nexable.safecheck.core.data.SafeCheckDatabase

/**
 * Android implementation of the database driver factory.
 */
actual class DatabaseDriverFactory(private val context: Context) {
    
    actual fun createDriver(): SqlDriver {
        return AndroidSqliteDriver(
            schema = SafeCheckDatabase.Schema,
            context = context,
            name = "safecheck.db",
            callback = object : AndroidSqliteDriver.Callback(SafeCheckDatabase.Schema) {
                override fun onOpen(driver: SqlDriver) {
                    super.onOpen(driver)
                    
                    // Configure SQLite for optimal performance
                    driver.execute(null, "PRAGMA foreign_keys = ON", 0)
                    driver.execute(null, "PRAGMA journal_mode = WAL", 0)
                    driver.execute(null, "PRAGMA synchronous = NORMAL", 0)
                    driver.execute(null, "PRAGMA cache_size = 2000", 0)
                    driver.execute(null, "PRAGMA temp_store = MEMORY", 0)
                    driver.execute(null, "PRAGMA mmap_size = 268435456", 0) // 256MB
                    driver.execute(null, "PRAGMA busy_timeout = 30000", 0) // 30 seconds
                    
                    // Enable auto vacuum for better space management
                    driver.execute(null, "PRAGMA auto_vacuum = INCREMENTAL", 0)
                }
                
                override fun onConfigure(driver: SqlDriver) {
                    super.onConfigure(driver)
                    
                    // Additional configuration can be done here
                    driver.execute(null, "PRAGMA secure_delete = ON", 0)
                }
            }
        )
    }
    
    /**
     * Creates an encrypted database driver using SQLCipher.
     * Note: This requires adding SQLCipher dependency to build.gradle.kts
     */
    fun createEncryptedDriver(password: String): SqlDriver {
        // For encrypted database, you would use:
        // return AndroidSqliteDriver(
        //     schema = SafeCheckDatabase.Schema,
        //     context = context,
        //     name = "safecheck_encrypted.db",
        //     password = password
        // )
        
        // For now, return regular driver with a warning
        println("Warning: Encrypted driver not implemented, using regular driver")
        return createDriver()
    }
}

/**
 * Android-specific database utilities.
 */
object AndroidDatabaseUtils {
    
    /**
     * Gets the database file path on Android.
     */
    fun getDatabasePath(context: Context, databaseName: String = "safecheck.db"): String {
        return context.getDatabasePath(databaseName).absolutePath
    }
    
    /**
     * Gets the database size in bytes.
     */
    fun getDatabaseSize(context: Context, databaseName: String = "safecheck.db"): Long {
        val dbFile = context.getDatabasePath(databaseName)
        return if (dbFile.exists()) dbFile.length() else 0L
    }
    
    /**
     * Checks if database exists.
     */
    fun databaseExists(context: Context, databaseName: String = "safecheck.db"): Boolean {
        return context.getDatabasePath(databaseName).exists()
    }
    
    /**
     * Deletes the database file.
     */
    fun deleteDatabase(context: Context, databaseName: String = "safecheck.db"): Boolean {
        return context.deleteDatabase(databaseName)
    }
    
    /**
     * Creates a backup of the database.
     */
    fun backupDatabase(
        context: Context, 
        sourceName: String = "safecheck.db",
        backupName: String = "safecheck_backup.db"
    ): Boolean {
        return try {
            val source = context.getDatabasePath(sourceName)
            val backup = context.getDatabasePath(backupName)
            
            if (source.exists()) {
                source.copyTo(backup, overwrite = true)
                true
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
        context: Context,
        backupName: String = "safecheck_backup.db",
        targetName: String = "safecheck.db"
    ): Boolean {
        return try {
            val backup = context.getDatabasePath(backupName)
            val target = context.getDatabasePath(targetName)
            
            if (backup.exists()) {
                backup.copyTo(target, overwrite = true)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
}

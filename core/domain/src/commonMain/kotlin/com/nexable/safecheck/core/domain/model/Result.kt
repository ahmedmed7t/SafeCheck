package com.nexable.safecheck.core.domain.model

import kotlinx.serialization.Serializable

/**
 * A generic wrapper for operation results that can represent success or failure states.
 * Provides a type-safe way to handle operations that might fail.
 */
@Serializable
sealed class Result<out T> {
    
    /**
     * Represents a successful operation result.
     */
    @Serializable
    data class Success<T>(val data: T) : Result<T>()
    
    /**
     * Represents a failed operation result.
     */
    @Serializable
    data class Error(
        val message: String,
        val code: String? = null,
        val details: Map<String, String> = emptyMap()
    ) : Result<Nothing>()
    
    /**
     * Represents a loading state (operation in progress).
     */
    @Serializable
    data object Loading : Result<Nothing>()
    
    companion object {
        /**
         * Creates a Success result.
         */
        fun <T> success(data: T): Result<T> = Success(data)
        
        /**
         * Creates an Error result.
         */
        fun error(
            message: String, 
            code: String? = null, 
            details: Map<String, String> = emptyMap()
        ): Result<Nothing> = Error(message, code, details)
        
        /**
         * Creates a Loading result.
         */
        fun loading(): Result<Nothing> = Loading
        
        /**
         * Wraps a function call in a Result, catching any exceptions.
         */
        inline fun <T> runCatching(action: () -> T): Result<T> {
            return try {
                success(action())
            } catch (e: Exception) {
                error(e.message ?: "Unknown error occurred", details = mapOf("exception" to e::class.simpleName.orEmpty()))
            }
        }
    }
}

/**
 * Extension property to check if the result is successful.
 */
val <T> Result<T>.isSuccess: Boolean
    get() = this is Result.Success

/**
 * Extension property to check if the result is an error.
 */
val <T> Result<T>.isError: Boolean
    get() = this is Result.Error

/**
 * Extension property to check if the result is loading.
 */
val <T> Result<T>.isLoading: Boolean
    get() = this is Result.Loading

/**
 * Extension function to get the data if successful, null otherwise.
 */
fun <T> Result<T>.getOrNull(): T? = when (this) {
    is Result.Success -> data
    else -> null
}

/**
 * Extension function to get the data if successful, or a default value.
 */
fun <T> Result<T>.getOrDefault(default: T): T = when (this) {
    is Result.Success -> data
    else -> default
}

/**
 * Extension function to get the error message if failed, null otherwise.
 */
fun <T> Result<T>.getErrorMessage(): String? = when (this) {
    is Result.Error -> message
    else -> null
}

/**
 * Extension function to transform the data if successful.
 */
inline fun <T, R> Result<T>.map(transform: (T) -> R): Result<R> = when (this) {
    is Result.Success -> Result.success(transform(data))
    is Result.Error -> this
    is Result.Loading -> this
}

/**
 * Extension function to transform the data if successful, handling exceptions.
 */
inline fun <T, R> Result<T>.mapCatching(transform: (T) -> R): Result<R> = when (this) {
    is Result.Success -> Result.runCatching { transform(data) }
    is Result.Error -> this
    is Result.Loading -> this
}

/**
 * Extension function to chain results (flatMap).
 */
inline fun <T, R> Result<T>.flatMap(transform: (T) -> Result<R>): Result<R> = when (this) {
    is Result.Success -> transform(data)
    is Result.Error -> this
    is Result.Loading -> this
}

/**
 * Extension function to handle both success and error cases.
 */
inline fun <T> Result<T>.fold(
    onSuccess: (T) -> Unit,
    onError: (String) -> Unit,
    onLoading: () -> Unit = {}
) {
    when (this) {
        is Result.Success -> onSuccess(data)
        is Result.Error -> onError(message)
        is Result.Loading -> onLoading()
    }
}

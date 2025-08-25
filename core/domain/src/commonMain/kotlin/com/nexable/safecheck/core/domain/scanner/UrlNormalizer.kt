package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.util.InputValidator

/**
 * URL normalization utilities following RFC standards.
 */
object UrlNormalizer {
    
    /**
     * Normalizes a URL according to RFC standards.
     */
    fun normalize(url: String): String {
        var normalized = url.trim()
        
        // Add protocol if missing
        if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
            normalized = "https://$normalized"
        }
        
        // Convert to lowercase (except path and query)
        val protocolEnd = normalized.indexOf("://") + 3
        val pathStart = normalized.indexOf("/", protocolEnd)
        
        if (pathStart == -1) {
            // No path, normalize entire URL
            normalized = normalized.lowercase()
        } else {
            // Normalize only protocol and domain
            val protocolAndDomain = normalized.substring(0, pathStart).lowercase()
            val pathAndQuery = normalized.substring(pathStart)
            normalized = protocolAndDomain + pathAndQuery
        }
        
        // Remove default ports
        normalized = normalized.replace(":443/", "/").replace(":80/", "/")
        if (normalized.endsWith(":443")) {
            normalized = normalized.removeSuffix(":443")
        }
        if (normalized.endsWith(":80")) {
            normalized = normalized.removeSuffix(":80")
        }
        
        // Ensure trailing slash for domain-only URLs
        if (normalized.indexOf("/", protocolEnd) == -1) {
            normalized += "/"
        }
        
        // Remove fragment (hash) for security analysis
        val fragmentIndex = normalized.indexOf("#")
        if (fragmentIndex != -1) {
            normalized = normalized.substring(0, fragmentIndex)
        }
        
        return normalized
    }
}

/**
 * URL validation utilities following RFC standards.
 */
object UrlValidator {
    
    /**
     * Validates URL according to RFC standards.
     */
    fun validate(url: String): Result<Unit> {
        // Basic URL structure validation
        if (!url.contains("://")) {
            return Result.error("Invalid URL: Missing protocol", "INVALID_PROTOCOL")
        }
        
        val protocolEnd = url.indexOf("://")
        val protocol = url.substring(0, protocolEnd)
        
        if (protocol !in listOf("http", "https", "ftp", "ftps")) {
            return Result.error("Unsupported protocol: $protocol", "UNSUPPORTED_PROTOCOL")
        }
        
        // Extract domain for validation
        val domain = UrlParser.extractDomain(url)
        if (domain.isBlank()) {
            return Result.error("Invalid or missing domain", "INVALID_DOMAIN")
        }
        
        // Domain validation
        if (!InputValidator.isValidDomain(domain)) {
            return Result.error("Invalid domain format", "INVALID_DOMAIN_FORMAT")
        }
        
        return Result.success(Unit)
    }
}

/**
 * URL parsing utilities.
 */
object UrlParser {
    
    /**
     * Extracts domain from a URL.
     */
    fun extractDomain(url: String): String {
        return try {
            val protocolEnd = url.indexOf("://") + 3
            val domainStart = protocolEnd
            val pathStart = url.indexOf("/", domainStart)
            val queryStart = url.indexOf("?", domainStart)
            val fragmentStart = url.indexOf("#", domainStart)
            
            val domainEnd = listOfNotNull(
                if (pathStart != -1) pathStart else null,
                if (queryStart != -1) queryStart else null,
                if (fragmentStart != -1) fragmentStart else null,
                url.length
            ).minOrNull() ?: url.length
            
            val domainWithPort = url.substring(domainStart, domainEnd)
            
            // Remove port if present
            val colonIndex = domainWithPort.lastIndexOf(':')
            if (colonIndex != -1 && domainWithPort.substring(colonIndex + 1).all { it.isDigit() }) {
                return domainWithPort.substring(0, colonIndex)
            }
            
            domainWithPort
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Extracts the path from a URL.
     */
    fun extractPath(url: String): String {
        return try {
            val protocolEnd = url.indexOf("://") + 3
            val pathStart = url.indexOf("/", protocolEnd)
            
            if (pathStart == -1) return "/"
            
            val queryStart = url.indexOf("?", pathStart)
            val fragmentStart = url.indexOf("#", pathStart)
            
            val pathEnd = listOfNotNull(
                if (queryStart != -1) queryStart else null,
                if (fragmentStart != -1) fragmentStart else null,
                url.length
            ).minOrNull() ?: url.length
            
            url.substring(pathStart, pathEnd)
        } catch (e: Exception) {
            "/"
        }
    }
    
    /**
     * Extracts query parameters from a URL.
     */
    fun extractQuery(url: String): String {
        return try {
            val queryStart = url.indexOf("?")
            if (queryStart == -1) return ""
            
            val fragmentStart = url.indexOf("#", queryStart)
            val queryEnd = if (fragmentStart != -1) fragmentStart else url.length
            
            url.substring(queryStart + 1, queryEnd)
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Extracts protocol from URL.
     */
    fun extractProtocol(url: String): String {
        return try {
            val protocolEnd = url.indexOf("://")
            if (protocolEnd == -1) return ""
            url.substring(0, protocolEnd)
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Extracts port from URL if specified.
     */
    fun extractPort(url: String): Int? {
        return try {
            val domain = extractDomain(url)
            val protocolEnd = url.indexOf("://") + 3
            val domainStart = protocolEnd
            val pathStart = url.indexOf("/", domainStart).let { if (it == -1) url.length else it }
            
            val domainWithPort = url.substring(domainStart, pathStart)
            val colonIndex = domainWithPort.lastIndexOf(':')
            
            if (colonIndex != -1 && domainWithPort.substring(colonIndex + 1).all { it.isDigit() }) {
                domainWithPort.substring(colonIndex + 1).toIntOrNull()
            } else {
                // Return default ports
                when (extractProtocol(url)) {
                    "https" -> 443
                    "http" -> 80
                    "ftp" -> 21
                    "ftps" -> 990
                    else -> null
                }
            }
        } catch (e: Exception) {
            null
        }
    }
}

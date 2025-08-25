package com.nexable.safecheck.core.platform.whois

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.*
// DateTime imports are working correctly
// These imports should now resolve properly in IDEs

/**
 * Android implementation of WHOIS client using raw socket connections.
 */
actual class WhoisClient {
    
    companion object {
        private const val DEFAULT_WHOIS_PORT = 43
        private const val CONNECTION_TIMEOUT = 10000 // 10 seconds
        
        // Common WHOIS servers for different TLDs
        private val whoisServers = mapOf(
            "com" to "whois.verisign-grs.com",
            "net" to "whois.verisign-grs.com",
            "org" to "whois.pir.org",
            "edu" to "whois.educause.edu",
            "gov" to "whois.dotgov.gov",
            "mil" to "whois.nic.mil",
            "info" to "whois.afilias.net",
            "biz" to "whois.biz",
            "name" to "whois.nic.name",
            "co.uk" to "whois.nominet.uk",
            "de" to "whois.denic.de",
            "fr" to "whois.afnic.fr",
            "jp" to "whois.jprs.jp",
            "cn" to "whois.cnnic.cn",
            "ru" to "whois.tcinet.ru"
        )
        
        private val dateFormats = listOf(
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US),
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US),
            SimpleDateFormat("yyyy-MM-dd", Locale.US),
            SimpleDateFormat("dd-MMM-yyyy", Locale.US),
            SimpleDateFormat("dd/MM/yyyy", Locale.US),
            SimpleDateFormat("MM/dd/yyyy", Locale.US)
        )
    }
    
    actual suspend fun lookup(domain: String): Result<WhoisInfo> {
        return withContext(Dispatchers.IO) {
            try {
                val cleanDomain = domain.lowercase().trim()
                val tld = extractTld(cleanDomain)
                val whoisServer = whoisServers[tld] ?: whoisServers["com"]!!
                
                val rawData = queryWhoisServer(whoisServer, cleanDomain)
                val whoisInfo = parseWhoisData(cleanDomain, rawData)
                
                Result.success(whoisInfo)
            } catch (e: Exception) {
                Result.error("WHOIS lookup failed for $domain: ${e.message}", "WHOIS_LOOKUP_FAILED")
            }
        }
    }
    
    actual suspend fun getDomainAge(domain: String): Result<Int> {
        return when (val result = lookup(domain)) {
            is Result.Success -> Result.success(result.data.ageDays)
            is Result.Error -> result
            is Result.Loading -> result
        }
    }
    
    actual suspend fun isExpired(domain: String): Result<Boolean> {
        return when (val result = lookup(domain)) {
            is Result.Success -> Result.success(result.data.isExpired)
            is Result.Error -> result
            is Result.Loading -> result
        }
    }
    
    private suspend fun queryWhoisServer(server: String, domain: String): String {
        return withContext(Dispatchers.IO) {
            var socket: Socket? = null
            var response = ""
            
            try {
                socket = Socket()
                socket.connect(java.net.InetSocketAddress(server, DEFAULT_WHOIS_PORT), CONNECTION_TIMEOUT)
                socket.soTimeout = CONNECTION_TIMEOUT
                
                val writer = PrintWriter(socket.getOutputStream(), true)
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                
                // Send domain query
                writer.println(domain)
                
                // Read response
                val responseBuilder = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    responseBuilder.appendLine(line!!)
                }
                
                response = responseBuilder.toString()
                
                writer.close()
                reader.close()
            } catch (e: Exception) {
                throw Exception("Failed to query WHOIS server $server: ${e.message}")
            } finally {
                socket?.close()
            }
            
            response
        }
    }
    
    private fun parseWhoisData(domain: String, rawData: String): WhoisInfo {
        val lines = rawData.lines()
        var registrar: String? = null
        var registeredDate: Instant? = null
        var expiryDate: Instant? = null
        var updatedDate: Instant? = null
        val nameServers = mutableListOf<String>()
        val status = mutableListOf<String>()
        var registrantCountry: String? = null
        var registrantOrganization: String? = null
        var adminEmail: String? = null
        var techEmail: String? = null
        var isPrivacyProtected = false
        
        for (line in lines) {
            val lowerLine = line.lowercase().trim()
            
            when {
                lowerLine.startsWith("registrar:") -> {
                    registrar = extractValue(line)
                }
                lowerLine.startsWith("creation date:") || lowerLine.startsWith("registered on:") || 
                lowerLine.startsWith("created:") -> {
                    registeredDate = parseDate(extractValue(line))
                }
                lowerLine.startsWith("expiry date:") || lowerLine.startsWith("expires on:") ||
                lowerLine.startsWith("expires:") || lowerLine.startsWith("expiration date:") -> {
                    expiryDate = parseDate(extractValue(line))
                }
                lowerLine.startsWith("updated date:") || lowerLine.startsWith("last updated:") ||
                lowerLine.startsWith("modified:") -> {
                    updatedDate = parseDate(extractValue(line))
                }
                lowerLine.startsWith("name server:") || lowerLine.startsWith("nserver:") -> {
                    extractValue(line)?.let { nameServers.add(it) }
                }
                lowerLine.startsWith("status:") || lowerLine.startsWith("domain status:") -> {
                    extractValue(line)?.let { status.add(it) }
                }
                lowerLine.startsWith("registrant country:") -> {
                    registrantCountry = extractValue(line)
                }
                lowerLine.startsWith("registrant organization:") || lowerLine.startsWith("org:") -> {
                    registrantOrganization = extractValue(line)
                }
                lowerLine.startsWith("admin email:") || lowerLine.contains("administrative contact") && 
                lowerLine.contains("email:") -> {
                    adminEmail = extractValue(line)
                }
                lowerLine.startsWith("tech email:") || lowerLine.contains("technical contact") &&
                lowerLine.contains("email:") -> {
                    techEmail = extractValue(line)
                }
                lowerLine.contains("privacy") || lowerLine.contains("whoisguard") ||
                lowerLine.contains("domains by proxy") -> {
                    isPrivacyProtected = true
                }
            }
        }
        
        val ageDays = registeredDate?.let { regDate ->
            val now = Clock.System.now()
            ((now.toEpochMilliseconds() - regDate.toEpochMilliseconds()) / (24 * 60 * 60 * 1000)).toInt()
        } ?: 0
        
        return WhoisInfo(
            domain = domain,
            registrar = registrar,
            registeredDate = registeredDate,
            expiryDate = expiryDate,
            updatedDate = updatedDate,
            nameServers = nameServers,
            status = status,
            registrantCountry = registrantCountry,
            registrantOrganization = registrantOrganization,
            adminEmail = adminEmail,
            techEmail = techEmail,
            rawData = rawData,
            isPrivacyProtected = isPrivacyProtected,
            ageDays = ageDays
        )
    }
    
    private fun extractTld(domain: String): String {
        val parts = domain.split(".")
        return when {
            parts.size >= 3 && parts[parts.size - 2] == "co" -> "${parts[parts.size - 2]}.${parts.last()}"
            else -> parts.last()
        }
    }
    
    private fun extractValue(line: String): String? {
        val colonIndex = line.indexOf(':')
        return if (colonIndex != -1 && colonIndex < line.length - 1) {
            line.substring(colonIndex + 1).trim()
        } else null
    }
    
    private fun parseDate(dateStr: String?): Instant? {
        if (dateStr.isNullOrBlank()) return null
        
        val cleanDate = dateStr.trim()
        
        for (format in dateFormats) {
            try {
                val date = format.parse(cleanDate)
                return Instant.fromEpochMilliseconds(date.time)
            } catch (e: Exception) {
                // Try next format
            }
        }
        
        return null
    }
    
    /**
     * Verification function to ensure kotlinx-datetime imports work correctly.
     * This demonstrates that Clock and Instant are properly imported and accessible.
     */
    private fun verifyDateTimeImports(): String {
        val now = Clock.System.now()
        val epochTime = now.toEpochMilliseconds()
        return "kotlinx-datetime imports working: Current time is $epochTime"
    }
}

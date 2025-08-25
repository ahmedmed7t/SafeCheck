package com.nexable.safecheck.core.platform.whois

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import platform.Foundation.*
import platform.Network.*
import kotlin.coroutines.resume

/**
 * iOS implementation of WHOIS client using Foundation networking APIs.
 */
actual class WhoisClient {
    
    companion object {
        private const val DEFAULT_WHOIS_PORT = 43
        private const val CONNECTION_TIMEOUT = 10.0 // 10 seconds
        
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
            NSDateFormatter().apply {
                dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
                timeZone = NSTimeZone.timeZoneWithAbbreviation("UTC")
            },
            NSDateFormatter().apply {
                dateFormat = "yyyy-MM-dd HH:mm:ss"
                timeZone = NSTimeZone.timeZoneWithAbbreviation("UTC")
            },
            NSDateFormatter().apply {
                dateFormat = "yyyy-MM-dd"
                timeZone = NSTimeZone.timeZoneWithAbbreviation("UTC")
            },
            NSDateFormatter().apply {
                dateFormat = "dd-MMM-yyyy"
                locale = NSLocale.localeWithLocaleIdentifier("en_US")
                timeZone = NSTimeZone.timeZoneWithAbbreviation("UTC")
            },
            NSDateFormatter().apply {
                dateFormat = "dd/MM/yyyy"
                timeZone = NSTimeZone.timeZoneWithAbbreviation("UTC")
            },
            NSDateFormatter().apply {
                dateFormat = "MM/dd/yyyy"
                timeZone = NSTimeZone.timeZoneWithAbbreviation("UTC")
            }
        )
    }
    
    actual suspend fun lookup(domain: String): Result<WhoisInfo> {
        return withContext(Dispatchers.Default) {
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
        return suspendCancellableCoroutine { continuation ->
            try {
                // Use iOS Network framework for socket connection
                val endpoint = NWEndpoint.hostEndpoint(server, "$DEFAULT_WHOIS_PORT")
                val parameters = NWParameters.tcpParameters()
                parameters.setRequiredInterfaceType(NWInterfaceType.NWInterfaceTypeWifi)
                
                val connection = NWConnection.connectionWithEndpoint(endpoint, parameters)
                
                connection.setStateChangedHandler { state ->
                    when (state) {
                        NWConnectionState.NWConnectionStateReady -> {
                            // Send WHOIS query
                            val queryData = "$domain\r\n".encodeToByteArray()
                            val nsData = queryData.toNSData()
                            
                            connection.sendData(nsData, nil, true) { error ->
                                if (error != null) {
                                    continuation.resume("")
                                    return@sendData
                                }
                                
                                // Receive response
                                connection.receiveData(1, UInt.MAX_VALUE) { data, context, isComplete, error ->
                                    if (error != null) {
                                        continuation.resume("")
                                        return@receiveData
                                    }
                                    
                                    val responseString = data?.toByteArray()?.decodeToString() ?: ""
                                    continuation.resume(responseString)
                                    connection.cancel()
                                }
                            }
                        }
                        NWConnectionState.NWConnectionStateFailed -> {
                            continuation.resume("")
                            connection.cancel()
                        }
                        else -> {
                            // Other states: preparing, waiting
                        }
                    }
                }
                
                connection.start(dispatch_get_main_queue())
                
                // Set timeout
                dispatch_after(
                    dispatch_time(DISPATCH_TIME_NOW, (CONNECTION_TIMEOUT * NSEC_PER_SEC).toLong()),
                    dispatch_get_main_queue()
                ) {
                    if (!continuation.isCompleted) {
                        continuation.resume("")
                        connection.cancel()
                    }
                }
                
            } catch (e: Exception) {
                continuation.resume("")
            }
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
        
        for (formatter in dateFormats) {
            try {
                val date = formatter.dateFromString(cleanDate)
                if (date != null) {
                    return Instant.fromEpochMilliseconds((date.timeIntervalSince1970 * 1000).toLong())
                }
            } catch (e: Exception) {
                // Try next format
            }
        }
        
        return null
    }
}

/**
 * Extension function to convert ByteArray to NSData.
 */
private fun ByteArray.toNSData(): NSData {
    return NSData.create(bytes = this.toCValues(), length = this.size.toULong())
}

/**
 * Extension function to convert NSData to ByteArray.
 */
private fun NSData.toByteArray(): ByteArray {
    return ByteArray(this.length.toInt()) { index ->
        this.bytes!![index]
    }
}
